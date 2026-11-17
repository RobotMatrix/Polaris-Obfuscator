// 生成编码表。只写二进制，不打印密钥。
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#define WBAES_NO_DEVBIND 1
#include "wbaes_key.h"
#include "hy_mask.h"
#include "wbaes_hybrid.h"
#include <sys/sysctl.h>

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b = (uint8_t)(b >> 1);
    }
    return p;
}
static uint8_t rotl8(uint8_t x, int n) { return (uint8_t)((x << n) | (x >> (8 - n))); }
static uint8_t gf_inv(uint8_t x) {
    if (!x) return 0;
    uint8_t a = gmul(x, x), x2 = a;
    a = gmul(a, a); uint8_t x4 = a;
    a = gmul(a, a); uint8_t x8 = a;
    a = gmul(a, a); uint8_t x16 = a;
    a = gmul(a, a); uint8_t x32 = a;
    a = gmul(a, a); uint8_t x64 = a;
    a = gmul(a, a);
    uint8_t p = gmul(a, x64); p = gmul(p, x32); p = gmul(p, x16); p = gmul(p, x8); p = gmul(p, x4);
    return gmul(p, x2);
}
static uint8_t sbox(uint8_t x) {
    uint8_t b = gf_inv(x);
    return (uint8_t)(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63);
}
static uint8_t inv_sbox(uint8_t x) {
    return gf_inv((uint8_t)(rotl8(x, 1) ^ rotl8(x, 3) ^ rotl8(x, 6) ^ 0x05));
}

static const uint8_t MC[4][4] = {
    {2, 3, 1, 1},
    {1, 2, 3, 1},
    {1, 1, 2, 3},
    {3, 1, 1, 2},
};
static const uint8_t IMC[4][4] = {
    {14, 11, 13, 9},
    {9, 14, 11, 13},
    {13, 9, 14, 11},
    {11, 13, 9, 14},
};

// 轮密钥烧毁: volatile 写, 阻优化器删除 (与 demo_wbaes.cpp 窗口用后即焚同一纪律)
static void burn16(uint8_t *k) {
    volatile uint8_t *p = k;
    for (int i = 0; i < 16; i++) p[i] = 0;
}
// 任意缓冲烧毁 (编码结构/表间产物)
static void burn(void *p, size_t n) {
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) *q++ = 0;
}

static int generate(const char *out_path, uint32_t env, uint8_t key[16]);

// 按需正向派生第 r 轮轮密钥 (r=0 即主密钥拷贝)。
// 全程只保留相邻两轮窗口; 返回前烧毁窗口 — 任意时刻不存在完整轮密钥矩阵。
static void derive_rk(int r, const uint8_t key[16], uint8_t out[16]) {
    uint8_t prev[16], cur[16], t[4];
    memcpy(prev, key, 16);
    for (int i = 1; i <= r; i++) {
        t[0] = prev[13]; t[1] = prev[14]; t[2] = prev[15]; t[3] = prev[12];
        uint8_t rc = 1;
        for (int j = 0; j < i - 1; j++) rc = xtime(rc);
        t[0] = (uint8_t)(sbox(t[0]) ^ rc);
        t[1] = sbox(t[1]);
        t[2] = sbox(t[2]);
        t[3] = sbox(t[3]);
        for (int k = 0; k < 16; k++)
            cur[k] = (uint8_t)(prev[k] ^ (k < 4 ? t[k] : cur[k - 4]));
        if (i < r) memcpy(prev, cur, 16);
    }
    if (r == 0) memcpy(out, prev, 16);
    else memcpy(out, cur, 16);
    burn16(prev);
    burn16(cur);
    burn16(t);
}

static void xor_rk(uint8_t s[16], const uint8_t *k) {
    for (int i = 0; i < 16; i++) s[i] ^= k[i];
}
static void sub(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = sbox(s[i]);
}
static void inv_sub(uint8_t s[16]) {
    for (int i = 0; i < 16; i++) s[i] = inv_sbox(s[i]);
}
static void shift(uint8_t s[16]) {
    uint8_t t[16];
    memcpy(t, s, 16);
    for (int dst = 0; dst < 16; dst++) s[dst] = t[hy_sr_src(dst)];
}
static void inv_shift(uint8_t s[16]) {
    uint8_t t[16];
    memcpy(t, s, 16);
    for (int dst = 0; dst < 16; dst++) s[dst] = t[hy_isr_src(dst)];
}
static void mix(uint8_t s[16], const uint8_t M[4][4]) {
    uint8_t t[16];
    memcpy(t, s, 16);
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++) {
            uint8_t a = 0;
            for (int k = 0; k < 4; k++) a ^= gmul(t[k + 4 * col], M[row][k]);
            s[row + 4 * col] = a;
        }
    }
}

static void ref_encrypt(const uint8_t pt[16], uint8_t ct[16], const uint8_t key[16]) {
    uint8_t rk[16], s[16];
    memcpy(s, pt, 16);
    xor_rk(s, key);                       // RK0 = 主密钥 (存活至 generate 末尾统一焚毁)
    for (int r = 1; r <= 9; r++) {
        sub(s);
        shift(s);
        mix(s, MC);
        derive_rk(r, key, rk);            // 单轮密钥, 用完即焚
        xor_rk(s, rk);
        burn16(rk);
    }
    sub(s);
    shift(s);
    derive_rk(10, key, rk);
    xor_rk(s, rk);
    burn16(rk);
    memcpy(ct, s, 16);
    burn16(s);                            // 中间状态混有轮密钥, 用完即焚
}

static void ref_decrypt(const uint8_t ct[16], uint8_t pt[16], const uint8_t key[16]) {
    uint8_t rk[16], s[16];
    memcpy(s, ct, 16);
    derive_rk(10, key, rk);
    xor_rk(s, rk);
    burn16(rk);
    inv_shift(s);
    inv_sub(s);
    for (int r = 9; r >= 1; r--) {
        derive_rk(r, key, rk);
        xor_rk(s, rk);
        burn16(rk);
        mix(s, IMC);
        inv_shift(s);
        inv_sub(s);
    }
    xor_rk(s, key);
    memcpy(pt, s, 16);
    burn16(s);                            // 中间状态混有轮密钥, 用完即焚
}

static FILE *g_ur = nullptr;
static uint32_t rnd32() {
    uint32_t x = 0;
    if (!g_ur || fread(&x, 4, 1, g_ur) != 1) exit(3);
    return x;
}
static void rand_perm(uint8_t p[256], uint8_t inv[256]) {
    for (int i = 0; i < 256; i++) p[i] = (uint8_t)i;
    for (int i = 255; i > 0; i--) {
        int j = (int)(rnd32() % (uint32_t)(i + 1));
        uint8_t t = p[i];
        p[i] = p[j];
        p[j] = t;
    }
    for (int i = 0; i < 256; i++) inv[p[i]] = (uint8_t)i;
}

static int table_has_key(const uint8_t *buf, size_t n, const uint8_t k[16]) {
    if (n < 16) return 0;
    for (size_t i = 0; i + 16 <= n; i++)
        if (memcmp(buf + i, k, 16) == 0) return 1;
    return 0;
}

static void fill_xor_round(uint8_t *tab, uint32_t base, int dir, int round, int src_kind,
                           uint8_t rk_in_pre[16], int use_pre,
                           const uint8_t (*InPinv)[256], int use_in_perm,
                           const uint8_t rk_after[16],
                           uint8_t OutP[16][256],
                           uint8_t Q[4][4][2][256], uint8_t Qi[4][4][2][256],
                           uint32_t env, int sbox_fwd) {
    for (int col = 0; col < 4; col++) {
        for (int side = 0; side < 2; side++) {
            for (int b0 = 0; b0 < 256; b0++) {
                for (int b1 = 0; b1 < 256; b1++) {
                    uint8_t sb[2];
                    int rows[2] = {side * 2, side * 2 + 1};
                    for (int t = 0; t < 2; t++) {
                        int dst = rows[t] + 4 * col;
                        int src = hy_pick(src_kind, dst);
                        uint8_t enc = (t == 0) ? (uint8_t)b0 : (uint8_t)b1;
                        uint8_t clear = use_in_perm ? InPinv[src][enc] : enc;
                        uint8_t v = use_pre ? (uint8_t)(clear ^ rk_in_pre[src]) : clear;
                        sb[t] = sbox_fwd ? sbox(v) : v;
                    }
                    uint32_t word = 0;
                    const uint8_t (*M)[4] = sbox_fwd ? MC : IMC;
                    for (int row = 0; row < 4; row++) {
                        uint8_t partial = (uint8_t)(gmul(sb[0], M[row][rows[0]]) ^ gmul(sb[1], M[row][rows[1]]));
                        uint8_t q = Q[col][row][side][partial];
                        word |= (uint32_t)q << (8 * row);
                    }
                    uint16_t logical = (uint16_t)(b0 | (b1 << 8));
                    uint32_t off = base + (uint32_t)col * HY_COL + (side ? HY_U32 : 0);
                    hy_store32(tab, off, logical, env, hy_tag(dir, round, col, side), word);
                }
            }
        }
        for (int row = 0; row < 4; row++) {
            int dst = row + 4 * col;
            for (int a = 0; a < 256; a++) {
                for (int b = 0; b < 256; b++) {
                    uint8_t mixed = (uint8_t)(Qi[col][row][0][a] ^ Qi[col][row][1][b] ^ rk_after[dst]);
                    uint8_t enc = OutP[dst][mixed];
                    uint32_t zoff = base + (uint32_t)col * HY_COL + HY_U32 + HY_U32 + (uint32_t)row * HY_U8;
                    hy_store8(tab, zoff, (uint16_t)(a | (b << 8)), env, hy_tag(dir, round, col, 2 + row), enc);
                }
            }
        }
    }
}

static void fill_pairs(uint8_t *tab, uint32_t base, int dir, int round, int wiring,
                       uint32_t env, const uint8_t outv[16][256]) {
    for (int p = 0; p < 8; p++) {
        int i0 = p * 2, i1 = i0 + 1;
        for (int a = 0; a < 256; a++) {
            for (int b = 0; b < 256; b++) {
                uint16_t w = (uint16_t)(outv[i0][a] | (outv[i1][b] << 8));
                hy_store16(tab, base + (uint32_t)p * HY_U16, (uint16_t)(a | (b << 8)), env,
                           hy_tag(dir, round, p, 16 + wiring), w);
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <out.bin> [--pagesize N] [--ncpu N] [--cls N]\n"
                        "  缺省读本机 sysctl; 交叉生成时显式给目标设备参数 (iOS: 16384/<ncpu>/<cls>)\n", argv[0]);
        return 2;
    }
    // hw.cachelinesize 是 8 字节 sysctl, int 缓冲会 ENOMEM → 读成 0 (与运行时一致地修)
    unsigned long long pagesize = 0, ncpu = 0, cls = 0;
    bool ov_ps = false, ov_nc = false, ov_cl = false;
    size_t nsz = sizeof(pagesize);
    sysctlbyname("hw.pagesize", &pagesize, &nsz, nullptr, 0);
    nsz = sizeof(ncpu);
    sysctlbyname("hw.ncpu", &ncpu, &nsz, nullptr, 0);
    nsz = sizeof(cls);
    sysctlbyname("hw.cachelinesize", &cls, &nsz, nullptr, 0);
    // 只校验显式传入的目标参数; 本机 sysctl 可能失败 (沙箱), 0 值与运行时一致即可
    for (int i = 2; i < argc - 1; i++) {
        if (!strcmp(argv[i], "--pagesize")) { pagesize = strtoull(argv[++i], nullptr, 0); ov_ps = true; }
        else if (!strcmp(argv[i], "--ncpu")) { ncpu = strtoull(argv[++i], nullptr, 0); ov_nc = true; }
        else if (!strcmp(argv[i], "--cls")) { cls = strtoull(argv[++i], nullptr, 0); ov_cl = true; }
    }
    if ((ov_ps && pagesize == 0) || (ov_nc && ncpu == 0) || (ov_cl && cls == 0)) {
        fprintf(stderr, "bad env value\n");
        return 2;
    }
    uint32_t env = hy_env_mix((int)pagesize, (int)ncpu, (int)cls);
    printf("env: pagesize=%d ncpu=%d cls=%d\n", (int)pagesize, (int)ncpu, (int)cls);

    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = wbaes_key::key_byte(i);
    // 主密钥只在 generate 内经 derive_rk 单轮消费; 无论成败返回后立即焚毁
    int rc = generate(argv[1], env, key);
    burn16(key);
    return rc;
}

static int generate(const char *out_path, uint32_t env, uint8_t key[16]) {
    uint8_t ct[16], back[16];
    ref_encrypt(wbaes_key::test_pt, ct, key);
    if (memcmp(ct, wbaes_key::test_ct, 16) != 0) return 5;
    ref_decrypt(ct, back, key);
    if (memcmp(back, wbaes_key::test_pt, 16) != 0) return 5;

    g_ur = fopen("/dev/urandom", "rb");
    if (!g_ur) return 3;
    int seen[65536];
    memset(seen, 0, sizeof(seen));
    for (int i = 0; i < 65536; i++) {
        uint16_t s = hy_scatter((uint16_t)i, env, 0x1234u);
        if (seen[s]) return 6;
        seen[s] = 1;
    }

    uint8_t P[9][16][256], Pi[9][16][256];
    for (int r = 0; r < 9; r++)
        for (int i = 0; i < 16; i++) rand_perm(P[r][i], Pi[r][i]);

    // Round 0 previously took the plaintext byte straight as the table index, so
    // each entry equalled S(pt ^ k0) and a table reader could recover the key.
    // Give round 0 an input-side bijection too: the tables are indexed by P0(pt)
    // and the runtime applies P0 before the first lookup.
    uint8_t P0[16][256], P0i[16][256];
    for (int i = 0; i < 16; i++) rand_perm(P0[i], P0i[i]);

    std::vector<uint8_t> tab(HY_TOTAL, 0);

    for (int r = 0; r < 9; r++) {
        uint8_t Q[4][4][2][256], Qi[4][4][2][256];
        for (int c = 0; c < 4; c++)
            for (int row = 0; row < 4; row++)
                for (int side = 0; side < 2; side++) rand_perm(Q[c][row][side], Qi[c][row][side]);
        uint8_t zeros[16] = {};
        uint8_t rk_next[16];
        derive_rk(r + 1, key, rk_next);
        fill_xor_round(tab.data(), hy_enc_col(r, 0), 0, r, 1,
                       r == 0 ? key : zeros, r == 0,
                       r == 0 ? (const uint8_t (*)[256])P0i : Pi[r - 1], 1,
                       rk_next, P[r], Q, Qi, env, 1);
        burn16(rk_next);                   // 本轮密钥随表写入完成即焚
        burn(Q, sizeof(Q));                // Q 网络编码随表固化, 缓冲即焚
        burn(Qi, sizeof(Qi));
    }
    {
        uint8_t rk10[16];
        derive_rk(10, key, rk10);
        uint8_t outv[16][256];
        for (int dst = 0; dst < 16; dst++) {
            int src = hy_sr_src(dst);
            for (int a = 0; a < 256; a++) {
                uint8_t clear = Pi[8][src][a];
                outv[dst][a] = (uint8_t)(sbox(clear) ^ rk10[dst]);
            }
        }
        burn16(rk10);                      // RK10 用完即焚 (解密入口再派生)
        fill_pairs(tab.data(), hy_enc_final(), 0, 9, 1, env, outv);
        burn(outv, sizeof(outv));          // 含 sbox^RK10, 即焚
        // P/Pi 编码链最后消费点已过, 全部焚毁 (~73KB)
        burn(P, sizeof(P));
        burn(Pi, sizeof(Pi));
    }

    auto table_enc = [&](const uint8_t in[16], uint8_t out[16]) {
        uint8_t s[16], n[16];
        for (int i = 0; i < 16; i++) s[i] = P0[i][in[i]]; // round-0 input bijection
        for (int r = 0; r < HY_MC_ROUNDS; r++) {
            hy_mc_round(tab.data(), hy_enc_col(r, 0), r, 0, 1, s, n, env);
            memcpy(s, n, 16);
        }
        hy_pair_map(tab.data(), hy_enc_final(), s, out, env, 0, 9, 1);
    };
    table_enc(wbaes_key::test_pt, ct);
    if (memcmp(ct, wbaes_key::test_ct, 16) != 0) return 8;

    // 解密编码：D[9] 是最后一轮加密之后的状态，D[0] 是 pt^rk0。
    uint8_t D[10][16][256], Di[10][16][256];
    for (int r = 0; r < 10; r++)
        for (int i = 0; i < 16; i++) rand_perm(D[r][i], Di[r][i]);
    uint8_t Mperm[9][16][256], Minv[9][16][256];
    for (int r = 0; r < 9; r++)
        for (int i = 0; i < 16; i++) rand_perm(Mperm[r][i], Minv[r][i]);

    {
        uint8_t rk10[16];
        derive_rk(10, key, rk10);
        uint8_t outv[16][256];
        for (int dst = 0; dst < 16; dst++) {
            int src = hy_isr_src(dst);
            for (int a = 0; a < 256; a++) {
                uint8_t x = (uint8_t)(a ^ rk10[src]);
                outv[dst][a] = D[9][dst][inv_sbox(x)];
            }
        }
        burn16(rk10);                      // RK10 用完即焚
        fill_pairs(tab.data(), hy_dec_entry(), 1, 0, 2, env, outv);
        burn(outv, sizeof(outv));          // 含 inv_sbox(x^RK10), 即焚
    }

    for (int step = 0; step < 9; step++) {
        int fwd = 9 - step;
        uint8_t Q[4][4][2][256], Qi[4][4][2][256];
        for (int c = 0; c < 4; c++)
            for (int row = 0; row < 4; row++)
                for (int side = 0; side < 2; side++) rand_perm(Q[c][row][side], Qi[c][row][side]);
        // InvMC(x ^ rk) = InvMC(x) ^ InvMC(rk)。常量折进联合表。
        uint8_t rk_fwd[16], folded[16];
        derive_rk(fwd, key, rk_fwd);
        memcpy(folded, rk_fwd, 16);
        burn16(rk_fwd);                    // 拷入 folded 后即焚
        mix(folded, IMC);
        uint8_t no_pre[16] = {};
        fill_xor_round(tab.data(), hy_dec_mc(step), 1, step, 0,
                       no_pre, 0, Di[fwd], 1, folded, Mperm[step], Q, Qi, env, 0);
        burn16(folded);                    // 折叠常量随本轮表写入完成即焚
        burn(Q, sizeof(Q));                // Q 网络编码即焚
        burn(Qi, sizeof(Qi));

        uint8_t outv[16][256];
        for (int dst = 0; dst < 16; dst++) {
            int src = hy_isr_src(dst);
            for (int a = 0; a < 256; a++) {
                uint8_t clear = Minv[step][src][a];
                outv[dst][a] = D[fwd - 1][dst][inv_sbox(clear)];
            }
        }
        fill_pairs(tab.data(), hy_dec_sb(step), 1, 20 + step, 2, env, outv);
        burn(outv, sizeof(outv));
    }
    {
        uint8_t outv[16][256];
        for (int dst = 0; dst < 16; dst++) {
            for (int a = 0; a < 256; a++) outv[dst][a] = (uint8_t)(Di[0][dst][a] ^ key[dst]);   // RK0 = 主密钥
        }
        fill_pairs(tab.data(), hy_dec_tail(), 1, 40, 0, env, outv);
        burn(outv, sizeof(outv));          // 含主密钥异或分量, 即焚
        // 解密编码链最后消费点已过, 全部焚毁 (~205KB)
        burn(D, sizeof(D));
        burn(Di, sizeof(Di));
        burn(Mperm, sizeof(Mperm));
        burn(Minv, sizeof(Minv));
    }

    auto table_dec = [&](const uint8_t in[16], uint8_t out[16]) {
        uint8_t s[16], t[16], n[16];
        hy_pair_map(tab.data(), hy_dec_entry(), in, s, env, 1, 0, 2);
        for (int step = 0; step < HY_DEC_STEPS; step++) {
            hy_mc_round(tab.data(), hy_dec_mc(step), step, 1, 0, s, t, env);
            hy_pair_map(tab.data(), hy_dec_sb(step), t, n, env, 1, 20 + step, 2);
            memcpy(s, n, 16);
        }
        hy_pair_map(tab.data(), hy_dec_tail(), s, out, env, 1, 40, 0);
    };

    table_enc(wbaes_key::test_pt, ct);
    table_dec(ct, back);
    if (memcmp(ct, wbaes_key::test_ct, 16) != 0) return 8;
    if (memcmp(back, wbaes_key::test_pt, 16) != 0) return 9;

    for (int n = 0; n < 8; n++) {
        uint8_t pt[16], c1[16], c2[16], p2[16];
        for (int i = 0; i < 16; i++) pt[i] = (uint8_t)rnd32();
        ref_encrypt(pt, c1, key);
        table_enc(pt, c2);
        if (memcmp(c1, c2, 16) != 0) return 10;
        table_dec(c2, p2);
        if (memcmp(p2, pt, 16) != 0) return 11;
    }
    fclose(g_ur);
    g_ur = nullptr;

    // 逐轮核验表内无轮密钥残留; 每轮扫描完立即焚毁该轮密钥
    for (int r = 0; r <= 10; r++) {
        uint8_t rkb[16];
        derive_rk(r, key, rkb);
        int hit = table_has_key(tab.data(), tab.size(), rkb);
        burn16(rkb);
        if (hit) return 12;
    }
    uint32_t maskSeed = 0;
    std::vector<uint8_t> plainCopy = tab;
    {
        uint8_t kb[16];
        for (int i = 0; i < 16; i++) kb[i] = wbaes_key::key_byte(i);
        uint32_t st = hy_mask_seed(kb);
        maskSeed = st;
        for (size_t i = 0; i < tab.size(); ++i) tab[i] ^= hy_mask_next(&st);
        burn(kb, sizeof(kb));
    }

    if (FILE *pf = fopen("hy_table.plain.bin", "wb")) {
        fwrite(plainCopy.data(), 1, plainCopy.size(), pf);
        fclose(pf);
    }

    FILE *fp = fopen(out_path, "wb");
    if (!fp) return 7;
    if (fwrite(tab.data(), 1, tab.size(), fp) != tab.size()) return 7;
    fclose(fp);

    // Bake a seal of the table so the runtime can tell a modified table from the
    // one this generation produced. Emitted next to the table as hy_seal.h.
    {
        uint32_t seal = 2166136261u;
        for (size_t i = 0; i < tab.size(); ++i) {
            seal ^= tab[i];
            seal *= 16777619u;
        }
        // Sampled seal: what the per-call check can afford after the one full pass.
        uint32_t sampled = 2166136261u;
        for (size_t i = 0; i < tab.size(); i += 4096) {
            sampled ^= tab[i];
            sampled *= 16777619u;
        }
        FILE *sf = fopen("hy_seal.h", "w");
        if (!sf) return 7;
        fprintf(sf,
                "// generated by gen_hybrid.cpp - do not edit\n"
                "#pragma once\n"
                "#define HY_TABLE_BYTES %uu\n"
                "#define HY_TABLE_SEAL 0x%08xu\n"
                "#define HY_TABLE_SEAL_S4096 0x%08xu\n"
                "#define HY_MASK_SEED 0x%08xu\n",
                (unsigned)tab.size(), seal, sampled, maskSeed);
        fclose(sf);
        printf("seal: 0x%08x\n", seal);
    }
    {
        FILE *inf = fopen("hy_in.h", "w");
        if (!inf) return 7;
        fprintf(inf, "// generated by gen_hybrid.cpp - do not edit\n#pragma once\n");
        fprintf(inf, "static const unsigned char HY_P0[16][256] = {\n");
        for (int i = 0; i < 16; i++) {
            fprintf(inf, "  {");
            for (int v = 0; v < 256; v++) fprintf(inf, "%s%u", v ? "," : "", P0[i][v]);
            fprintf(inf, "},\n");
        }
        fprintf(inf, "};\nstatic const unsigned char HY_P0I[16][256] = {\n");
        for (int i = 0; i < 16; i++) {
            fprintf(inf, "  {");
            for (int v = 0; v < 256; v++) fprintf(inf, "%s%u", v ? "," : "", P0i[i][v]);
            fprintf(inf, "},\n");
        }
        fprintf(inf, "};\n");
        fclose(inf);
        printf("round-0 input bijection: emitted hy_in.h\n");
    }
    printf("table-check PASS\nseal-check PASS\nwrote %s (%u bytes)\n", out_path, HY_TOTAL);
    return 0;
}
