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

// ---- per-round family schedule -------------------------------------------------
// Which shape each round uses. Every family computes the identical function, so
// the ciphertext cannot depend on this array - that is exactly what the checks
// below verify. Within one column every family but F0 hides its table values the
// same way: each lane of a lookup is a random 256-element bijection of
// MC[row][k]*S(x), the four lanes of a row are decoded two at a time in a 64K
// table (the inverse of those bijections), the two plain partial sums are XORed,
// and a 256-entry table applies the random boundary permutation. So no table row
// holds S(x^k) or MC(S(x^k)) verbatim, and no boundary is affine.
static const int SCHED_ENC[9] = {HY_FAM_T32, HY_FAM_T8, HY_FAM_T32K, HY_FAM_PAIR, HY_FAM_T32,
                                 HY_FAM_T8, HY_FAM_PAIR, HY_FAM_T32K, HY_FAM_T32};
static const int SCHED_DEC[9] = {HY_FAM_PAIR, HY_FAM_T32, HY_FAM_T8, HY_FAM_PAIR, HY_FAM_T32K,
                                 HY_FAM_T32, HY_FAM_T8, HY_FAM_PAIR, HY_FAM_T32K};

// What one round needs to know, independent of which family implements it.
struct RndSpec {
    const uint8_t (*inp)[256];  // input decoding per source byte; null = identity
    const uint8_t *rk_pre;      // XORed before SubBytes (round 0 only); null = none
    const uint8_t *rk_after;    // constant added after the linear layer
    const uint8_t (*outp)[256]; // boundary permutation per destination byte
    int src_kind;
    int sbox_fwd;               // 1: SubBytes then MC; 0: identity then InvMC
};

static uint8_t round_byte(const RndSpec &s, int src, uint8_t enc) {
    uint8_t v = s.inp ? s.inp[src][enc] : enc;
    if (s.rk_pre) v ^= s.rk_pre[src];
    return s.sbox_fwd ? sbox(v) : v;
}

// FAM_PAIR: two 16-bit pair tables feed a Q network, four byte tables invert Q,
// add the round constant and apply the output encoding. Kept exactly as it was,
// because this is the shape the earlier generations were verified on.
static void fill_col_pair(uint8_t *tab, uint32_t cb, int dir, int round, int col,
                          const RndSpec &sp, uint32_t env) {
    const uint8_t (*M)[4] = sp.sbox_fwd ? MC : IMC;
    uint8_t Q[4][2][256], Qi[4][2][256];
    for (int row = 0; row < 4; row++)
        for (int side = 0; side < 2; side++) rand_perm(Q[row][side], Qi[row][side]);
    for (int side = 0; side < 2; side++) {
        const int rows[2] = {side * 2, side * 2 + 1};
        for (int b0 = 0; b0 < 256; b0++)
            for (int b1 = 0; b1 < 256; b1++) {
                uint8_t sb[2];
                for (int t = 0; t < 2; t++)
                    sb[t] = round_byte(sp, hy_pick(sp.src_kind, rows[t] + 4 * col),
                                       (uint8_t)(t ? b1 : b0));
                uint32_t word = 0;
                for (int row = 0; row < 4; row++) {
                    uint8_t partial = (uint8_t)(gmul(sb[0], M[row][rows[0]]) ^ gmul(sb[1], M[row][rows[1]]));
                    word |= (uint32_t)Q[row][side][partial] << (8 * row);
                }
                hy_store32(tab, cb + (side ? HY_U32 : 0u), (uint16_t)(b0 | (b1 << 8)), env,
                           hy_tag(dir, round, col, HY_K_PAIR_L + side), word);
            }
    }
    // The two halves meet in a 64K two-byte table: it inverts Q for each half, adds
    // the round constant and applies the output bijection. Qi never reaches the
    // artifact - it exists in this process only, to compute the table values.
    for (int row = 0; row < 4; row++) {
        const int dst = row + 4 * col;
        for (int a = 0; a < 256; a++)
            for (int b = 0; b < 256; b++) {
                uint8_t mixed = (uint8_t)(Qi[row][0][a] ^ Qi[row][1][b] ^ sp.rk_after[dst]);
                hy_store8(tab, cb + HY_BDY_OFF + (uint32_t)row * HY_N, (uint16_t)(a | (b << 8)), env,
                          hy_tag(dir, round, col, HY_K_BDY_PAIR + row), sp.outp[dst][mixed]);
            }
    }
    burn(Q, sizeof(Q));
    burn(Qi, sizeof(Qi));
}

// One random bijection per (row,k) lane and its inverse. The inverse is
// materialised inside the 64K decode tables only: a lane value cannot be undone
// by reading one row of one 256-entry table, which is what made dl3's rows
// equal MC[row][k]*S(x) and handed over the key byte.
struct LaneEnc {
    uint8_t e[4][4][256];
    uint8_t d[4][4][256];
};

static void fill_lane_enc(LaneEnc &L) {
    for (int row = 0; row < 4; row++)
        for (int k = 0; k < 4; k++) rand_perm(L.e[row][k], L.d[row][k]);
}

// The tail F1/F2/F3 share: two 64K pair-decode tables per output row (lanes k=0,1
// and lanes k=2,3), each one a random bijection Z applied to the XOR of the two
// lane inverses, then one 64K two-byte boundary table that undoes both Z, adds the
// column constant and applies the output bijection. Z's inverse exists only inside
// that boundary table, so the pipeline is not XOR-separable and no standalone
// inverse array is written. key_in_quad != 0 folds the column constant into the
// first decode table, which is how F3 keeps "no key XOR anywhere in the code".
static void fill_col_tail(uint8_t *tab, uint32_t cb, int dir, int round, int col,
                          int qk, int bk, int key_in_quad, const RndSpec &sp,
                          const LaneEnc &L, uint32_t env) {
    for (int row = 0; row < 4; row++) {
        const int dst = row + 4 * col;
        uint8_t Z[2][256], Zi[2][256];
        for (int p = 0; p < 2; p++) rand_perm(Z[p], Zi[p]);
        for (int p = 0; p < 2; p++) {
            const uint8_t *d0 = L.d[row][2 * p], *d1 = L.d[row][2 * p + 1];
            for (int a = 0; a < 256; a++)
                for (int b = 0; b < 256; b++) {
                    uint8_t v = (uint8_t)(d0[a] ^ d1[b]);
                    if (key_in_quad && p == 0) v ^= sp.rk_after[dst];
                    hy_store8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + p) * HY_N,
                              (uint16_t)(a | (b << 8)), env,
                              hy_tag(dir, round, col, qk + 2 * row + p), Z[p][v]);
                }
        }
        const uint8_t rk = key_in_quad ? 0 : sp.rk_after[dst];
        for (int u = 0; u < 256; u++)
            for (int v = 0; v < 256; v++) {
                uint8_t mixed = (uint8_t)(Zi[0][u] ^ Zi[1][v] ^ rk);
                hy_store8(tab, cb + HY_BDY_OFF + (uint32_t)row * HY_N, (uint16_t)(u | (v << 8)), env,
                          hy_tag(dir, round, col, bk + row), sp.outp[dst][mixed]);
            }
        burn(Z, sizeof(Z));
        burn(Zi, sizeof(Zi));
    }
}

// FAM_T32 / FAM_T32K: four 32-bit lookups per column. Each byte of the 32-bit
// word is one MC contribution already pushed through a random bijection, so the
// word is not XOR-combined directly; the decode tables below undo the bijections
// on a pair of lanes at a time. The key sits in the boundary permutation's index
// (T32) or in the first decode table (T32K).
static void fill_col_t32(uint8_t *tab, uint32_t cb, int dir, int round, int col, int fam,
                         const RndSpec &sp, uint32_t env) {
    const uint8_t (*M)[4] = sp.sbox_fwd ? MC : IMC;
    LaneEnc L;
    fill_lane_enc(L);
    for (int k = 0; k < 4; k++) {
        const int src = hy_pick(sp.src_kind, k + 4 * col);
        for (int enc = 0; enc < 256; enc++) {
            const uint8_t sb = round_byte(sp, src, (uint8_t)enc);
            uint32_t word = 0;
            for (int row = 0; row < 4; row++)
                word |= (uint32_t)L.e[row][k][gmul(sb, M[row][k])] << (8 * row);
            hy_store32t(tab, cb + (uint32_t)k * HY_W1024, (uint8_t)enc, env,
                        hy_tag(dir, round, col,
                               (fam == HY_FAM_T32K ? HY_K_T32K_W : HY_K_T32_W) + k),
                        word);
        }
    }
    if (fam == HY_FAM_T32K)
        fill_col_tail(tab, cb, dir, round, col, HY_K_T32K_Q, HY_K_BDY_T32K, 1, sp, L, env);
    else
        fill_col_tail(tab, cb, dir, round, col, HY_K_T32_Q, HY_K_BDY_T32, 0, sp, L, env);
    burn(&L, sizeof(L));
}

// FAM_T8: 16 coefficient byte tables per column, one per (k,row), plus the same
// decode/boundary tail. No 32-bit load anywhere in this shape.
static void fill_col_t8(uint8_t *tab, uint32_t cb, int dir, int round, int col,
                        const RndSpec &sp, uint32_t env) {
    const uint8_t (*M)[4] = sp.sbox_fwd ? MC : IMC;
    LaneEnc L;
    fill_lane_enc(L);
    for (int k = 0; k < 4; k++) {
        const int src = hy_pick(sp.src_kind, k + 4 * col);
        for (int row = 0; row < 4; row++)
            for (int enc = 0; enc < 256; enc++)
                hy_store8t(tab, cb + (uint32_t)(k * 4 + row) * HY_W256, (uint8_t)enc, env,
                           hy_tag(dir, round, col, HY_K_T8_C + k * 4 + row),
                           L.e[row][k][gmul(round_byte(sp, src, (uint8_t)enc), M[row][k])]);
    }
    fill_col_tail(tab, cb, dir, round, col, HY_K_T8_Q, HY_K_BDY_T8, 0, sp, L, env);
    burn(&L, sizeof(L));
}

// ---- the 32-bit nonlinear recoding (generator side) -------------------------
// The generator draws the three rounds (per-byte bijection, per-byte inverse,
// per-round constant), writes both directions' tables and burns the pair. The
// forward direction is composed into nothing - the tables are used as they are -
// and the inverse direction is what the round boundary applies, so no inverse of
// the whole map is ever materialised.
struct Spn {
    uint8_t s[HY_SPN_ROUNDS][4][256];
    uint8_t si[HY_SPN_ROUNDS][4][256];
    uint8_t c[HY_SPN_ROUNDS][4];
};

static void spn_gen(Spn &S) {
    for (uint32_t i = 0; i < HY_SPN_ROUNDS; i++)
        for (int j = 0; j < 4; j++) {
            rand_perm(S.s[i][j], S.si[i][j]);
            S.c[i][j] = (uint8_t)rnd32();
        }
}

static void spn_fill(uint8_t *tab, uint32_t cb, int dir, int round, int col,
                     const Spn &S, uint32_t env) {
    for (uint32_t i = 0; i < HY_SPN_ROUNDS; i++)
        for (int j = 0; j < 4; j++) {
            const int ks = HY_K_SPN_S + (int)(i * 4u) + j;
            const int ki = HY_K_SPN_SI + (int)(i * 4u) + j;
            for (int v = 0; v < 256; v++) {
                hy_store8t(tab, cb + HY_SPN_OFF + (i * 4u + (uint32_t)j) * HY_W256, (uint8_t)v, env,
                           hy_tag(dir, round, col, ks), S.s[i][j][v]);
                hy_store8t(tab, cb + HY_SPN_OFF + HY_SPN_SI_OFF + (i * 4u + (uint32_t)j) * HY_W256,
                           (uint8_t)v, env, hy_tag(dir, round, col, ki), S.si[i][j][v]);
            }
            // Constants are read directly (not through an index), so they sit in a
            // fixed 12-byte block of the same slot: still inside the masked blob.
            tab[cb + HY_SPN_OFF + HY_SPN_C_OFF + i * 4u + (uint32_t)j] = S.c[i][j];
        }
}

// MDS self-check: the matrix and its inverse, applied in turn, must be the
// identity, and every square submatrix of the forward matrix must be nonsingular
// (that is what "MDS" buys: a single changed input byte changes every output
// byte). Both properties are printed by generate().
static uint8_t gdet(const uint8_t m[4][4], int n) {
    if (n == 1) return m[0][0];
    uint8_t s = 0;
    for (int j = 0; j < n; j++) {
        if (!m[0][j]) continue;
        uint8_t sub[4][4] = {{0}};
        for (int i = 1; i < n; i++) {
            int c = 0;
            for (int k = 0; k < n; k++)
                if (k != j) sub[i - 1][c++] = m[i][k];
        }
        s ^= gmul(m[0][j], gdet(sub, n - 1));
    }
    return s;
}

static int spn_mds_check() {
    static const uint8_t W[4] = {1, 4, 3, 7};
    static const uint8_t V[4] = {11, 11, 9, 8};
    uint8_t M[4][4], Mi[4][4];
    for (int r = 0; r < 4; r++)
        for (int k = 0; k < 4; k++) {
            M[r][k] = W[(k - r + 4) & 3];
            Mi[r][k] = V[(k - r + 4) & 3];
        }
    for (int r = 0; r < 4; r++)
        for (int k = 0; k < 4; k++) {
            uint8_t a = 0;
            for (int t = 0; t < 4; t++) a ^= gmul(M[r][t], Mi[t][k]);
            if (a != (uint8_t)(r == k)) return 0;
        }
    for (int n = 1; n <= 4; n++)
        for (int rows = 0; rows < 16; rows++)
            for (int cols = 0; cols < 16; cols++) {
                int nr = 0, nc = 0;
                uint8_t sub[4][4] = {{0}};
                for (int i = 0; i < 4; i++) {
                    if (!(rows & (1 << i))) continue;
                    nc = 0;
                    for (int j = 0; j < 4; j++)
                        if (cols & (1 << j)) sub[nr][nc++] = M[i][j];
                    nr++;
                }
                if (nr != n || nc != n) continue;
                if (gdet(sub, n) == 0) return 0;
            }
    return 1;
}

static void fill_round(uint8_t *tab, uint32_t base, int dir, int round, int fam,
                       const RndSpec &sp, uint32_t env) {
    for (int col = 0; col < 4; col++) {
        const uint32_t cb = base + (uint32_t)col * HY_COL;
        if (fam == HY_FAM_PAIR) fill_col_pair(tab, cb, dir, round, col, sp, env);
        else if (fam == HY_FAM_T8) fill_col_t8(tab, cb, dir, round, col, sp, env);
        else fill_col_t32(tab, cb, dir, round, col, fam, sp, env);
    }
}

// The schedule goes into the table so the reader is driven by data: a family
// byte per (dir, round) plus a check byte, all sealed and masked with the rest.
// The tail of the block carries the layout words the HSV bytecode reads through
// Tld: base and round stride per direction, column stride, and the two lane
// strides (one table per lane for F1/F2/F3, two pair tables for F0). They sit at
// 4-byte-aligned offsets because Tld only reads aligned words.
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void write_sched(uint8_t *tab, const int enc[9], const int dec[9]) {
    for (int d = 0; d < 2; d++) {
        const int *s = d == 0 ? enc : dec;
        uint8_t *g = tab + HY_SCHED_OFF + (uint32_t)d * HY_SCHED_STRIDE;
        uint8_t x = (uint8_t)d;
        for (int r = 0; r < 9; r++) {
            g[r] = (uint8_t)s[r];
            x ^= (uint8_t)s[r];
        }
        g[9] = x;
    }
    uint8_t *w = tab + HY_SCHED_OFF;
    put32(w + 32, 0u);                            // encrypt base offset
    put32(w + 36, HY_OFF_DEC + HY_DEC_ENTRY);     // decrypt base offset
    put32(w + 40, HY_ROUND);                      // encrypt round stride
    put32(w + 44, HY_DEC_STEP);                   // decrypt round stride
    put32(w + 48, HY_COL);                        // column stride
    put32(w + 52, HY_W1024);                      // lane stride, F1/F2/F3
    put32(w + 56, HY_U32);                        // pair stride, F0 lanes 2/3
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

// --fam N forces every round in both directions to family N (0..3). Every family
// computes the same function, so the ciphertext must not change: that is what the
// four forced builds verify. Without it the mixed schedule above is used.
static int g_force_fam = -1;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <out.bin> [--pagesize N] [--ncpu N] [--cls N] [--fam N]\n"
                        "  缺省读本机 sysctl; 交叉生成时显式给目标设备参数 (iOS: 16384/<ncpu>/<cls>)\n"
                        "  --fam 0..3: 九轮全部使用同一实现族 (用于密文一致性对照)\n", argv[0]);
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
        else if (!strcmp(argv[i], "--fam")) {
            const long v = strtol(argv[++i], nullptr, 0);
            if (v < 0 || v > 3) { fprintf(stderr, "bad --fam (0..3)\n"); return 2; }
            g_force_fam = (int)v;
        }
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

    // The recoding's mixing matrix must be invertible and MDS; both are structural
    // facts, so a failure here means the constants in wbaes_hybrid.h were edited.
    if (!spn_mds_check()) return 13;
    printf("spn-mds: PASS (circulant (1,4,3,7) / inverse (11,11,9,8), all square minors nonzero)\n");

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

    // The schedule: mixed by default, one family everywhere under --fam.
    int sched_enc[9], sched_dec[9];
    for (int i = 0; i < 9; i++) {
        sched_enc[i] = g_force_fam >= 0 ? g_force_fam : SCHED_ENC[i];
        sched_dec[i] = g_force_fam >= 0 ? g_force_fam : SCHED_DEC[i];
    }

    std::vector<uint8_t> tab(HY_TOTAL, 0);
    write_sched(tab.data(), sched_enc, sched_dec);

    // Recoding parameters per (direction, round, column). Only the generator holds
    // them; the table gets the forward and inverse S-boxes and the constants, never
    // the inverse of the composed 32-bit map.
    std::vector<Spn> spn((size_t)(2 * HY_MC_ROUNDS * 4));
    auto spn_at = [&](int dir, int round, int col) -> Spn & {
        return spn[(size_t)((dir * HY_MC_ROUNDS + round) * 4 + col)];
    };

    for (int r = 0; r < 9; r++) {
        uint8_t rk_next[16];
        derive_rk(r + 1, key, rk_next);
        RndSpec sp;
        sp.inp = (r == 0) ? (const uint8_t (*)[256])P0i : (const uint8_t (*)[256])Pi[r - 1];
        sp.rk_pre = (r == 0) ? key : nullptr;
        sp.rk_after = rk_next;
        sp.outp = (const uint8_t (*)[256])P[r];
        sp.src_kind = 1;
        sp.sbox_fwd = 1;
        for (int col = 0; col < 4; col++) spn_gen(spn_at(0, r, col));
        fill_round(tab.data(), hy_enc_col(r, 0), 0, r, sched_enc[r], sp, env);
        for (int col = 0; col < 4; col++)
            spn_fill(tab.data(), hy_enc_col(r, col), 0, r, col, spn_at(0, r, col), env);
        burn16(rk_next);                   // 本轮密钥随表写入完成即焚
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
            // Undo the previous round's 32-bit recoding first: the round tables are
            // built on the plain (output-bijection) domain, exactly as hy_encrypt_once
            // does it.
            if (r) hy_rec_undo(tab.data(), hy_enc_col(r - 1, 0), 0, r - 1, s, env);
            hy_mc_round(tab.data(), hy_enc_col(r, 0), r, 0, 1, s, n, env);
            memcpy(s, n, 16);
        }
        hy_rec_undo(tab.data(), hy_enc_col(HY_MC_ROUNDS - 1, 0), 0, HY_MC_ROUNDS - 1, s, env);
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
        // InvMC(x ^ rk) = InvMC(x) ^ InvMC(rk)。常量折进联合表。
        uint8_t rk_fwd[16], folded[16];
        derive_rk(fwd, key, rk_fwd);
        memcpy(folded, rk_fwd, 16);
        burn16(rk_fwd);                    // 拷入 folded 后即焚
        mix(folded, IMC);
        RndSpec sp;
        sp.inp = (const uint8_t (*)[256])Di[fwd];
        sp.rk_pre = nullptr;
        sp.rk_after = folded;
        sp.outp = (const uint8_t (*)[256])Mperm[step];
        sp.src_kind = 0;
        sp.sbox_fwd = 0;
        for (int col = 0; col < 4; col++) spn_gen(spn_at(1, step, col));
        fill_round(tab.data(), hy_dec_mc(step), 1, step, sched_dec[step], sp, env);
        for (int col = 0; col < 4; col++)
            spn_fill(tab.data(), hy_dec_mc(step) + (uint32_t)col * HY_COL, 1, step, col,
                     spn_at(1, step, col), env);
        burn16(folded);                    // 折叠常量随本轮表写入完成即焚

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
            hy_rec_undo(tab.data(), hy_dec_mc(step), 1, step, t, env);
            hy_pair_map(tab.data(), hy_dec_sb(step), t, n, env, 1, 20 + step, 2);
            memcpy(s, n, 16);
        }
        // No undo here: the last pair map already returned the D[0] domain, and
        // hy_dec_tail() expects exactly that.
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
    burn(spn.data(), spn.size() * sizeof(Spn)); // 编码参数用完即焚

    // 逐轮核验表内无轮密钥残留; 每轮扫描完立即焚毁该轮密钥
    for (int r = 0; r <= 10; r++) {
        uint8_t rkb[16];
        derive_rk(r, key, rkb);
        int hit = table_has_key(tab.data(), tab.size(), rkb);
        burn16(rkb);
        if (hit) return 12;
    }
    // The mask seed must not be a function of the key: deriving it from the key
    // handed the attacker a free checksum of the very key this was meant to
    // protect. It is random per generation, and it is stored as four words whose
    // XOR is the seed, so no single immediate equals it.
    uint32_t maskSeed = arc4random();
    uint32_t seedFrag[4];
    seedFrag[0] = arc4random();
    seedFrag[1] = arc4random();
    seedFrag[2] = arc4random();
    seedFrag[3] = seedFrag[0] ^ seedFrag[1] ^ seedFrag[2] ^ maskSeed;
    uint32_t sampledPlain = 2166136261u;
    {
        uint32_t st = maskSeed;
        for (size_t i = 0; i < tab.size(); ++i) {
            uint8_t m = hy_mask_next(&st);
            if ((i & 4095u) == 0) { sampledPlain ^= tab[i]; sampledPlain *= 16777619u; }
            tab[i] ^= m;
        }
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
                "#define HY_TABLE_SEAL_S4096_P 0x%08xu\n"
                "static volatile const unsigned int HY_SEED_FRAG[4] = {0x%08xu,0x%08xu,0x%08xu,0x%08xu};\n",
                (unsigned)tab.size(), seal, sampled, sampledPlain,
                seedFrag[0], seedFrag[1], seedFrag[2], seedFrag[3]);
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
    printf("table-check PASS\nseal-check PASS\n");
    {
        static const char *nm[4] = {"F0", "F1", "F2", "F3"};
        printf("round families enc:");
        for (int r = 0; r < 9; r++) printf(" %s", nm[sched_enc[r]]);
        printf("\n              dec:");
        for (int r = 0; r < 9; r++) printf(" %s", nm[sched_dec[r]]);
        printf("\n");
    }
    printf("wrote %s (%u bytes)\n", out_path, HY_TOTAL);
    return 0;
}
