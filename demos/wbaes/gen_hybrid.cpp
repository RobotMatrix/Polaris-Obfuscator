// 生成中间轮表和份额池。只写文件，不打印密钥。
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#define WBAES_NO_DEVBIND 1
#include "wbaes_key.h"
#include "wbaes_hybrid.h"
#include <sys/sysctl.h>

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) { if (b & 1) p ^= a; a = xtime(a); b = (uint8_t)(b >> 1); }
    return p;
}
static uint8_t rotl8(uint8_t x, int n) { return (uint8_t)((x << n) | (x >> (8 - n))); }
static uint8_t gf_inv(uint8_t x) {
    if (!x) return 0;
    uint8_t a = gmul(x, x), x2 = a; a = gmul(a, a); uint8_t x4 = a; a = gmul(a, a); uint8_t x8 = a;
    a = gmul(a, a); uint8_t x16 = a; a = gmul(a, a); uint8_t x32 = a; a = gmul(a, a); uint8_t x64 = a;
    a = gmul(a, a);
    uint8_t p = gmul(a, x64); p = gmul(p, x32); p = gmul(p, x16); p = gmul(p, x8); p = gmul(p, x4); return gmul(p, x2);
}
static uint8_t sbox(uint8_t x) {
    uint8_t b = gf_inv(x);
    return (uint8_t)(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63);
}
static uint8_t inv_sbox(uint8_t x) {
    return gf_inv((uint8_t)(rotl8(x, 1) ^ rotl8(x, 3) ^ rotl8(x, 6) ^ 0x05));
}
static uint32_t mc_col(uint8_t sb, int kk) {
    switch (kk) {
    case 0: return ((uint32_t)gmul(sb, 2) << 24) | ((uint32_t)sb << 16) | ((uint32_t)sb << 8) | gmul(sb, 3);
    case 1: return ((uint32_t)gmul(sb, 3) << 24) | ((uint32_t)gmul(sb, 2) << 16) | ((uint32_t)sb << 8) | sb;
    case 2: return ((uint32_t)sb << 24) | ((uint32_t)gmul(sb, 3) << 16) | ((uint32_t)gmul(sb, 2) << 8) | sb;
    default:return ((uint32_t)sb << 24) | ((uint32_t)sb << 16) | ((uint32_t)gmul(sb, 3) << 8) | gmul(sb, 2);
    }
}
static uint32_t imc_col(uint8_t v, int kk) {
    switch (kk) {
    case 0: return ((uint32_t)gmul(v, 14) << 24) | ((uint32_t)gmul(v, 9) << 16) | ((uint32_t)gmul(v, 13) << 8) | gmul(v, 11);
    case 1: return ((uint32_t)gmul(v, 11) << 24) | ((uint32_t)gmul(v, 14) << 16) | ((uint32_t)gmul(v, 9) << 8) | gmul(v, 13);
    case 2: return ((uint32_t)gmul(v, 13) << 24) | ((uint32_t)gmul(v, 11) << 16) | ((uint32_t)gmul(v, 14) << 8) | gmul(v, 9);
    default:return ((uint32_t)gmul(v, 9) << 24) | ((uint32_t)gmul(v, 13) << 16) | ((uint32_t)gmul(v, 11) << 8) | gmul(v, 14);
    }
}
struct Aff { uint8_t m[8], minv[8], c; };
static int invert(const uint8_t m[8], uint8_t out[8]) {
    uint8_t tmp[8], inv[8];
    memcpy(tmp, m, 8);
    for (int i = 0; i < 8; i++) inv[i] = (uint8_t)(1u << i);
    for (int col = 0; col < 8; col++) {
        int piv = -1;
        for (int r = col; r < 8; r++) if ((tmp[r] >> col) & 1) { piv = r; break; }
        if (piv < 0) return -1;
        if (piv != col) {
            uint8_t t = tmp[col]; tmp[col] = tmp[piv]; tmp[piv] = t;
            t = inv[col]; inv[col] = inv[piv]; inv[piv] = t;
        }
        for (int r = 0; r < 8; r++) if (r != col && ((tmp[r] >> col) & 1)) { tmp[r] ^= tmp[col]; inv[r] ^= inv[col]; }
    }
    memcpy(out, inv, 8);
    return 0;
}
static uint8_t aff_mat(const uint8_t m[8], uint8_t x) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit = 0;
        for (int j = 0; j < 8; j++) if ((m[i] >> j) & 1) bit ^= (x >> j) & 1;
        r |= (uint8_t)(bit << i);
    }
    return r;
}
static uint8_t aff_fwd(const Aff *a, uint8_t x, int use_c) { return (uint8_t)(aff_mat(a->m, x) ^ (use_c ? a->c : 0)); }
static uint8_t aff_inv(const Aff *a, uint8_t z) { return aff_mat(a->minv, (uint8_t)(z ^ a->c)); }
static void make_aff(Aff *a, uint32_t seed) {
    for (int tries = 0; tries < 64; tries++) {
        for (int i = 0; i < 8; i++) { seed = seed * 1664525u + 1013904223u; a->m[i] = (uint8_t)(seed >> 16); }
        a->c = (uint8_t)(seed >> 24);
        if (invert(a->m, a->minv) == 0) return;
    }
}
static void key_expand(const uint8_t key[16], uint8_t rk[11][16]) {
    memcpy(rk[0], key, 16);
    for (int r = 1; r <= 10; r++) {
        uint8_t t[4] = {rk[r - 1][13], rk[r - 1][14], rk[r - 1][15], rk[r - 1][12]};
        uint8_t rc = 1;
        for (int i = 0; i < r - 1; i++) rc = xtime(rc);
        t[0] = (uint8_t)(sbox(t[0]) ^ rc); t[1] = sbox(t[1]); t[2] = sbox(t[2]); t[3] = sbox(t[3]);
        for (int i = 0; i < 16; i++) rk[r][i] = (uint8_t)(rk[r - 1][i] ^ (i < 4 ? t[i] : rk[r][i - 4]));
    }
}

static uint32_t T[8][4][4][256];
static uint32_t TD[9][4][4][256];
static Aff A[8], B[8];

static void build_enc(uint8_t rk[11][16]) {
    for (int r = 0; r < 7; r++) make_aff(&A[r], 0xC0FFEE00u + (uint32_t)r * 17u);
    for (int round = 0; round < 8; round++) {
        const Aff *out = (round < 7) ? &A[round] : nullptr;
        const Aff *in = (round == 0) ? nullptr : &A[round - 1];
        for (int col = 0; col < 4; col++)
            for (int row = 0; row < 4; row++)
                for (int z = 0; z < 256; z++) {
                    uint8_t raw = in ? aff_inv(in, (uint8_t)z) : (uint8_t)z;
                    int src = row + 4 * ((col + row) % 4);
                    uint32_t word = mc_col(sbox((uint8_t)(raw ^ rk[round + 1][src])), row);
                    if (round == 7 && row == 3) {
                        for (int b = 0; b < 4; b++) {
                            uint8_t byte = (uint8_t)((word >> (24 - 8 * b)) ^ rk[9][b + 4 * col]);
                            word = (word & ~(0xFFu << (24 - 8 * b))) | ((uint32_t)byte << (24 - 8 * b));
                        }
                    }
                    if (out) {
                        uint32_t ew = 0;
                        for (int b = 0; b < 4; b++) {
                            uint8_t byte = aff_fwd(out, (uint8_t)(word >> (24 - 8 * b)), row == 3);
                            ew |= (uint32_t)byte << (24 - 8 * b);
                        }
                        word = ew;
                    }
                    T[round][row][col][z] = word;
                }
    }
    uint32_t moved[4][4][256];
    for (int col = 0; col < 4; col++)
        for (int row = 0; row < 4; row++)
            for (int z = 0; z < 256; z++) moved[row][col][hy_nl((uint8_t)z)] = T[0][row][col][z];
    for (int col = 0; col < 4; col++)
        for (int row = 0; row < 4; row++)
            for (int z = 0; z < 256; z++) T[0][row][col][z] = moved[row][col][z];
}
static void build_dec(uint8_t rk[11][16]) {
    for (int r = 0; r < 8; r++) make_aff(&B[r], 0x51A7C300u + (uint32_t)r * 29u);
    for (int round = 0; round < 9; round++) {
        const Aff *in = (round == 0) ? nullptr : &B[round - 1];
        const Aff *out = (round < 8) ? &B[round] : nullptr;
        int rk_i = 9 - round;
        for (int col = 0; col < 4; col++)
            for (int row = 0; row < 4; row++)
                for (int z = 0; z < 256; z++) {
                    uint8_t raw = in ? aff_inv(in, (uint8_t)z) : (uint8_t)z;
                    uint32_t word = imc_col((uint8_t)(inv_sbox(raw) ^ rk[rk_i][row + 4 * col]), row);
                    if (out) {
                        uint32_t ew = 0;
                        for (int b = 0; b < 4; b++) {
                            uint8_t byte = aff_fwd(out, (uint8_t)(word >> (24 - 8 * b)), row == 3);
                            ew |= (uint32_t)byte << (24 - 8 * b);
                        }
                        word = ew;
                    }
                    TD[round][row][col][z] = word;
                }
    }
}

static uint32_t rnd32(FILE *ur) {
    uint32_t x = 0;
    if (fread(&x, 4, 1, ur) != 1) exit(3);
    return x;
}
static void plant(uint32_t *pool, int logical, uint8_t target, uint32_t env, FILE *ur) {
    uint32_t *sl = pool + (size_t)hy_share_id(logical) * HY_PROG;
    for (int i = 0; i < 31; i++) sl[i] = rnd32(ur);
    uint32_t acc = env ^ 0xA5C31E87u;
    for (int i = 0; i < 15; i++) acc = hy_step(acc, sl[i], sl[16 + i]);
    uint32_t top = ((acc >> 24) ^ target) & 0xffu;
    sl[31] = (rnd32(ur) & 0x00ffffffu) | (top << 24);
    if (hy_share_byte(pool, logical, env) != target) exit(4);
}

static void apply_enc(const uint32_t tab[4][4][256], const uint8_t in[16], uint8_t out[16], int nl) {
    for (int col = 0; col < 4; col++) {
        uint32_t acc = 0;
        for (int row = 0; row < 4; row++) {
            int src_col = (col + row) % 4;
            uint8_t b = in[row + 4 * src_col];
            if (nl) b = hy_nl(b);
            acc ^= tab[row][col][b];
        }
        for (int row = 0; row < 4; row++) out[row + 4 * col] = (uint8_t)(acc >> (24 - 8 * row));
    }
}
static int clear_vec(uint8_t rk[11][16]) {
    uint8_t s[16], n[16], ct[16];
    memcpy(s, wbaes_key::test_pt, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[0][i];
    uint8_t t[16], u[16];
    for (int i = 0; i < 16; i++) t[i] = sbox(s[i]);
    for (int row = 0; row < 4; row++)
        for (int col = 0; col < 4; col++) u[row + 4 * col] = t[row + 4 * ((col + row) % 4)];
    for (int col = 0; col < 4; col++) {
        uint32_t acc = 0;
        for (int row = 0; row < 4; row++) acc ^= mc_col(u[row + 4 * col], row);
        for (int row = 0; row < 4; row++) s[row + 4 * col] = (uint8_t)(acc >> (24 - 8 * row));
    }
    apply_enc(T[0], s, n, 1);
    for (int r = 1; r < 8; r++) { apply_enc(T[r], n, s, 0); memcpy(n, s, 16); }
    for (int i = 0; i < 16; i++) t[i] = sbox(n[i]);
    for (int row = 0; row < 4; row++)
        for (int col = 0; col < 4; col++)
            ct[row + 4 * col] = (uint8_t)(t[row + 4 * ((col + row) % 4)] ^ rk[10][row + 4 * col]);
    return memcmp(ct, wbaes_key::test_ct, 16) == 0;
}

static void emit(FILE *fp, const char *name, const uint32_t *w, int n) {
    fprintf(fp, "unsigned int %s[%d] = {\n", name, n);
    for (int i = 0; i < n; i++) fprintf(fp, "0x%08xu%s", w[i], (i + 1) % 8 == 0 ? ",\n" : ",");
    fprintf(fp, "};\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    int pagesize = 0, ncpu = 0, cls = 0;
    size_t nsz = sizeof(int);
    sysctlbyname("hw.pagesize", &pagesize, &nsz, nullptr, 0);
    nsz = sizeof(int);
    sysctlbyname("hw.ncpu", &ncpu, &nsz, nullptr, 0);
    nsz = sizeof(int);
    sysctlbyname("hw.cachelinesize", &cls, &nsz, nullptr, 0);
    uint32_t env = hy_env_mix(pagesize, ncpu, cls);
    uint8_t key[16], rk[11][16];
    for (int i = 0; i < 16; i++) key[i] = wbaes_key::key_byte(i);
    key_expand(key, rk);
    build_enc(rk);
    build_dec(rk);
    if (!clear_vec(rk)) return 5;
    int seen[HY_IDS] = {};
    for (int i = 0; i < HY_IDS; i++) seen[hy_share_id(i)]++;
    for (int i = 0; i < HY_IDS; i++) if (seen[i] != 1) return 6;
    uint32_t pool[HY_POOL_N];
    memset(pool, 0, sizeof(pool));
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur) return 3;
    int real = hy_real_slot(env);
    for (int slot = 0; slot < HY_SLOTS; slot++) {
        for (int which = 0; which < 2; which++) {
            for (int b = 0; b < 16; b++) {
                uint8_t kb = (slot == real) ? rk[which == 0 ? 0 : 10][b] : (uint8_t)rnd32(ur);
                uint8_t s0 = (uint8_t)(rnd32(ur) | 1);
                uint8_t s1 = (uint8_t)(s0 ^ kb);
                plant(pool, hy_id(slot, which, b, 0), s0, env, ur);
                plant(pool, hy_id(slot, which, b, 1), s1, env, ur);
            }
        }
    }
    fclose(ur);
    FILE *fp = fopen(argv[1], "wb");
    if (!fp) return 7;
    emit(fp, "kMidEnc", &T[0][0][0][0], 8 * 4 * 4 * 256);
    emit(fp, "kMidDec", &TD[0][0][0][0], 9 * 4 * 4 * 256);
    emit(fp, "kSharePool", pool, HY_POOL_N);
    fclose(fp);
    printf("table-check PASS\nseal-check PASS\nwrote %s\n", argv[1]);
    return 0;
}
