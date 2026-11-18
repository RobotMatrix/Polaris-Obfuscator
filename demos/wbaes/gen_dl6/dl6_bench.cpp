// Per-block timing for a dl6 table: same round function the runtime would run, no
// tracing, warm-up pays the 70 MB unmask. usage: bench <table_masked> <p0.bin> <seed> <n>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <chrono>
#define HY_TABLE_BYTES 70103104u
#define HY_TRACE(a, l, w) do {} while (0)   // the bench does not record traces
static uint8_t g_tab_buf[HY_TABLE_BYTES];
static const uint8_t *hy_tab_ptr = g_tab_buf;
#define HYKTAB hy_tab_ptr
#include "hy_trace.h"

static unsigned char HY_P0[16][256];
static uint8_t hy_mask_next(uint32_t *s) {
    uint32_t x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; *s = x;
    return (uint8_t)(x >> 24);
}
static void enc_once(const uint8_t in[16], uint8_t out[16], uint32_t env) {
    uint8_t s[16], n[16];
    for (int i = 0; i < 16; i++) s[i] = HY_P0[i][in[i]];
    for (int r = 0; r < HY_MC_ROUNDS; r++) {
        if (r) hy_rec_undo(HYKTAB, hy_enc_col(r - 1, 0), 0, r - 1, s, env);
        if (r == 1) hy_rkz_apply(HYKTAB, s, env);
        hy_mc_round(HYKTAB, hy_enc_col(r, 0), r, 0, 1, s, n, env);
        for (int i = 0; i < 16; i++) s[i] = n[i];
    }
    hy_rec_undo(HYKTAB, hy_enc_col(HY_MC_ROUNDS - 1, 0), 0, HY_MC_ROUNDS - 1, s, env);
    hy_pair_map(HYKTAB, hy_enc_final(), s, out, env, 0, 9, 1);
}
int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: bench <tab> <p0> <seed> <n>\n"); return 2; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    static std::vector<uint8_t> masked(HY_TABLE_BYTES);
    if (fread(masked.data(), 1, HY_TABLE_BYTES, f) != HY_TABLE_BYTES) return 4;
    fclose(f);
    f = fopen(argv[2], "rb");
    if (!f) return 3;
    if (fread(HY_P0, 1, sizeof(HY_P0), f) != sizeof(HY_P0)) return 4;
    fclose(f);
    uint32_t st = (uint32_t)strtoul(argv[3], nullptr, 0);
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i++) g_tab_buf[i] = (uint8_t)(masked[i] ^ hy_mask_next(&st));
    int n = atoi(argv[4]);
    uint8_t pt[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    uint8_t ct[16];
    enc_once(pt, ct, HY_ENV);                       // warm-up (pays the unmask's caches)
    printf("ct:");
    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("\n");
    double best = 1e9;
    for (int rep = 0; rep < 5; rep++) {
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < n; i++) { pt[0] = (uint8_t)i; enc_once(pt, ct, HY_ENV); }
        auto t1 = std::chrono::steady_clock::now();
        double us = std::chrono::duration<double, std::micro>(t1 - t0).count() / n;
        if (us < best) best = us;
    }
    printf("best of 5 over %d blocks: %.2f us/block\n", n, best);
    return 0;
}
