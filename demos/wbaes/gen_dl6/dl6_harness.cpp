// Trace harness for the wbaes table network: builds a trace-enabled copy of the
// runtime in a scratch directory (demos/wbaes itself is never modified) and runs it
// over the *shipped* artifact's table section.
//
// It unmasks the table exactly as wbaes_hybrid.inc does on first call, loads the
// round-0 input bijection from the binary, then logs every table access as
// (table offset, pre-scatter logical index, access width). The ciphertext it prints
// must equal the artifact's, which is what makes the traces evidence.
//
// usage: harness <table_masked.bin> <p0.bin> <seed-hex> <n_traces> <out_prefix>
//   writes <prefix>_traces.bin and <prefix>_pts.bin, and <prefix>_table_plain.bin
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

// ---- trace log --------------------------------------------------------------
struct Tr { uint32_t addr; uint32_t logical; uint32_t width; };
static std::vector<Tr> g_tr;
static inline void hy_trace_push(uint32_t a, uint32_t l, uint32_t w) { g_tr.push_back({a, l, w}); }
#define HY_TRACE(a, l, w) hy_trace_push((uint32_t)(a), (uint32_t)(l), (uint32_t)(w))

#define HY_TABLE_BYTES 70103104u // HY_TOTAL from wbaes_hybrid_dl6.h
static uint8_t g_tab_buf[HY_TABLE_BYTES];
static const uint8_t *hy_tab_ptr = g_tab_buf;
#define HYKTAB hy_tab_ptr

#include "hy_trace.h" // copy of demos/wbaes/wbaes_hybrid.h with the HY_TRACE hooks

static unsigned char HY_P0[16][256];

static uint8_t hy_mask_next(uint32_t *s) {
    uint32_t x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; *s = x;
    return (uint8_t)(x >> 24);
}

// same structure as hy_encrypt_once() in wbaes_hybrid.inc, plus the dl6 key layer
static void enc_once(const uint8_t in[16], uint8_t out[16], uint32_t env) {
    uint8_t s[16], n[16];
    for (int i = 0; i < 16; i++) s[i] = HY_P0[i][in[i]];
    for (int r = 0; r < HY_MC_ROUNDS; r++) {
        // mirror hy_encrypt_once: undo the previous round's 32-bit recoding first
        if (r) hy_rec_undo(HYKTAB, hy_enc_col(r - 1, 0), 0, r - 1, s, env);
        if (r == 1) hy_rkz_apply(HYKTAB, s, env);   // dl6: rk0 on the output side
        hy_mc_round(HYKTAB, hy_enc_col(r, 0), r, 0, 1, s, n, env);
        for (int i = 0; i < 16; i++) s[i] = n[i];
    }
    hy_rec_undo(HYKTAB, hy_enc_col(HY_MC_ROUNDS - 1, 0), 0, HY_MC_ROUNDS - 1, s, env);
    hy_pair_map(HYKTAB, hy_enc_final(), s, out, env, 0, 9, 1);
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: harness <tab> <p0> <seed> <n> <prefix>\n"); return 2; }
    const char *tabf = argv[1], *p0f = argv[2];
    uint32_t seed = (uint32_t)strtoul(argv[3], nullptr, 0);
    int n = atoi(argv[4]);
    const char *pref = argv[5];

    FILE *f = fopen(tabf, "rb");
    if (!f) return 3;
    uint8_t *masked = (uint8_t *)malloc(HY_TABLE_BYTES);
    if (!masked || fread(masked, 1, HY_TABLE_BYTES, f) != HY_TABLE_BYTES) return 4;
    fclose(f);
    f = fopen(p0f, "rb");
    if (!f) return 3;
    if (fread(HY_P0, 1, sizeof(HY_P0), f) != sizeof(HY_P0)) return 4;
    fclose(f);

    uint32_t st = seed;
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i++) g_tab_buf[i] = (uint8_t)(masked[i] ^ hy_mask_next(&st));
    free(masked);

    printf("sched enc:");
    for (int r = 0; r < HY_MC_ROUNDS; r++) printf(" %d", g_tab_buf[HY_SCHED_OFF + r]);
    printf("\nsched dec:");
    for (int r = 0; r < HY_MC_ROUNDS; r++) printf(" %d", g_tab_buf[HY_SCHED_OFF + HY_SCHED_STRIDE + r]);
    printf("\n");

    char path[512];
    snprintf(path, sizeof(path), "%s_table_plain.bin", pref);
    f = fopen(path, "wb");
    if (!f) return 5;
    fwrite(g_tab_buf, 1, HY_TABLE_BYTES, f);
    fclose(f);

    uint8_t testpt[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    uint8_t ct[16];
    g_tr.clear();
    enc_once(testpt, ct, HY_ENV);
    printf("ct:");
    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("\naccesses/block: %zu\n", g_tr.size());

    snprintf(path, sizeof(path), "%s_traces.bin", pref);
    FILE *tf = fopen(path, "wb");
    snprintf(path, sizeof(path), "%s_pts.bin", pref);
    FILE *pf = fopen(path, "wb");
    if (!tf || !pf) return 6;
    uint32_t rng = 0x12345678u;
    for (int t = 0; t < n; t++) {
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; pt[i] = (uint8_t)(rng >> 16); }
        fwrite(pt, 1, 16, pf);
        g_tr.clear();
        enc_once(pt, ct, HY_ENV);
        uint32_t cnt = (uint32_t)g_tr.size();
        fwrite(&cnt, 4, 1, tf);
        fwrite(g_tr.data(), sizeof(Tr), cnt, tf);
    }
    fclose(tf);
    fclose(pf);
    printf("wrote %d traces\n", n);
    return 0;
}
