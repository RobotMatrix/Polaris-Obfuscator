// Trace harness for the randomisation experiment.
//
// Same job as attacks/trace_harness/harness.cpp: unmask the shipped table, run the
// reference encryption loop over it, and record (address, logical index, width)
// for every table access. Three additions:
//
//   * hy_rnd_seed() is called at the top of every block from a counter, so the
//     lane-decode permutation (and the dummy sites) differ per call;
//   * the seed and the counter are written to <prefix>_seeds.bin, so the
//     permutation of every recorded trace is reproducible;
//   * <prefix>_ct.bin holds all n ciphertexts, so the function can be compared
//     byte for byte against the shipped build;
//   * a second timed pass with the recorder switched off, so the per-block cost
//     is not the cost of the trace logger.
//
// usage: harness_rnd <table_plain.bin> <p0.bin> <n> <seed_base> <prefix>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <chrono>

// ---- trace log --------------------------------------------------------------
struct Tr { uint32_t addr; uint32_t logical; uint32_t width; };
static std::vector<Tr> g_tr;
static int g_record = 1;
static inline void hy_trace_push(uint32_t a, uint32_t l, uint32_t w) {
    if (g_record) g_tr.push_back({a, l, w});
}
#define HY_TRACE(a, l, w) hy_trace_push((uint32_t)(a), (uint32_t)(l), (uint32_t)(w))

#define HY_TABLE_BYTES 70090816u // HY_TOTAL from wbaes_hybrid.h (dl5 layout)
static uint8_t g_tab_buf[HY_TABLE_BYTES];
static const uint8_t *hy_tab_ptr = g_tab_buf;
#define HYKTAB hy_tab_ptr

#include "hy_trace.h" // copy of the randomised header with the HY_TRACE hooks

static unsigned char HY_P0[16][256];

static uint8_t hy_mask_next(uint32_t *s) {
    uint32_t x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; *s = x;
    return (uint8_t)(x >> 24);
}

// same structure as hy_encrypt_once() in wbaes_hybrid.inc, minus the DFA second pass
static void enc_once(const uint8_t in[16], uint8_t out[16], uint32_t env, uint32_t rnd_seed) {
    hy_rnd_seed(rnd_seed);
    uint8_t s[16], n[16];
    for (int i = 0; i < 16; i++) s[i] = HY_P0[i][in[i]];
    for (int r = 0; r < HY_MC_ROUNDS; r++) {
        if (r) hy_rec_undo(HYKTAB, hy_enc_col(r - 1, 0), 0, r - 1, s, env);
        hy_mc_round(HYKTAB, hy_enc_col(r, 0), r, 0, 1, s, n, env);
        for (int i = 0; i < 16; i++) s[i] = n[i];
    }
    hy_rec_undo(HYKTAB, hy_enc_col(HY_MC_ROUNDS - 1, 0), 0, HY_MC_ROUNDS - 1, s, env);
    hy_pair_map(HYKTAB, hy_enc_final(), s, out, env, 0, 9, 1);
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: harness_rnd <tab_plain> <p0> <n> <seed_base> <prefix>\n"); return 2; }
    const char *tabf = argv[1], *p0f = argv[2];
    int n = atoi(argv[3]);
    uint32_t seed_base = (uint32_t)strtoul(argv[4], nullptr, 0);
    const char *pref = argv[5];

    FILE *f = fopen(tabf, "rb");
    if (!f) return 3;
    if (fread(g_tab_buf, 1, HY_TABLE_BYTES, f) != HY_TABLE_BYTES) return 4;
    fclose(f);
    f = fopen(p0f, "rb");
    if (!f) return 3;
    if (fread(HY_P0, 1, sizeof(HY_P0), f) != sizeof(HY_P0)) return 4;
    fclose(f);

    uint8_t testpt[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    uint8_t ct[16];
    g_tr.clear();
    enc_once(testpt, ct, HY_ENV, 0x11111111u);
    printf("sched enc:");
    for (int r = 0; r < HY_MC_ROUNDS; r++) printf(" %d", g_tab_buf[HY_SCHED_OFF + r]);
    printf("\nct:");
    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("\naccesses/block: %zu\n", g_tr.size());

    std::vector<uint8_t> pts((size_t)n * 16), cts((size_t)n * 16);
    std::vector<uint32_t> seeds((size_t)n);
    uint32_t rng = 0x12345678u; // same plaintext stream as the shipped harness
    for (int t = 0; t < n; t++)
        for (int i = 0; i < 16; i++) {
            rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
            pts[(size_t)t * 16 + i] = (uint8_t)(rng >> 16);
        }
    for (int t = 0; t < n; t++)
        seeds[t] = seed_base ^ ((uint32_t)(t + 1) * 0x9E3779B1u) ^ 0xA5C31E87u;

    // pass 1: records nothing, only times the block
    g_record = 0;
    for (int t = 0; t < n; t++) enc_once(&pts[(size_t)t * 16], &cts[(size_t)t * 16], HY_ENV, seeds[t]);
    std::vector<double> ms((size_t)n);
    unsigned long sink = 0;
    for (int t = 0; t < n; t++) {
        auto t0 = std::chrono::steady_clock::now();
        for (int rep = 0; rep < 4; rep++) {
            uint8_t o[16];
            enc_once(&pts[(size_t)t * 16], o, HY_ENV, seeds[t] + (uint32_t)rep);
            sink += o[0] + o[15];              // keeps the call from being hoisted
        }
        auto t1 = std::chrono::steady_clock::now();
        ms[t] = std::chrono::duration<double, std::milli>(t1 - t0).count() / 4.0;
    }
    printf("sink %lu\n", sink);
    std::sort(ms.begin(), ms.end());
    double mean = 0;
    for (int t = 0; t < n; t++) mean += ms[t];
    mean /= n;
    printf("timing: mean %.4f ms  median %.4f ms  min %.4f ms  max %.4f ms  (n=%d, 4 reps each)\n",
           mean, ms[n / 2], ms[0], ms[n - 1], n);

    // pass 2: record
    g_record = 1;
    g_tr.reserve(2048);
    char path[512];
    snprintf(path, sizeof(path), "%s_traces.bin", pref);
    FILE *tf = fopen(path, "wb");
    if (!tf) return 6;
    for (int t = 0; t < n; t++) {
        g_tr.clear();
        enc_once(&pts[(size_t)t * 16], &cts[(size_t)t * 16], HY_ENV, seeds[t]);
        uint32_t cnt = (uint32_t)g_tr.size();
        fwrite(&cnt, 4, 1, tf);
        fwrite(g_tr.data(), sizeof(Tr), cnt, tf);
    }
    fclose(tf);
    snprintf(path, sizeof(path), "%s_pts.bin", pref);
    tf = fopen(path, "wb"); fwrite(pts.data(), 1, pts.size(), tf); fclose(tf);
    snprintf(path, sizeof(path), "%s_ct.bin", pref);
    tf = fopen(path, "wb"); fwrite(cts.data(), 1, cts.size(), tf); fclose(tf);
    snprintf(path, sizeof(path), "%s_seeds.bin", pref);
    tf = fopen(path, "wb"); fwrite(seeds.data(), 4, seeds.size(), tf); fclose(tf);
    printf("wrote %d traces (+ pts, ct, seeds)\n", n);
    return 0;
}
