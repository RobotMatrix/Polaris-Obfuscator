// bench_wbaes.cpp — per-block cost of the baked white-box path.
//
// Includes the demo translation unit with its main() disabled, so the code under
// the clock is exactly the shipped encrypt/decrypt path (nothing is re-implemented
// here). Reported numbers are the best of five runs, after one warm-up call that
// also pays the one-time table unmask and the full-table seal.
//
//   bench_wbaes <iterations>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

#define WBAES_NO_MAIN
#include "demo_wbaes.cpp"

static double now_s() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static volatile unsigned g_sink;

int main(int argc, char **argv) {
    const int n = argc > 1 ? atoi(argv[1]) : 2000;
    WBAES wb;
    wb.init();
    uint8_t ct[16], pt[16], rt[16];
    wb.encrypt(wbaes_key::test_pt, ct);  // warm-up: unmask + full-table seal
    wb.decrypt(ct, rt);
    if (memcmp(rt, wbaes_key::test_pt, 16) != 0) {
        printf("roundtrip warm-up: FAIL\n");
        return 1;
    }
    double best_e = 1e9, best_d = 1e9;
    for (int rep = 0; rep < 5; rep++) {
        double t0 = now_s();
        for (int i = 0; i < n; i++) {
            memcpy(pt, wbaes_key::test_pt, 16);
            pt[15] ^= (uint8_t)i;  // vary the input so nothing folds
            wb.encrypt(pt, ct);
            g_sink ^= ct[0];
        }
        double t1 = now_s();
        for (int i = 0; i < n; i++) {
            wb.decrypt(ct, rt);
            g_sink ^= rt[0];
        }
        double t2 = now_s();
        if ((t1 - t0) / n < best_e) best_e = (t1 - t0) / n;
        if ((t2 - t1) / n < best_d) best_d = (t2 - t1) / n;
    }
    wb.encrypt(wbaes_key::test_pt, ct);
    const bool vec = memcmp(ct, wbaes_key::test_ct, 16) == 0;
    printf("blocks    : %d\n", n);
    printf("encrypt   : %.2f us/block\n", best_e * 1e6);
    printf("decrypt   : %.2f us/block\n", best_d * 1e6);
    printf("vector-match: %s\n", vec ? "PASS" : "FAIL");
    return vec ? 0 : 1;
}
