// hy_selftest.cpp — does the rewritten table compute the same round as the
// original one? Comparison is per (dir, round), so a bad family, a bad tag or a
// bad offset shows up as one failing line instead of a wrong ciphertext.
#include "wbaes_hybrid.h"
#include "hy_seal.h"
#include "hy_mask.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <sys/sysctl.h>

static std::vector<uint8_t> load_unmasked(const char *path, const uint32_t frags[4]) {
    std::vector<uint8_t> b(HY_TABLE_BYTES);
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    if (fread(b.data(), 1, HY_TABLE_BYTES, f) != HY_TABLE_BYTES) { fprintf(stderr, "short\n"); exit(2); }
    fclose(f);
    uint32_t st = frags[0] ^ frags[1] ^ frags[2] ^ frags[3];
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i++) b[i] ^= hy_mask_next(&st);
    return b;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s orig.bin new.bin\n", argv[0]); return 2; }
    uint32_t frags[4] = {HY_SEED_FRAG[0], HY_SEED_FRAG[1], HY_SEED_FRAG[2], HY_SEED_FRAG[3]};
    auto A = load_unmasked(argv[1], frags);
    auto B = load_unmasked(argv[2], frags);
    unsigned long long ps = 0, nc = 0, cl = 0;
    size_t n = sizeof(ps);
    sysctlbyname("hw.pagesize", &ps, &n, nullptr, 0);
    n = sizeof(nc); sysctlbyname("hw.ncpu", &nc, &n, nullptr, 0);
    n = sizeof(cl); sysctlbyname("hw.cachelinesize", &cl, &n, nullptr, 0);
    const uint32_t env = hy_env_mix((int)ps, (int)nc, (int)cl);
    printf("env=0x%08x\n", env);

    int bad = 0;
    for (int dir = 0; dir < 2; dir++) {
        for (int r = 0; r < HY_MC_ROUNDS; r++) {
            uint8_t in[16], o1[16], o2[16];
            for (int i = 0; i < 16; i++) in[i] = (uint8_t)(i * 37 + r * 11 + dir);
            if (dir == 0) {
                hy_mc_round(A.data(), hy_enc_col(r, 0), r, 0, 1, in, o1, env);
                hy_mc_round(B.data(), hy_enc_col(r, 0), r, 0, 1, in, o2, env);
            } else {
                hy_mc_round(A.data(), hy_dec_mc(r), r, 1, 0, in, o1, env);
                hy_mc_round(B.data(), hy_dec_mc(r), r, 1, 0, in, o2, env);
            }
            const int ok = memcmp(o1, o2, 16) == 0;
            if (!ok) bad++;
            printf("dir=%d round=%d fam=%d %s  ", dir, r,
                   A[HY_SCHED_OFF + dir * HY_SCHED_STRIDE + r], ok ? "OK" : "MISMATCH");
            if (!ok) {
                for (int i = 0; i < 16; i++) printf("%02x", o1[i]);
                printf(" != ");
                for (int i = 0; i < 16; i++) printf("%02x", o2[i]);
            }
            printf("\n");
        }
    }
    printf(bad ? "rounds differing: %d\n" : "all rounds identical\n", bad);
    return bad ? 1 : 0;
}
