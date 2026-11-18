// hy_scrub.cpp — export-time re-encoding of the S-box-shaped tables.
//
// What it did, and for which generations
// --------------------------------------
// In the eight-bit generations a 256-entry lane table whose values are
// gmul(SBox(x ^ k), c) composed with a random per-lane bijection is still
// structurally an AES S-box row: every one of its 255 derivatives is exactly
// 4-to-1, and a 40-line detector finds each one (tools/m1_detect.py). Nothing
// about the key leaks from that, but it tells the attacker "this is AES, these
// are the S-box rows, start the key-recovery here". For those artifacts this pass
// rewrote every such table as T'(x) = A(T(x)) with A an invertible affine map on
// GF(2)^8, fresh per build and per (table, output row), and absorbed the inverse
// into the 64K decode table it feeds: Q'(A(u), A(v)) = Q(u, v). Net cost in the
// shipped artifact: 0 bytes, 0 ops per block.
//
// The honest accounting for that transform is in reports/EXPORT-HARDENING.md:
// differential uniformity is invariant under a bijective re-encoding, an attacker
// holding the table recovers A in 256 lookups, and hs_attack.py still recovers the
// key from a rewritten blob (§5.27's residual attack). It removes a *name tag* —
// two builds no longer share a single table value — not the structure.
//
// Why this generation has no target
// ---------------------------------
// F4 (README 5.29) has no 256-entry lane tables at all. A column's front is four
// 2^16-entry tables of 16-bit values (the 16-bit partial sums), and its values are
// already carried through a per-build affine map on GF(2)^16 by the generator
// itself. There is no S-box row to re-encode and no 64K table keyed on a lane pair
// to re-index, so this pass has nothing to do: it verifies the artifact, writes it
// back byte-for-byte (still masked) and reports zero tables touched. The Mach-O
// and known-answer treatments in harden_export.py are unaffected and still apply.
// Saying "0 tables" here is the point — a silent identical copy would look like a
// successful scrub.
//
// Usage: hy_scrub in.bin out.bin <seed> [--pagesize N] [--ncpu N] [--cls N]
//                [--stats out.json]
#include "wbaes_hybrid.h"
#include "hy_seal.h"
#include "hy_mask.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>

#include <sys/sysctl.h>

// ---- main ---------------------------------------------------------------
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s in.bin out.bin <seed> "
                        "[--pagesize N] [--ncpu N] [--cls N] [--stats file.json]\n", argv[0]);
        return 2;
    }
    const char *in_path = argv[1], *out_path = argv[2];
    const char *seed = argv[3];
    const char *stats_path = nullptr;
    unsigned long long pagesize = 0, ncpu = 0, cls = 0;
    bool ov_ps = false, ov_nc = false, ov_cl = false;
    size_t nsz = sizeof(pagesize);
    sysctlbyname("hw.pagesize", &pagesize, &nsz, nullptr, 0);
    nsz = sizeof(ncpu);
    sysctlbyname("hw.ncpu", &ncpu, &nsz, nullptr, 0);
    nsz = sizeof(cls);
    sysctlbyname("hw.cachelinesize", &cls, &nsz, nullptr, 0);
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "--index-perm")) {
            fprintf(stderr, "refusing --index-perm: an index permutation changes the "
                            "function unless the reader applies it too, and the reader "
                            "(hy_mc_round) is not this pass's to change. Measured on the "
                            "eight-bit shape: 13/18 rounds wrong.\n");
            return 2;
        }
        else if (!strcmp(argv[i], "--pagesize")) { pagesize = strtoull(argv[++i], nullptr, 0); ov_ps = true; }
        else if (!strcmp(argv[i], "--ncpu")) { ncpu = strtoull(argv[++i], nullptr, 0); ov_nc = true; }
        else if (!strcmp(argv[i], "--cls")) { cls = strtoull(argv[++i], nullptr, 0); ov_cl = true; }
        else if (!strcmp(argv[i], "--stats")) stats_path = argv[++i];
        else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    if ((ov_ps && pagesize == 0) || (ov_nc && ncpu == 0) || (ov_cl && cls == 0)) {
        fprintf(stderr, "bad env value\n");
        return 2;
    }
    const uint32_t env = hy_env_mix((int)pagesize, (int)ncpu, (int)cls);
    fprintf(stderr, "env: pagesize=%llu ncpu=%llu cls=%llu -> 0x%08x\n",
            pagesize, ncpu, cls, env);

    std::vector<uint8_t> buf(HY_TABLE_BYTES);
    FILE *f = fopen(in_path, "rb");
    if (!f) { perror("open in"); return 3; }
    if (fread(buf.data(), 1, HY_TABLE_BYTES, f) != HY_TABLE_BYTES) {
        fprintf(stderr, "short read: expected %u bytes\n", HY_TABLE_BYTES);
        return 3;
    }
    fclose(f);

    // unmask, exactly as hy_table_unmask() does
    {
        uint32_t st = HY_SEED_FRAG[0] ^ HY_SEED_FRAG[1] ^ HY_SEED_FRAG[2] ^ HY_SEED_FRAG[3];
        for (uint32_t i = 0; i < HY_TABLE_BYTES; i++) buf[i] = (uint8_t)(buf[i] ^ hy_mask_next(&st));
    }
    // Sanity: the schedule block carries a per-direction check byte and, in this
    // generation, one family byte value. A wrong env or wrong seed fragments are
    // caught here instead of producing a table that silently computes a different
    // function.
    for (uint32_t d = 0; d < 2; d++) {
        const uint8_t *g = buf.data() + HY_SCHED_OFF + d * HY_SCHED_STRIDE;
        uint8_t x = (uint8_t)d;
        for (int r = 0; r < HY_MC_ROUNDS; r++) x ^= g[r];
        if (g[HY_MC_ROUNDS] != x) {
            fprintf(stderr, "unmask check failed (dir %u): env/seed fragments do not match "
                            "this table; refusing to rewrite\n", d);
            return 4;
        }
        for (int r = 0; r < HY_MC_ROUNDS; r++)
            if (g[r] != HY_FAM_W16) {
                fprintf(stderr, "unexpected family byte %u at dir %u round %d: this pass "
                                "only describes the F4 layout\n", g[r], d, r);
                return 4;
            }
    }

    // Nothing in an F4 artifact is a 256-entry S-box-shaped lane table, so the
    // re-encoding this pass exists for has no target. Say so, then write the same
    // bytes back (re-masked, never plain).
    fprintf(stderr, "F4 layout: the column front is four 2^16-entry pair tables of 16-bit "
                    "values, not 256-entry S-box rows; nothing for this pass to re-encode\n");

    uint32_t h4096p = 2166136261u;
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i += 4096) { h4096p ^= buf[i]; h4096p *= 16777619u; }

    // re-mask with the same stream
    {
        uint32_t s2 = HY_SEED_FRAG[0] ^ HY_SEED_FRAG[1] ^ HY_SEED_FRAG[2] ^ HY_SEED_FRAG[3];
        for (uint32_t i = 0; i < HY_TABLE_BYTES; i++) buf[i] = (uint8_t)(buf[i] ^ hy_mask_next(&s2));
    }
    f = fopen(out_path, "wb");
    if (!f) { perror("open out"); return 3; }
    if (fwrite(buf.data(), 1, HY_TABLE_BYTES, f) != HY_TABLE_BYTES) { fclose(f); return 3; }
    fclose(f);
    uint32_t h1 = 2166136261u, h4096 = 2166136261u;
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i++) { h1 ^= buf[i]; h1 *= 16777619u; }
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i += 4096) { h4096 ^= buf[i]; h4096 *= 16777619u; }
    fprintf(stderr, "wrote %s (%u bytes, unchanged)\n", out_path, HY_TABLE_BYTES);

    // Machine-readable summary for the export driver. Zero tables re-encoded is
    // the honest answer for this generation, and the driver reads it.
    printf("{\n");
    printf("  \"env\": %u,\n", env);
    printf("  \"layout\": \"F4\",\n");
    printf("  \"t8_tables\": 0,\n");
    printf("  \"t32_tables\": 0,\n");
    printf("  \"q_tables\": 0,\n");
    printf("  \"q_entries\": 0,\n");
    printf("  \"pair_tables_untouched\": 0,\n");
    printf("  \"tables_reenencoded\": 0,\n");
    printf("  \"bytes_changed\": \"0 - F4 has no 256-entry S-box-shaped lane table\",\n");
    printf("  \"seal\": %u,\n", h1);
    printf("  \"seal_s4096\": %u,\n", h4096);
    printf("  \"seal_s4096_p\": %u\n", h4096p);
    printf("}\n");
    if (stats_path) {
        FILE *sf = fopen(stats_path, "w");
        if (sf) {
            fprintf(sf, "{\"env\": %u, \"layout\": \"F4\", \"t8_tables\": 0, \"t32_tables\": 0, "
                        "\"q_tables\": 0, \"tables_reenencoded\": 0, "
                        "\"seal\": %u, \"seal_s4096\": %u, \"seal_s4096_p\": %u, "
                        "}\n",
                    env, h1, h4096, h4096p);
            fclose(sf);
        }
    }
    return 0;
}
