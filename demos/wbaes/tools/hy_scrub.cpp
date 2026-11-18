// hy_scrub.cpp — export-time re-encoding of the S-box-shaped tables.
//
// The problem
// -----------
// A 256-entry table whose values are  gmul(SBox(x ^ k), c)  composed with a
// random per-lane bijection is still structurally an AES S-box row: every one of
// its 255 derivatives is exactly 4-to-1. A 40-line detector finds each one
// (tools/m1_detect.py --table-classifier). Nothing about the key leaks from
// that, but it tells the attacker "this is AES, these are the S-box rows, start
// the key-recovery here".
//
// What this does
// --------------
// For every 256-entry table that is structurally an S-box row, the export step
// rewrites it as
//
//     T'(x) = A( T(x) )
//
// with A an invertible affine map on GF(2)^8 (8x8 GF(2) matrix + constant), fresh
// per build and per (table, output row), derived from the build seed.
//
// That needs no runtime change: A is applied to the *value*, so every reader is
// unaffected. What consumes those values — the 64K pair-decode tables — is
// re-indexed instead:
//
//         Q'(A(u), A(v)) = Q(u, v)
//
// which is a permutation of the 64K table's entries. Net cost in the shipped
// artifact: 0 bytes, 0 ops per block. The work happens once here, over the
// 69 MB blob, before it is embedded (0.7 s).
//
// An *index* permutation T'(x) = A(T(pi(x))) would be the only build-time
// transform that clears the differential-uniformity signature, and it is NOT
// free: the reader picks exactly one position per logical index (scatter8(x)),
// so permuting the index changes the function. Absorbing pi would need a matching
// change in hy_mc_round(), i.e. in wbaes_hybrid.inc, which this export pass does
// not own. Measured attempt: it broke 13 of 18 rounds; --index-perm is refused.
//
// So what does A buy? Not the signature: for an affine A, A(x) ^ A(x^a) = M*a is
// constant, so every derivative of A o T is the same map as T's, and differential
// uniformity — what the classifier measures — is invariant under any bijective
// re-encoding on either side. Measured: no table in this artifact is 4-uniform in
// the first place (the generator's random input/output bijections take peak DD to
// 10..12), so an affine-only variant scores exactly the same, and an
// attacker holding the table recovers A in 256 lookups. What it does buy is that
// two builds no longer share a single table value, which kills the "align two
// versions by matching a row" trick, and it costs nothing. The numbers are in
// reports/EXPORT-HARDENING.md; the report says plainly that this is a cheap
// no-op rather than a defence.
//
// What it does not do: the algebra is unchanged. T' is still a permutation of
// the same multiset, gmul(S(x),c) is still inside the 64K tables it feeds, and a
// reader who knows the layout can still peel it (attacks/residual/hs_attack.py
// still recovers the key from the rewritten blob). This removes a *name tag*,
// not the structure.
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
#include <string>
#include <vector>

#include <sys/sysctl.h>

// ---- per-build PRNG -------------------------------------------------------
static uint64_t g_rng;
static uint64_t mix64(uint64_t z) {
    z += 0x9E3779B97F4A7C15ull;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}
static uint64_t rnd() { g_rng = mix64(g_rng); return g_rng; }
static uint8_t rnd8() { return (uint8_t)(rnd() >> 24); }

// An invertible affine map on GF(2)^8: rows[i] is the image of bit i.
struct Affine {
    uint8_t rows[8];
    uint8_t c;
    uint8_t t[256];
    void build() { for (int x = 0; x < 256; x++) t[x] = apply_raw((uint8_t)x); }
    uint8_t apply_raw(uint8_t x) const {
        uint8_t r = c;
        for (int i = 0; i < 8; i++)
            if (x & (1u << i)) r ^= rows[i];
        return r;
    }
    uint8_t operator()(uint8_t x) const { return t[x]; }
};

static int gf2_rank(uint8_t m[8]) {
    uint8_t a[8];
    memcpy(a, m, 8);
    int rank = 0;
    for (int bit = 0; bit < 8; bit++) {
        int piv = -1;
        for (int r = rank; r < 8; r++)
            if (a[r] & (1u << bit)) { piv = r; break; }
        if (piv < 0) continue;
        uint8_t tmp = a[rank]; a[rank] = a[piv]; a[piv] = tmp;
        for (int r = 0; r < 8; r++)
            if (r != rank && (a[r] & (1u << bit))) a[r] ^= a[rank];
        rank++;
    }
    return rank;
}

static void rand_affine(Affine &A) {
    do {
        for (int i = 0; i < 8; i++) A.rows[i] = rnd8();
    } while (gf2_rank(A.rows) != 8);
    A.c = rnd8();
    A.build();
}

// ---- layout helpers ------------------------------------------------------
// Which family each (dir, round) uses is data in the table, not in the reader,
// so it is read here exactly as hy_mc_round() reads it.
static int fam_at(const uint8_t *tab, int dir, int round) {
    return tab[HY_SCHED_OFF + (uint32_t)dir * HY_SCHED_STRIDE + (uint32_t)round];
}

struct Stats {
    uint64_t t8_tables = 0, t32_tables = 0, q_tables = 0, pair_tables = 0;
    uint64_t tables_touched = 0, q_entries = 0;
};

// Re-index one 64K decode table: Q'(A0(u), A1(v)) = Q(u, v).
// The table is addressed through hy_scatter(16-bit logical, env, tag).
static void reindex_q(uint8_t *tab, uint32_t off, uint32_t env, uint32_t tag,
                      const Affine &A0, const Affine &A1, Stats &st) {
    static std::vector<uint8_t> src;
    src.resize(HY_N);
    memcpy(src.data(), tab + off, HY_N);
    for (int u = 0; u < 256; u++) {
        const uint16_t nu = (uint16_t)A0((uint8_t)u);
        for (int v = 0; v < 256; v++) {
            const uint16_t nv = (uint16_t)A1((uint8_t)v);
            uint16_t old_logical = (uint16_t)(u | (v << 8));
            uint16_t new_logical = (uint16_t)(nu | (nv << 8));
            tab[off + hy_scatter(new_logical, env, tag)] =
                src[hy_scatter(old_logical, env, tag)];
        }
    }
    st.q_entries += HY_N;
}

// Re-encode one 256-entry byte table: T'(x) = A0(T(x)).
static void reencode8(uint8_t *tab, uint32_t off, uint32_t env, uint32_t tag,
                      const Affine &A0) {
    uint8_t src[256];
    for (int x = 0; x < 256; x++) src[x] = tab[off + hy_scatter8((uint8_t)x, env, tag)];
    for (int x = 0; x < 256; x++)
        tab[off + hy_scatter8((uint8_t)x, env, tag)] = A0(src[x]);
}

// Re-encode one 256-entry 32-bit table: byte row r becomes Ar(T_r(x)).
static void reencode32(uint8_t *tab, uint32_t off, uint32_t env, uint32_t tag,
                       const Affine A[4]) {
    uint8_t src[256][4];
    for (int x = 0; x < 256; x++) {
        const uint8_t *p = tab + off + (uint32_t)hy_scatter8((uint8_t)x, env, tag) * 4u;
        for (int r = 0; r < 4; r++) src[x][r] = p[r];
    }
    for (int x = 0; x < 256; x++) {
        uint8_t *p = tab + off + (uint32_t)hy_scatter8((uint8_t)x, env, tag) * 4u;
        for (int r = 0; r < 4; r++) p[r] = A[r](src[x][r]);
    }
}

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
                            "(hy_mc_round) is not this pass's to change. See the header "
                            "comment; measured: 13/18 rounds wrong.\n");
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

    // seed -> PRNG state
    {
        uint64_t h = 0xcbf29ce484222325ull;
        for (const char *p = seed; *p; p++) { h ^= (uint8_t)*p; h *= 0x100000001b3ull; }
        g_rng = mix64(h);
    }

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
    // Sanity: the schedule block carries a per-direction check byte, so a wrong
    // env or wrong seed fragments are caught here instead of producing a table
    // that silently computes a different function.
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
            if (g[r] > 3) { fprintf(stderr, "bad family byte %u at dir %u round %d\n", g[r], d, r); return 4; }
    }

    Stats st;
    uint8_t *tab = buf.data();
    for (int dir = 0; dir < 2; dir++) {
        for (int round = 0; round < HY_MC_ROUNDS; round++) {
            const int fam = fam_at(tab, dir, round);
            for (int col = 0; col < 4; col++) {
                const uint32_t cb = dir == 0 ? hy_enc_col(round, col)
                                             : hy_dec_mc(round) + (uint32_t)col * HY_COL;
                if (fam == HY_FAM_PAIR) {
                    // 16-bit-indexed pair tables: not a 256-entry S-box row.
                    st.pair_tables += 2 + 4;
                    continue;
                }
                // One affine per (k, row): 16 per column slot.
                Affine laneA[4][4];
                for (int k = 0; k < 4; k++)
                    for (int row = 0; row < 4; row++) rand_affine(laneA[k][row]);
                if (fam == HY_FAM_T8) {
                    for (int k = 0; k < 4; k++)
                        for (int row = 0; row < 4; row++) {
                            const uint32_t off = cb + (uint32_t)(k * 4 + row) * HY_W256;
                            const uint32_t tag = hy_tag(dir, round, col, HY_K_T8_C + k * 4 + row);
                            reencode8(tab, off, env, tag, laneA[k][row]);
                            st.t8_tables++;
                        }
                } else {
                    const int kw = (fam == HY_FAM_T32K) ? HY_K_T32K_W : HY_K_T32_W;
                    for (int k = 0; k < 4; k++) {
                        const uint32_t off = cb + (uint32_t)k * HY_W1024;
                        const uint32_t tag = hy_tag(dir, round, col, kw + k);
                        reencode32(tab, off, env, tag, laneA[k]);
                        st.t32_tables++;
                    }
                }
                // The 64K decode tables consume the lane values: absorb A there.
                const int qb = fam == HY_FAM_T8 ? HY_K_T8_Q
                               : fam == HY_FAM_T32K ? HY_K_T32K_Q : HY_K_T32_Q;
                for (int row = 0; row < 4; row++) {
                    for (int p = 0; p < 2; p++) {
                        const uint32_t tag = hy_tag(dir, round, col, qb + 2 * row + p);
                        reindex_q(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + p) * HY_N, env, tag,
                                  laneA[2 * p][row], laneA[2 * p + 1][row], st);
                        st.q_tables++;
                    }
                }
            }
        }
    }
    st.tables_touched = st.t8_tables + st.t32_tables;

    // Hashes the loader checks: the two over the masked file are computed after
    // re-masking below; this one is over the unmasked image, and it is what
    // proves the mask stream and the seed fragments agree.
    uint32_t h1 = 2166136261u, h4096 = 2166136261u, h4096p = 2166136261u;
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
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i++) { h1 ^= buf[i]; h1 *= 16777619u; }
    for (uint32_t i = 0; i < HY_TABLE_BYTES; i += 4096) { h4096 ^= buf[i]; h4096 *= 16777619u; }
    fprintf(stderr, "wrote %s (%u bytes)\n", out_path, HY_TABLE_BYTES);

    // Machine-readable summary for the export driver.
    printf("{\n");
    printf("  \"env\": %u,\n", env);
    printf("  \"t8_tables\": %llu,\n", (unsigned long long)st.t8_tables);
    printf("  \"t32_tables\": %llu,\n", (unsigned long long)st.t32_tables);
    printf("  \"q_tables\": %llu,\n", (unsigned long long)st.q_tables);
    printf("  \"q_entries\": %llu,\n", (unsigned long long)st.q_entries);
    printf("  \"pair_tables_untouched\": %llu,\n", (unsigned long long)st.pair_tables);
    printf("  \"tables_reenencoded\": %llu,\n", (unsigned long long)st.tables_touched);
    printf("  \"bytes_changed\": \"lane 256B tables + %llu B of 64K decode tables\",\n",
           (unsigned long long)st.q_entries);
    printf("  \"seal\": %u,\n", h1);
    printf("  \"seal_s4096\": %u,\n", h4096);
    printf("  \"seal_s4096_p\": %u\n", h4096p);
    printf("}\n");
    if (stats_path) {
        FILE *sf = fopen(stats_path, "w");
        if (sf) {
            fprintf(sf, "{\"env\": %u, \"t8_tables\": %llu, \"t32_tables\": %llu, "
                        "\"q_tables\": %llu, \"tables_reenencoded\": %llu, "
                        "\"seal\": %u, \"seal_s4096\": %u, \"seal_s4096_p\": %u, "
                        "}\n",
                    env, (unsigned long long)st.t8_tables, (unsigned long long)st.t32_tables,
                    (unsigned long long)st.q_tables, (unsigned long long)st.tables_touched,
                    h1, h4096, h4096p);
            fclose(sf);
        }
    }
    return 0;
}
