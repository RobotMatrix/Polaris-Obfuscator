#!/usr/bin/env python3
"""Write the randomised runtime used by RANDOMISATION.md.

Reads a byte copy of the shipped header (demos/wbaes/wbaes_hybrid.h) and writes a
copy elsewhere -- never in place, the shipped file is input only. Two mechanical
edits, each with a unique anchor that is checked:

  1. a per-call xorshift state and hy_dummy_access(), inserted after the includes
     and after the load helpers it calls. HY_RND_K (dummy reads per round) and
     HY_RND_SHUFFLE come from the compiler command line, so one generated header
     serves every level.
  2. hy_mc_round() rewritten as three phases: column offsets and inputs, then the
     16 lane decodes in a per-call Fisher-Yates order, then per column the
     boundary decode and the recoding. Same reads, same tags, same values, same
     function; only the issue order and the extra dummy reads differ.
     HY_RND_K=0 HY_RND_SHUFFLE=0 gives the shipped order back.

usage: python3 rnd/patch_header.py --out /tmp/wbaes-rnd/demos/wbaes/wbaes_hybrid.h
"""
import argparse
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
SHIP = os.path.join(REPO, "demos", "wbaes", "wbaes_hybrid.h")

RNG_HEAD = r'''
// ---------------------------------------------------------------------------
// experiment: per-execution randomisation of the table-access stream.
//
// HY_RND_SHUFFLE: HY_MC_ROUND's 16 lane decodes are issued in the order of a
//   Fisher-Yates permutation drawn per call from hy_rnd_next(). The seed comes
//   from a per-call counter (see the caller), so every block gets its own
//   permutation. A fixed permutation would leave the order inferable from one
//   trace and would be worthless.
// HY_RND_K: HY_RND_K extra table reads per round (4 or 16), spread K/4 per
//   column. Each one copies the (offset, width) of a real access of that column
//   -- sampled uniformly from the column's access sites -- and draws a fresh
//   index inside that table, so a dummy is indistinguishable from a real access
//   by address, width or offset, and deduplicating equal addresses does not
//   remove it. The value is read and discarded: the function is unchanged.
// ---------------------------------------------------------------------------
#ifndef HY_RND_K
#define HY_RND_K 0
#endif
#ifndef HY_RND_SHUFFLE
#define HY_RND_SHUFFLE (HY_RND_K > 0)
#endif

inline uint32_t hy_rnd_state = 0x9E3779B9u;

inline void hy_rnd_seed(uint32_t s) { hy_rnd_state = s ? s : 0x1234567u; }
inline uint32_t hy_rnd_next() {
    uint32_t x = hy_rnd_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    hy_rnd_state = x;
    return x;
}
'''

DUMMY_HELPER = r'''
// One dummy read at a site of this column, with a fresh index. The site list per
// family is the set of reads hy_mc_round performs for that column, so sampling it
// uniformly reproduces the real width/offset distribution of the family.
inline void hy_dummy_access(const uint8_t *tab, int fam, uint32_t cb, const uint32_t *lk,
                            int dir, int round, int col, uint32_t env) {
    const uint32_t r = hy_rnd_next();
    const uint16_t i16 = (uint16_t)hy_rnd_next();
    const uint8_t i8 = (uint8_t)hy_rnd_next();
    if (fam == HY_FAM_PAIR) {
        const int s = (int)(r % 18u);            // 2 lane + 4 boundary + 12 recoding
        if (s < 2) {
            (void)hy_load32(tab, s ? lk[2] : lk[0], i16, env,
                            hy_tag(dir, round, col, HY_K_PAIR_L + s));
        } else if (s < 6) {
            const int row = s - 2;
            (void)hy_load8(tab, cb + HY_BDY_OFF + (uint32_t)row * HY_N, i16, env,
                           hy_tag(dir, round, col, HY_K_BDY_PAIR + row));
        } else {
            const int j = s - 6;
            (void)hy_load8t(tab, cb + HY_SPN_OFF + (uint32_t)j * HY_W256, i8, env,
                            hy_tag(dir, round, col, HY_K_SPN_S + j));
        }
        return;
    }
    if (fam == HY_FAM_T8) {
        const int s = (int)(r % 40u);            // 16 coeff + 8 Q + 4 boundary + 12 recoding
        if (s < 16) {
            const int k = s >> 2, row = s & 3;
            (void)hy_load8t(tab, lk[k] + (uint32_t)row * HY_W256, i8, env,
                            hy_tag(dir, round, col, HY_K_T8_C + k * 4 + row));
        } else if (s < 24) {
            const int row = (s - 16) >> 1, pair = (s - 16) & 1;
            (void)hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + pair) * HY_N, i16, env,
                           hy_tag(dir, round, col, HY_K_T8_Q + 2 * row + pair));
        } else if (s < 28) {
            const int row = s - 24;
            (void)hy_load8(tab, cb + HY_BDY_OFF + (uint32_t)row * HY_N, i16, env,
                           hy_tag(dir, round, col, HY_K_BDY_T8 + row));
        } else {
            const int j = s - 28;
            (void)hy_load8t(tab, cb + HY_SPN_OFF + (uint32_t)j * HY_W256, i8, env,
                            hy_tag(dir, round, col, HY_K_SPN_S + j));
        }
        return;
    }
    const int kw = (fam == HY_FAM_T32K) ? HY_K_T32K_W : HY_K_T32_W;
    const int qb = (fam == HY_FAM_T32K) ? HY_K_T32K_Q : HY_K_T32_Q;
    const int bk = (fam == HY_FAM_T32K) ? HY_K_BDY_T32K : HY_K_BDY_T32;
    const int s = (int)(r % 28u);                // 4 lane + 8 Q + 4 boundary + 12 recoding
    if (s < 4) {
        (void)hy_load32t(tab, lk[s], i8, env, hy_tag(dir, round, col, kw + s));
    } else if (s < 12) {
        const int row = (s - 4) >> 1, pair = (s - 4) & 1;
        (void)hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + pair) * HY_N, i16, env,
                       hy_tag(dir, round, col, qb + 2 * row + pair));
    } else if (s < 16) {
        const int row = s - 12;
        (void)hy_load8(tab, cb + HY_BDY_OFF + (uint32_t)row * HY_N, i16, env,
                       hy_tag(dir, round, col, bk + row));
    } else {
        const int j = s - 16;
        (void)hy_load8t(tab, cb + HY_SPN_OFF + (uint32_t)j * HY_W256, i8, env,
                        hy_tag(dir, round, col, HY_K_SPN_S + j));
    }
}
'''

MC_ROUND = r'''inline void hy_mc_round(const uint8_t *tab, uint32_t base, int round, int dir, int src_kind,
                        const uint8_t in[16], uint8_t out[16], uint32_t env,
                        const uint32_t *lane16 = nullptr) {
    const int fam = (int)tab[HY_SCHED_OFF + (uint32_t)dir * HY_SCHED_STRIDE + (uint32_t)round];
    // Per-column slot base, lane-table base per input row k, and the four input
    // bytes: the same numbers the shipped code computes inside the column loop,
    // hoisted so the lane decodes of all four columns can be issued in any order.
    uint32_t cbv[4], bdyv[4], lkv[4][4];
    uint8_t bv[4][4];
    for (int col = 0; col < 4; col++) {
        const uint32_t cb = lane16 ? lane16[4 * col] : base + (uint32_t)col * HY_COL;
        cbv[col] = cb;
        bdyv[col] = cb + HY_BDY_OFF;
        for (int k = 0; k < 4; k++)
            lkv[col][k] = lane16 ? lane16[4 * col + k]
                                 : (fam == HY_FAM_PAIR ? ((k >= 2) ? cb + HY_U32 : cb)
                                                       : cb + (uint32_t)k * HY_W1024);
        for (int k = 0; k < 4; k++) bv[col][k] = in[hy_pick(src_kind, k + 4 * col)];
    }

    // ---- phase 1: the 16 lane decodes, in a per-call shuffled order ----------
    uint32_t lw[4][4];
    uint8_t v8[4][4][4];
    uint32_t lp[4][2];
    int ord[16];
    for (int i = 0; i < 16; i++) ord[i] = i;
#if HY_RND_SHUFFLE
    for (int i = 15; i > 0; i--) {
        const int j = (int)(hy_rnd_next() % (uint32_t)(i + 1));
        const int t = ord[i]; ord[i] = ord[j]; ord[j] = t;
    }
#endif
    for (int t = 0; t < 16; t++) {
        const int col = ord[t] >> 2, k = ord[t] & 3;
        if (fam == HY_FAM_PAIR) {
            // F0 reads two 16-bit pairs per column, so slots k=1 and k=3 carry no
            // read of their own and are skipped.
            if (k == 0)
                lp[col][0] = hy_load32(tab, lkv[col][0], (uint16_t)(bv[col][0] | (bv[col][1] << 8)),
                                       env, hy_tag(dir, round, col, HY_K_PAIR_L));
            else if (k == 2)
                lp[col][1] = hy_load32(tab, lkv[col][2], (uint16_t)(bv[col][2] | (bv[col][3] << 8)),
                                       env, hy_tag(dir, round, col, HY_K_PAIR_L + 1));
        } else if (fam == HY_FAM_T8) {
            for (int row = 0; row < 4; row++)
                v8[col][k][row] = hy_load8t(tab, lkv[col][k] + (uint32_t)row * HY_W256,
                                            bv[col][k], env,
                                            hy_tag(dir, round, col, HY_K_T8_C + k * 4 + row));
        } else {
            const int kw = (fam == HY_FAM_T32K) ? HY_K_T32K_W : HY_K_T32_W;
            lw[col][k] = hy_load32t(tab, lkv[col][k], bv[col][k], env,
                                    hy_tag(dir, round, col, kw + k));
        }
    }

    // ---- dummy reads: HY_RND_K/4 per column, pinned to a row and a side -------
    // Half land before that row's boundary decode and half after, so a dummy
    // precedes the real access it imitates about half the time. Emitting them all
    // after the boundary block would make a first-hit reader (the one in
    // attacks/residual/reslib.py) immune by construction.
#if HY_RND_K > 0
    const int ndum = HY_RND_K / 4;
    int drow[4][HY_RND_K / 4], dcoin[4][HY_RND_K / 4];
    for (int col = 0; col < 4; col++)
        for (int d = 0; d < ndum; d++) {
            drow[col][d] = (int)(hy_rnd_next() & 3u);
            dcoin[col][d] = (int)(hy_rnd_next() & 1u);
        }
#define HY_DUMMY_EMIT(rowv, coinv)                                            \
    do {                                                                      \
        for (int _d = 0; _d < ndum; _d++)                                     \
            if (drow[col][_d] == (rowv) && dcoin[col][_d] == (coinv))         \
                hy_dummy_access(tab, fam, cb, lkv[col], dir, round, col, env); \
    } while (0)
#else
#define HY_DUMMY_EMIT(rowv, coinv) do { (void)(rowv); (void)(coinv); } while (0)
#endif

    // ---- phase 2: boundary decode + recoding, per column ---------------------
    for (int col = 0; col < 4; col++) {
        const uint32_t cb = cbv[col];
        const uint32_t bdy = bdyv[col];
        if (fam == HY_FAM_PAIR) {
            const uint32_t left = lp[col][0], right = lp[col][1];
            for (int row = 0; row < 4; row++) {
                HY_DUMMY_EMIT(row, 0);
                const uint8_t pl = (uint8_t)((left >> (8 * row)) & 255);
                const uint8_t pr = (uint8_t)((right >> (8 * row)) & 255);
                out[row + 4 * col] = hy_load8(tab, bdy + (uint32_t)row * HY_N,
                                              (uint16_t)(pl | (pr << 8)), env,
                                              hy_tag(dir, round, col, HY_K_BDY_PAIR + row));
                HY_DUMMY_EMIT(row, 1);
            }
        } else if (fam == HY_FAM_T8) {
            for (int row = 0; row < 4; row++) {
                HY_DUMMY_EMIT(row, 0);
                const uint8_t pl = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row) * HY_N,
                                            (uint16_t)(v8[col][0][row] | (v8[col][1][row] << 8)), env,
                                            hy_tag(dir, round, col, HY_K_T8_Q + 2 * row));
                const uint8_t pr = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + 1) * HY_N,
                                            (uint16_t)(v8[col][2][row] | (v8[col][3][row] << 8)), env,
                                            hy_tag(dir, round, col, HY_K_T8_Q + 2 * row + 1));
                out[row + 4 * col] = hy_load8(tab, bdy + (uint32_t)row * HY_N,
                                              (uint16_t)(pl | (pr << 8)), env,
                                              hy_tag(dir, round, col, HY_K_BDY_T8 + row));
                HY_DUMMY_EMIT(row, 1);
            }
        } else {
            const int qb = (fam == HY_FAM_T32K) ? HY_K_T32K_Q : HY_K_T32_Q;
            const int bk = (fam == HY_FAM_T32K) ? HY_K_BDY_T32K : HY_K_BDY_T32;
            for (int row = 0; row < 4; row++) {
                HY_DUMMY_EMIT(row, 0);
                const uint8_t a0 = (uint8_t)(lw[col][0] >> (8 * row)), a1 = (uint8_t)(lw[col][1] >> (8 * row));
                const uint8_t a2 = (uint8_t)(lw[col][2] >> (8 * row)), a3 = (uint8_t)(lw[col][3] >> (8 * row));
                const uint8_t pl = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row) * HY_N,
                                            (uint16_t)(a0 | (a1 << 8)), env,
                                            hy_tag(dir, round, col, qb + 2 * row));
                const uint8_t pr = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + 1) * HY_N,
                                            (uint16_t)(a2 | (a3 << 8)), env,
                                            hy_tag(dir, round, col, qb + 2 * row + 1));
                out[row + 4 * col] = hy_load8(tab, bdy + (uint32_t)row * HY_N,
                                              (uint16_t)(pl | (pr << 8)), env,
                                              hy_tag(dir, round, col, bk + row));
                HY_DUMMY_EMIT(row, 1);
            }
        }
        // Cross-lane nonlinear recoding: the four output bytes of the column are a
        // 32-bit word and they leave the round SPN-encoded.
        uint8_t y[4];
        for (int j = 0; j < 4; j++) y[j] = out[4 * col + j];
        hy_spn_fwd(tab, cb, dir, round, col, y, env);
        for (int j = 0; j < 4; j++) out[4 * col + j] = y[j];
    }
}
#undef HY_DUMMY_EMIT
'''


def build(ship_text):
    out = ship_text
    anchor = "#include <cstring>\n"
    if out.count(anchor) != 1:
        raise SystemExit("include anchor not unique")
    out = out.replace(anchor, anchor + RNG_HEAD)
    anchor2 = "\n// ---- the 32-bit nonlinear recoding ---"
    if out.count(anchor2) != 1:
        raise SystemExit("recoding anchor not unique")
    out = out.replace(anchor2, "\n" + DUMMY_HELPER + anchor2)
    a = out.index("inline void hy_mc_round(const uint8_t *tab, uint32_t base, int round, int dir,")
    b = out.index("\n// wiring: 0 ", a)
    old = out[a:b]
    if old.count("hy_spn_fwd") != 1 or old.count("HY_K_BDY_T8") != 1:
        raise SystemExit("hy_mc_round slice looks wrong")
    return out[:a] + MC_ROUND + out[b:]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ship", default=SHIP, help="shipped header (read only)")
    ap.add_argument("--out", required=True, help="where to write the randomised copy")
    a = ap.parse_args(argv)
    src = open(a.ship).read()
    dst = build(src)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    open(a.out, "w").write(dst)
    print("%s -> %s (%d -> %d bytes)" % (a.ship, a.out, len(src), len(dst)))


if __name__ == "__main__":
    main()
