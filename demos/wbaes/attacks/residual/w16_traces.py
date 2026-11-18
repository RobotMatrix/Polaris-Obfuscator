#!/usr/bin/env python3
"""What the address traces leak about a 16-bit-combine (F4) artifact.

The four address-side attacks in this repository (E4c-A the single-byte CPA on the
round-0 lane table, E4c-B the boundary-index MITM, and the two residual trace
attacks) all ask one question: is there a table whose *index* is a function of one
key byte composed with a public, invertible map of the plaintext? This script
measures that for the F4 shape, straight off a trace file:

  1. the index of every round-0 pair table. F4's pair tables are indexed by two
     bytes of P0(pt): recoverable, but key-free. Measured against P0.
  2. the index of every round-0 decode table. This is the F4 analogue of dl5's
     64K boundary index: the 16-bit XOR of two pair-table values. Measured by
     *recomputing* it from the artifact's own bytes, and by counting how many
     distinct values 64 traces produce: an index with 2^16 values cannot be
     predicted by a 256-hypothesis-per-byte correlation.

usage: python3 w16_traces.py --table hy_table.bin --work . --traces dl4_traces.bin
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import wblib as wb
import res16 as W


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--table", required=True)
    ap.add_argument("--work", default=".")
    ap.add_argument("--traces", required=True)
    a = ap.parse_args(argv)

    art, seed, secs = W.load(a.table, a.work)
    traces, pts = wb.read_traces(a.traces)
    print("artifact: %s, mask seed 0x%08x, unmasked in %.1fs"
          % (os.path.basename(a.table), seed, secs))
    print("traces  : %d x %d accesses" % (len(traces), len(traces[0])))

    # ---- 1. pair-table indices versus the public round-0 bijection ----------
    print("\n== 1. round-0 pair tables: is the index a function of the key? ==")
    print("   col k  traces  index == P0(pt_a)|P0(pt_b)<<8  distinct indices")
    okall = 0
    tot = 0
    for col in range(4):
        for k in range(4):
            lp, rp = k % 2, k // 2
            if rp != 0:
                continue      # the rows-2,3 tables are read in the same pattern
            src0 = wb.sr_src(2 * lp + 4 * col)
            src1 = wb.sr_src(2 * lp + 1 + 4 * col)
            lo = W.col_base(col, 0, 0) + k * W.W16_TAB
            hi = lo + W.W16_TAB
            seen = []
            ok = 0
            for t, recs in enumerate(traces):
                hit = [r[1] for r in recs if lo <= r[0] < hi]
                if len(hit) != 1:
                    print("   col %d k %d: %d accesses in the table" % (col, k, len(hit)))
                    continue
                want = art.p0[src0][pts[t][src0]] | (art.p0[src1][pts[t][src1]] << 8)
                ok += (hit[0] == want)
                seen.append(hit[0])
            print("   %3d %d  %6d  %d/%d                        %d"
                  % (col, k, len(seen), ok, len(seen), len(set(seen))))
            okall += ok
            tot += len(seen)
    print("   %d/%d: the pair-table index is P0 of two plaintext bytes - public,"
          " key-free" % (okall, tot))

    # ---- 2. decode indices --------------------------------------------------
    print("\n== 2. round-0 decode tables: the 16-bit index, recomputed ==")
    print("   col row  index == pair_left ^ pair_right  distinct/64")
    same = 0
    tot2 = 0
    for col in range(4):
        cb = W.col_base(col, 0, 0)
        for row in range(4):
            lo = cb + wb.BDY_OFF + row * wb.N
            hi = lo + wb.N
            rp = row // 2
            kl, kr = 2 * rp, 2 * rp + 1
            seen = []
            eq = 0
            srcs = [wb.sr_src(l + 4 * col) for l in range(4)]
            for t, recs in enumerate(traces):
                hit = [r[1] for r in recs if lo <= r[0] < hi]
                if len(hit) != 1:
                    continue
                seen.append(hit[0])
                # recompute the two halves from the artifact and XOR them
                idx_l = art.p0[srcs[0]][pts[t][srcs[0]]] | \
                        (art.p0[srcs[1]][pts[t][srcs[1]]] << 8)
                idx_r = art.p0[srcs[2]][pts[t][srcs[2]]] | \
                        (art.p0[srcs[3]][pts[t][srcs[3]]] << 8)
                wl = art.tab_obj.r16(cb + kl * W.W16_TAB, idx_l,
                                     wb.hy_tag(0, 0, col, W.K_W16_L + kl))
                wr = art.tab_obj.r16(cb + kr * W.W16_TAB, idx_r,
                                     wb.hy_tag(0, 0, col, W.K_W16_L + kr))
                eq += (hit[0] == (wl ^ wr))
            print("   %3d %3d  %d/%d                              %d/64"
                  % (col, row, eq, len(seen), len(set(seen))))
            same += eq
            tot2 += len(seen)
    print("   %d/%d: the decode index is exactly the XOR of the two 16-bit pair"
          " values" % (same, tot2))
    print("   every decode index is one of 2^16 values, so no 256-hypothesis test")
    print("   on a single key byte can predict it; the pair tables that produce it")
    print("   are indexed by public P0(pt).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
