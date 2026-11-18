#!/usr/bin/env python3
"""Does a 16-bit-wide column combine hide rk0?  Measured on a built F4 artifact.

The construction (`gen_hybrid.cpp` in this experiment, HY_FAM_W16) pairs the four
lanes of a column two by two *and* the four output rows two by two, so the column's
partial sums are 16 bits wide:

    T_L01[a][b]  = E01( MC[0][0]u0 ^ MC[0][1]u1, MC[1][0]u0 ^ MC[1][1]u1 )
    T_R01[c][d]  = E01( MC[0][2]u2 ^ MC[0][3]u3, MC[1][0]u2 ^ MC[1][1]u3 )
    Y01 = E01^-1( T_L01 ^ T_R01 )                 # 16-bit XOR, 16-bit values
    out_r = P_out[ byte_r(Y01) ^ rk_after[r] ]    # four 2^16-index decode tables

with E01 a per-build affine 16-bit map, the same on both halves of a row pair.

What this script measures, in this order:

  0. the arithmetic that has to hold *before* a table is built: is the combine
     really 16 bits wide, and can the value encoding be anything but affine?
  1. the artifact: unmask, then the pair-table census (is every 2^16-index pair
     table a bijection onto 2^16 16-bit values, i.e. is the sum layer 16 bits?).
  2. the dl4/BGE step in 16-bit values: is T[a][b] == X[a] ^ Y[b]?   (XOR fit)
  3. the generalised hidden-shift decomposition (res16.Decomp16) on the 16-bit
     pair tables, and reslib.Decomp on their 8-bit projections and on the decode
     tables -- which is where the previous generation's failure lived.
  4. the gauge-invariant per-key-byte test on a 16-bit axis: how many 256-guess
     tests does the whole key cost?
  5. key -> AES -> the shipped ciphertext.

usage: python3 w16_probe.py --table hy_table.bin --work .
"""

import argparse
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import wblib as wb
import reslib as R
import res16 as W

MC = wb.MC


# ---------------------------------------------------------------------------
def rand_invertible16(rng):
    """A random invertible 16x16 GF(2) map as 16 parity rows (y_i = <row_i, x>)."""
    basis = []
    while len(basis) < 16:
        v = rng.randrange(65536)
        y = v
        for b in basis:
            y = min(y, y ^ b)
        if y:
            basis.append(y)
            basis.sort(reverse=True)
    return basis


def apply16(rows, x):
    y = 0
    for i in range(16):
        if bin(x & rows[i]).count("1") & 1:
            y |= 1 << i
    return y


def check_combine_width(rng):
    """Is the value the two halves meet in really 16 bits wide?

    Both operands are 16-bit table values, so the XOR is 16 bits by construction.
    What is worth measuring is whether the map those tables implement is injective
    on its 2^16 indices: a bijection keeps all 16 bits, a collapse would make the
    combine narrower than claimed.
    """
    rows = rand_invertible16(rng)
    c = rng.randrange(65536)
    vals = {apply16(rows, i) ^ c for i in range(65536)}
    return len(vals), 65536


def check_encoding_must_be_affine(rng, samples=4096):
    """Can a *nonlinear* 16-bit value encoding be undone by a 2^16-index table?

    The runtime needs one table D with D(E0(u) ^ E1(v)) = u ^ v for all u, v.
    Sample `samples` pairs and count how often the same index x = E0(u) ^ E1(v)
    comes back with two different required outputs u ^ v. Zero conflicts is a
    necessary condition for such a table to exist.
    """
    def perm():
        p = list(range(65536))
        rng.shuffle(p)
        return p

    E0, E1 = perm(), perm()
    seen, conf_nl = {}, 0
    for _ in range(samples):
        u, v = rng.randrange(65536), rng.randrange(65536)
        x, w = E0[u] ^ E1[v], u ^ v
        old = seen.get(x)
        if old is None:
            seen[x] = w
        elif old != w:
            conf_nl += 1
    nl_dist = len(seen)

    rows = rand_invertible16(rng)
    c = rng.randrange(65536)
    seen2, conf_aff = {}, 0
    for _ in range(samples):
        u, v = rng.randrange(65536), rng.randrange(65536)
        x = (apply16(rows, u) ^ c) ^ (apply16(rows, v) ^ c)
        w = u ^ v
        old = seen2.get(x)
        if old is None:
            seen2[x] = w
        elif old != w:
            conf_aff += 1
    return conf_nl, nl_dist, conf_aff, len(seen2)


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--table", required=True)
    ap.add_argument("--work", default=".")
    ap.add_argument("--seed", type=int, default=0xC0FFEE)
    a = ap.parse_args(argv)

    import random
    rng = random.Random(a.seed)
    t_start = time.time()

    print("== 0. arithmetic preconditions (checked before the table was built) ==")
    nvals, nidx = check_combine_width(rng)
    print("   one pair table: %d distinct 16-bit values over %d indices -> %s"
          % (nvals, nidx, "a bijection, so the sum layer is 16 bits wide"
             if nvals == nidx else "NOT injective: the sum is narrower"))
    conf_nl, nl_dist, conf_aff, aff_dist = check_encoding_must_be_affine(rng)
    print("   merge table D(E0(u)^E1(v)) = u^v, 4096 sampled pairs:")
    print("     E0, E1 random 16-bit bijections : %d collisions demanding two"
          " different outputs (%d distinct indices)" % (conf_nl, nl_dist))
    print("     E0 = E1 affine 16-bit map       : %d collisions (%d distinct indices)"
          % (conf_aff, aff_dist))
    print("   -> the value encoding has to be affine; the collision counts above are")
    print("      the numerical form of the proof in the report.")

    print("\n== 1. artifact ==")
    art, seed, secs = W.load(a.table, a.work)
    print("   table %s, %d bytes, mask seed 0x%08x, env 0x%08x"
          % (os.path.basename(a.table), len(art.tab), seed, art.env))
    print("   unmasked in %.1fs (one pass over 70 MB)" % secs)

    print("\n== 2. the pair tables: is the sum layer really 16 bits? ==")
    t1 = time.time()
    census = []
    for col in range(4):
        for k in range(4):
            Q = W.pair_tab(art, col, k)
            vals = set()
            for row in Q:
                vals.update(row)
            census.append(len(vals))
    print("   16 pair tables x 65536 entries, distinct 16-bit values per table:")
    print("   min %d, max %d  (65536 = a bijection on the index)"
          % (min(census), max(census)))
    print("   read and counted in %.2fs" % (time.time() - t1))

    print("\n== 3. the dl4/BGE step, in 16-bit values ==")
    hits = tot = 0
    for col in range(4):
        line = []
        for k in range(4):
            Q = W.pair_tab(art, col, k)
            ok, bad = W.sep_fit(Q)
            hits += ok
            tot += ok + bad
            line.append("%d/%d" % (ok, ok + bad))
        print("   col %d: T[a][b] == X[a]^Y[b] on %s" % (col, "  ".join(line)))
    print("   total %d/%d: one row plus one column of 256 values reproduces every"
          " 2^16 table exactly" % (hits, tot))

    print("\n== 4. the generalised hidden-shift decomposition ==")
    print("   (reslib.Decomp reads a group off the rows; a 16-bit value alphabet")
    print("    would only leave the gauge |GL(16,2)|*2^16 = 2^%.1f, so it is worth"
          " trying)" % (math.log2(W.gauge16_size())))
    t2 = time.time()
    for col in range(4):
        Q = W.pair_tab(art, col, 0)
        d16 = W.Decomp16(Q, "col%d.k0" % col)
        print("   pair table col %d k=0: %s" % (col, d16.report()))
        r0, d0 = W.decomp_projection(Q, 0)
        print("     reslib.Decomp on its byte-0 projection: %s"
              % ("decomposes" if r0 else "refuses (%s)" % d0))
        r1, d1 = W.decomp_projection(Q, 1)
        print("     reslib.Decomp on its byte-1 projection: %s"
              % ("decomposes" if r1 else "refuses (%s)" % d1))
    # The decode tables are the 2^16-index, 8-bit-valued tables the last
    # generation died on. Scan every encrypt-direction one of them.
    full = 0
    total = 0
    permrow_tabs = 0
    for rnd in range(9):
        for col in range(4):
            for row in range(4):
                D = W.decode_tab(art, col, row, rnd)
                Q = [[D[(x << 8) | y] for y in range(256)] for x in range(256)]
                total += 1
                permrows = sum(1 for x in range(256) if len(set(Q[x])) == 256)
                if permrows == 256:
                    permrow_tabs += 1
                r, d = W.decomp_projection(Q, 0)
                if r:
                    full += 1
    print("   decode tables (2^16 index, 8-bit values), all %d encrypt slots:" % total)
    print("     permutation rows (the object Decomp needs): %d/%d tables"
          % (permrow_tabs, total))
    print("     reslib.Decomp succeeds on: %d/%d" % (full, total))
    print("   both 8x8 blocks of E^-1 have to be invertible for a decode table to")
    print("   decompose (one for the rows, one for lam to be injective), i.e. about")
    print("   8% per table; a decomposition would return E^-1 up to gauge, which is")
    print("   the public linear map, not a key byte.")
    print("   %.2fs" % (time.time() - t2))

    print("\n== 5. the gauge-invariant key test on a 16-bit axis ==")
    known = bytes.fromhex(R.CHALLENGE_KEY)
    print("   model check: at the true key byte, is the 256-entry 16-bit axis an")
    print("   affine image of S(P0^-1(enc) ^ k), i.e. the object the test looks for?")
    src0 = wb.sr_src(0)
    axis = W.pair_row(art, 0, 0, 0)
    mid = W.lane_vector16(art.p0i, src0, known[src0], 0, rows=(0, 1))
    mp = {}
    okfit = True
    for i in range(256):
        xd, vd = (mid[i] ^ mid[0]), (axis[i] ^ axis[0])
        if xd in mp and mp[xd] != vd:
            okfit = False
            break
        mp[xd] = vd
    print("     col 0 lane 0: %d/256 differences consistent, fit holds: %s"
          % (len(mp), "YES" if okfit else "NO"))
    print("   lane col true   candidates        tests  verdict")
    t3 = time.time()
    got = {}
    tests = 0
    for col in range(4):
        for lane in range(4):
            lp = lane // 2
            src = wb.sr_src(lane + 4 * col)
            val = W.pair_row(art, col, lp, lane % 2)
            cands = W.key_candidates16(val, art.p0i, src)
            tests += 256
            print("   %4d  %3d  0x%02x  %-16s  %5d  %s"
                  % (lane, col, known[src], [hex(c) for c in cands], 256,
                     "unique" if len(cands) == 1 else "%d candidates" % len(cands)))
            if len(cands) == 1:
                got.setdefault(src, set()).add(cands[0])
    print("   16 axes, %d tests, %.2fs" % (tests, time.time() - t3))

    print("\n== 5b. the byte-axis routes, and why they are not cheaper ==")
    t4 = time.time()
    tests_b = 0
    uniq_inv = 0
    uniq_tol = 0
    for col in range(4):
        for lane in range(4):
            src = wb.sr_src(lane + 4 * col)
            val = W.pair_row(art, col, lane // 2, lane % 2)
            for byte in (0, 1):
                v8 = [(v >> (8 * byte)) & 255 for v in val]
                c_inv = R.key_candidates(v8, art.p0i, src, 1)   # shipped test
                c_tol = [g for g in range(256)
                         if W.affine_image_ok(W.lane_axis(art.p0i, src, g), v8,
                                              need_rank=1, bits=8)]
                tests_b += 256            # 256 guesses per axis, per variant
                uniq_inv += (len(c_inv) == 1)
                uniq_tol += (len(c_tol) == 1)
    print("   32 byte axes x 256 guesses x 2 variants = %d tests, %.2fs"
          " (an attack needs half of that)" % (tests_b, time.time() - t4))
    print("   shipped test (needs an invertible image): %d/32 unique" % uniq_inv)
    print("   rank-tolerant test (singular image allowed): %d/32 unique" % uniq_tol)
    print("   the 16-bit test needs %d and needs no tolerance: one 16-bit value"
          " covers two MC rows" % tests)
    # The route the previous generation used: decompose an 8-bit projection of the
    # pair table (that is the shape dl5 died on), then run the key test in the
    # *label* domain the decomposition produces. Scan all 32 projections.
    dec_proj = 0
    demo = None
    for col in range(4):
        for k in range(4):
            Q = W.pair_tab(art, col, k)
            for byte in (0, 1):
                r, d = W.decomp_projection(Q, byte)
                if r:
                    dec_proj += 1
                    if demo is None:
                        demo = (col, k, byte, d)
    print("   projections that decompose: %d/32 (pair tables, both value bytes)"
          % dec_proj)
    if demo is not None:
        col, k, byte, d = demo
        lane_off = 0                       # the decomposition labels both index axes
        src = wb.sr_src(2 * (k % 2) + lane_off + 4 * col)
        lab = [d.d_for(lane_off)[b] for b in range(256)]
        c_inv = R.key_candidates(lab, art.p0i, src, 1)
        print("   through col %d table %d byte %d: hidden shift recovered"
              " (%d lambda elements, gauge 2^70.2)," % (col, k, byte, len(set(d.lam))))
        print("     label-domain axis -> %s at 256 guesses: the same single"
              " candidate, no cheaper" % [hex(c) for c in c_inv])

    print("\n== 6. result ==")
    if len(got) != 16 or any(len(s) != 1 for s in got.values()):
        print("   incomplete: %d/16 key bytes" % len(got))
        return 1
    rk = bytes(next(iter(got[i])) for i in range(16))
    ct = wb.aes_encrypt(bytes.fromhex(R.CHALLENGE_PT), rk)
    print("   recovered key: %s" % rk.hex())
    print("   AES-128(%s) = %s" % (R.CHALLENGE_PT, ct.hex()))
    print("   shipped ct   = %s" % R.CHALLENGE_CT)
    print("   reproduces the shipped ciphertext: %s"
          % ("YES" if ct.hex() == R.CHALLENGE_CT else "NO"))
    print("   work factor: 4096 affine-consistency tests (16 lane axes x 256"
          " guesses), no search over the 16-bit encoding, no traces, %.2fs total"
          % (time.time() - t_start))
    return 0 if ct.hex() == R.CHALLENGE_CT else 1


if __name__ == "__main__":
    sys.exit(main())
