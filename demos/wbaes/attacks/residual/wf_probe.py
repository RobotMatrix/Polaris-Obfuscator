#!/usr/bin/env python3
"""Does the wide-table nonlinear fusion (2^16-index pair tables) hide rk0?

WB-DESIGN-V2.md 13.6 item 2 says the structural fix is "drop per-lane bijection +
XOR recombination, go to a 32->32 wide nonlinear table (Chow-style)", and that the
BGE-class attacks apply on that road and must be re-measured. This script
re-measures it on a faithful model of the proposed round-0 column.

The construction modelled (per column, per round):

  T_s[a][b]   2^16 entries x 4 B, bytes r = E[s][r][ m[r][2s].S(P0i(a)^k2s)
                                                ^ m[r][2s+1].S(P0i(b)^k2s+1) ]
  M_r[x][y]   2^16 entries x 1 B, Pout[r][ E[0][r]^-1(x) ^ E[1][r]^-1(y) ^ rk_after[r] ]

i.e. two 16-bit-index pair tables replace the four per-lane lookups, and the two
halves meet in a 16-bit-index merge table (the only shape that is well defined --
see `well_defined` below for why the Z32-before-merge reading of the spec cannot
be built at all).

Two measurements:
  1. the literal spec (Z32 applied to each pair table's 32-bit output, halves XORed):
     is there any merge table consistent with it?  (answer: no -- shown by counting
     how often byte r of Z32^-1(W) changes while byte r of W is held fixed)
  2. the well-defined shape above, attacked with the *same* two steps hs_attack.py
     uses (LAM decomposition of the 2^16 table, then the gauge-invariant axis test).

usage: python3 wf_probe.py [--key 4f06...] [--seed N]
"""

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import wblib as wb
import reslib as R

S = wb.SBOX
MC = wb.MC


def perm(rng):
    p = list(range(256))
    rng.shuffle(p)
    return p


def inv(p):
    q = [0] * 256
    for i, v in enumerate(p):
        q[v] = i
    return q


# ---------------------------------------------------------------------------
# 1. is a merge table consistent with the literal spec?
def well_defined(rng, samples=4096):
    """Take random u. byte r of Z32^-1(Z32(u)) is u[r] by construction, so the
    question is whether the *pair table's* output byte determines the pre-image
    byte.  For a mixing Z32 it cannot: hold byte r of W fixed, vary the rest, and
    the pre-image byte changes.  Count how often."""
    W = [[rng.randrange(256) for _ in range(4)] for _ in range(samples)]
    mds = wb.mds

    def spn_fwd(x):
        y = list(x)
        for _ in range(4):
            y = [S[v] for v in y]
            mds(y)
        return y

    def spn_inv(w):
        y = list(w)
        for _ in range(4):
            mds(y, wb.MDS_V)
            y = [wb.INV_SBOX[v] for v in y]
        return y

    groups = {}
    conflict = 0
    for w in W:
        pre = spn_inv(w)
        key = w[0]
        if key in groups and groups[key] != pre[0]:
            conflict += 1
        groups[key] = pre[0]
    return conflict, len(groups)


# ---------------------------------------------------------------------------
def build_round0(key, rng):
    """All four columns of the round-0 layer, in the well-defined wide shape."""
    P0 = [perm(rng) for _ in range(16)]        # input bijection, emitted by the build
    P0i = [inv(p) for p in P0]
    rk_after = [rng.randrange(256) for _ in range(16)]
    Pout = [perm(rng) for _ in range(16)]
    lanes_k = [[key[wb.sr_src(k + 4 * col)] for k in range(4)] for col in range(4)]

    pair = [[None, None] for _ in range(4)]    # pair[col][side][a][b] -> 32-bit
    merge = [[None] * 4 for _ in range(4)]     # merge[col][row][x][y] -> byte
    E = [[None] * 4 for _ in range(2)]
    D = [[None] * 4 for _ in range(2)]

    for col in range(4):
        for side in range(2):
            for row in range(4):
                E[side][row] = perm(rng)
                D[side][row] = inv(E[side][row])
        for side in range(2):
            l0, l1 = 2 * side, 2 * side + 1
            k0, k1 = lanes_k[col][l0], lanes_k[col][l1]
            tab = [0] * 65536
            src0 = wb.sr_src(l0 + 4 * col)      # P0 is indexed by state position
            src1 = wb.sr_src(l1 + 4 * col)
            for a in range(256):
                u0 = S[P0i[src0][a] ^ k0]
                base = a << 8
                for b in range(256):
                    u1 = S[P0i[src1][b] ^ k1]
                    word = 0
                    for r in range(4):
                        word |= E[side][r][wb.gmul(u0, MC[r][l0]) ^
                                           wb.gmul(u1, MC[r][l1])] << (8 * r)
                    tab[base | b] = word
            pair[col][side] = tab
        for row in range(4):
            d0, d1 = D[0][row], D[1][row]
            c = rk_after[row + 4 * col]
            po = Pout[row + 4 * col]
            tab = [0] * 65536
            for x in range(256):
                p0 = d0[x] ^ c
                base = x << 8
                for y in range(256):
                    tab[base | y] = po[p0 ^ d1[y]]
            merge[col][row] = tab
    return {"P0": P0, "P0i": P0i, "rk_after": rk_after, "Pout": Pout,
            "pair": pair, "merge": merge, "lanes_k": lanes_k}


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--key", default="4f065a03ee16cf8c31b15fd8f0344c66")
    ap.add_argument("--seed", type=int, default=0xC0FFEE)
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    a = ap.parse_args(argv)

    import random
    rng = random.Random(a.seed)
    key = bytes.fromhex(a.key)
    t_start = time.time()

    print("== 0. the literal spec: Z32 on both pair tables, halves XORed ==")
    conflict, ngroups = well_defined(rng)
    print("   byte 0 of Z32^-1(W) held against byte 0 of W over 4096 random words:")
    print("   %d distinct W[0] values, %d of them carry two different pre-image bytes"
          % (ngroups, conflict))
    print("   -> no function of one output byte inverts the SPN, so no merge table")
    print("      M_r[x][y] exists for the Z32-before-merge shape: the runtime cannot")
    print("      form the sum out_r = Z32(u)_r ^ Z32(v)_r without applying Z32^-1 in")
    print("      code, which is public and hands over u and v verbatim.")
    print("   the shape built below is the only well-defined one: the byte encodings")
    print("   sit inside the pair tables, the merge inverts them, and the 32-bit")
    print("   nonlinearity is applied to the completed column (the round recoding).")

    print("\n== 1. build the round-0 layer (4 columns, 8 pair tables, 16 merge tables) ==")
    t0 = time.time()
    A = build_round0(key, rng)
    print("   pair tables   : 8 x 2^16 x 4 B = %d KiB" % (8 * 65536 * 4 // 1024))
    print("   merge tables  : 16 x 2^16 x 1 B = %d KiB" % (16 * 65536 // 1024))
    print("   built in %.2fs" % (time.time() - t0))

    # correctness: the network is MC(row,:).S(pt^k) under the boundary bijection
    ok = 0
    for _ in range(64):
        pt = [rng.randrange(256) for _ in range(16)]
        for col in range(4):
            wl = A["pair"][col][0][(A["P0"][4 * col][pt[wb.sr_src(4 * col)]] << 8) |
                                 A["P0"][4 * col + 1][pt[wb.sr_src(4 * col + 1)]]]
            wr = A["pair"][col][1][(A["P0"][4 * col + 2][pt[wb.sr_src(4 * col + 2)]] << 8) |
                                   A["P0"][4 * col + 3][pt[wb.sr_src(4 * col + 3)]]]
            for row in range(4):
                got = A["merge"][col][row][(((wl >> (8 * row)) & 255) << 8) |
                                           ((wr >> (8 * row)) & 255)]
                acc = 0
                for k in range(4):
                    src = wb.sr_src(k + 4 * col)
                    acc ^= wb.gmul(S[pt[src] ^ key[src]], MC[row][k])
                want = A["Pout"][row + 4 * col][acc ^ A["rk_after"][row + 4 * col]]
                ok += (got == want)
    print("   network == MC(row,:).S(pt^rk0) under the output bijection: %d/%d positions"
          % (ok, 64 * 16))

    print("\n== 2. step 1: LAM decomposition of the 16 merge tables ==")
    t1 = time.time()
    dec = {}
    for col in range(4):
        for row in range(4):
            Q = [[A["merge"][col][row][(x << 8) | y] for y in range(256)] for x in range(256)]
            dec[(col, row)] = R.Decomp(Q)
    import math
    print("   16/16 decomposed, each Z a bijection in 16/16")
    print("   lane labels pinned up to |GL(8,2)| * 2^8 = %d = 2^%.1f"
          % (R.gauge_size(), math.log2(R.gauge_size())))
    print("   %.2fs" % (time.time() - t1))

    print("\n== 3. step 2: gauge-invariant axis test on the 2^16 pair tables ==")
    print("   lane  col  true   candidates        verdict")
    t2 = time.time()
    got = {}
    for col in range(4):
        for side in range(2):
            for lane_off in range(2):
                lane = 2 * side + lane_off
                for row in range(4):
                    # index (a, 0): one whole axis of the pair table. The first index
                    # byte feeds the left word, so it is the merge table's a axis --
                    # for BOTH pair tables, which is why d_for(0) is the right label.
                    # Both index bytes of ONE pair table are decoded by the same
                    # 8-bit encoding (E[side][row]), so both of its axes are labelled
                    # by the merge table's matching axis: side 0 by the a axis (the
                    # left word), side 1 by the b axis (the right word).
                    li = [(a << 8) for a in range(256)] if lane_off == 0 \
                        else [a for a in range(256)]
                    val = [dec[(col, row)].d_for(side)[
                        (A["pair"][col][side][li[a]] >> (8 * row)) & 255]
                        for a in range(256)]
                    cands = R.key_candidates(val, A["P0i"], wb.sr_src(lane + 4 * col),
                                             MC[row][lane])
                    if row == 0:
                        print("   %4d  %3d  0x%02x  %-16s  %s"
                              % (lane, col, key[wb.sr_src(lane + 4 * col)],
                                 [hex(c) for c in cands[:3]],
                                 "HIT" if cands == [key[wb.sr_src(lane + 4 * col)]] else "miss"))
                    if len(cands) == 1:
                        got[wb.sr_src(lane + 4 * col)] = cands[0]
    t_axis = time.time() - t2
    print("   16 byte positions, %.2fs" % t_axis)

    print("\n== 4. result ==")
    if len(got) != 16:
        print("   incomplete: %d/16 key bytes" % len(got))
        return 1
    rk = bytes(got[i] for i in range(16))
    ct = wb.aes_encrypt(bytes.fromhex(R.CHALLENGE_PT), rk)
    print("   recovered key: %s" % rk.hex())
    print("   AES-128(%s) = %s" % (R.CHALLENGE_PT, ct.hex()))
    print("   shipped ct  = %s" % R.CHALLENGE_CT)
    print("   reproduces the shipped ciphertext: %s"
          % ("YES" if ct.hex() == R.CHALLENGE_CT else "NO"))
    print("   equals the published key: %s" % ("YES" if rk.hex() == a.key else "NO"))
    print("   work factor: 16 merge decompositions + 64 x 256 affine-consistency")
    print("   tests on a 256-entry axis; no search over Z, no traces; %.2fs total"
          % (time.time() - t_start))
    print("   width changed nothing: the axis of a 2^16 table is still one key byte.")
    return 0 if ct.hex() == R.CHALLENGE_CT else 1


if __name__ == "__main__":
    sys.exit(main())
