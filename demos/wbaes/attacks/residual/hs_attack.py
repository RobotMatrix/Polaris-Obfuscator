#!/usr/bin/env python3
"""Residual attack (a): hidden shift on Q[a][b] = Z(D0[a] ^ D1[b])  (Biryukov-Shamir class).

The pair-decode tables dl5 added to kill the dl4 XOR fit are

    Q[a][b] = Z( D0[a] ^ D1[b] )

with Z, D0, D1 random bijections. The design calls this a hidden-shift problem and
records it as unimplemented (WB-DESIGN-V2.md 12.4 item 1). This script implements the
structural attack and measures how far it gets.

What is recoverable without brute force
---------------------------------------
Every row f_a = Q[a][.] is a permutation of the 256 output values, so

    lam_a = f_a o f_0^-1,   lam_a(y) = Z( Z^-1(y) ^ (D0[a] ^ D0[0]) )

is computable from Q alone, and LAM = {lam_a} is a group of 256 involutions acting
regularly on the value set, isomorphic to (Z2)^8. The same construction on columns
gives the D1 side inside the same group. So Q determines

    D0[a]^D0[0] and D1[b]^D1[0] as group elements, i.e. B(D0[a] ^ t) for an unknown
    linear B in GL(8,2) and an unknown t,

and nothing else: (Z, D0, D1) -> (Z o A^-1, A o D0, A o D1) and (D0^t, D1^t) leave Q
bit-identical. Those are the "entries pinned / remaining freedom" numbers below.

Why the key still falls
-----------------------
Round 0's lane table gives, for lane k and byte row r,

    byte_r( lane_k[enc] ) = E_{r,k}[ m_{r,k} . S( P0^-1(enc) ^ key ) ]

and D_{r,k} = E_{r,k}^-1 is exactly the labelling Decomp recovers from Q (lanes 2p and
2p+1 share one Q table per row). So val = D_{r,k}[byte_r] equals m.S(...) composed
with the unknown gauge B. The dl4 test "val equals m.S(pt ^ g) up to a constant"
therefore cannot fire (measured: 0 candidates) -- but its gauge-invariant form can:
ask whether val is an *affine* image of m.S(pt ^ g), i.e. whether a GF(2)-linear A
with val = A(m.S(pt^g)) ^ const exists. The true key gives A = B. A wrong key would
need the AES S-box to be linearly equivalent to one of its own input translations,
which the candidate counts below show does not happen.

usage:
  python3 hs_attack.py [--binary BIN] [--seed 0x..] [--cache FILE] [--key HEX]
"""

import argparse
import math
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reslib as R
import wblib as wb


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--binary", default=wb.DEFAULT_BIN)
    ap.add_argument("--seed", type=lambda s: int(s, 0))
    ap.add_argument("--cache", default=None, help="cache the unmasked table here")
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--key", default=R.CHALLENGE_KEY, help="only used on the verify line")
    ap.add_argument("--table", default=None,
                    help="raw table from a variant generator (needs --work for hy_in.h/hy_seal.h)")
    ap.add_argument("--work", default=None)
    a = ap.parse_args(argv)

    t_start = time.time()
    if a.table:
        art, _seed = R.load_variant(a.table, a.work or os.path.dirname(a.table),
                                   (a.pagesize, a.ncpu, a.cls))
        t_load = time.time() - t_start
    else:
        art, t_load = R.load_shipped(a.binary, a.seed, a.cache, (a.pagesize, a.ncpu, a.cls))
    print("binary : %s" % (a.table or a.binary))
    print("artifact: table %d B, mask seed 0x%08x, unmask %.2fs"
          % (len(art.tab), art.seed, t_load))
    print("schedule enc: %s" % [wb.FAM_NAMES[s] for s in art.schedule])
    if art.schedule[0] != wb.FAM_T32:
        raise SystemExit("round 0 is not F1/T32; this script's tag choice assumes it")

    print("== 1. decompose the 32 pair-decode tables (Q = Z o (D0 ^ D1)) ==")
    t0 = time.time()
    res = R.round0_peel(art)
    t_peel = time.time() - t0
    dec = res["dec"]
    zperm = sum(1 for d in dec.values() if d.ok)
    print("   every row and every column of Q is a permutation of the 256 output values,")
    print("   LAM is (Z2)^8 with a regular action, so Q rebuilds as Z(da[a]^db[b]):")
    print("   %d/%d entries over 32 tables, Z a bijection in %d/32"
          % (65536 * zperm, 65536 * 32, zperm))
    print("   pinned by Q alone: the group element of D0[a]^D0[0] for all 256 a, and of")
    print("   D1[b]^D1[0] for all 256 b, in all 32 tables")
    print("   remaining freedom: |GL(8,2)| * 2^8 = %d = 2^%.1f (an outer linear map and a"
          % (R.gauge_size(), math.log2(R.gauge_size())))
    print("   translation of the D values, i.e. Z's byte labelling, are unobservable)")
    print("   32 tables decomposed in %.2fs" % t_peel)

    print("== 2. round-0 key bytes, gauge-invariantly ==")
    print("   col lane row  candidates")
    for col in range(4):
        for k in range(4):
            for row, cands in res["detail"][(col, k)]:
                if row == 0:
                    print("   %3d %4d %3d  %d  %s" % (col, k, row, len(cands),
                                                      [hex(c) for c in cands[:3]]))
    nc = res["cand"]
    print("   candidates over all %d (col,lane,row) byte positions: min %d median %d max %d"
          % (len(nc), min(nc), sorted(nc)[len(nc) // 2], max(nc)))
    agree = 0
    for col in range(4):
        for k in range(4):
            sets = [cands for _row, cands in res["detail"][(col, k)]]
            agree += 1 if all(s == sets[0] for s in sets) else 0
    print("   the four MC rows agree on the candidate set for %d/16 (column, lane) pairs"
          % agree)

    # control: the dl4 test with the gauge forced to the identity finds nothing
    strict = 0
    for col in range(4):
        for k in range(4):
            src = wb.sr_src(k + 4 * col)
            words = R.lane_word(art, col, k)
            dd = dec[(col, 0, k // 2)].d_for(k % 2)
            val = [dd[words[enc] & 255] for enc in range(256)]
            m = wb.MC[0][k]
            for g in range(256):
                x = R.half_round_values(art.p0i, src, g, m)
                c = x[0] ^ val[0]
                if all((x[i] ^ c) == val[i] for i in range(256)):
                    strict += 1
    print("   same test with the unknown gauge forced to the identity (dl4's test):")
    print("   %d candidates for 16 bytes -> the gauge is what the pair table cannot hide"
          % strict)

    print("== 3. result ==")
    key = res["key"]
    if key is None:
        print("   incomplete: %d/16 bytes" % len(res["per_byte"]))
        return 1
    ct = wb.aes_encrypt(bytes.fromhex(R.CHALLENGE_PT), key)
    print("   recovered key: %s" % key.hex())
    print("   AES-128(%s) = %s" % (R.CHALLENGE_PT, ct.hex()))
    print("   shipped ct  = %s" % R.CHALLENGE_CT)
    print("   reproduces the shipped ciphertext: %s"
          % ("YES" if ct.hex() == R.CHALLENGE_CT else "NO"))
    print("   equals the published key: %s" % ("YES" if key.hex() == a.key else "NO"))
    print("   work factor: %d affine-consistency tests (64 byte positions x 256 guesses),"
          " 32 group recoveries" % (len(nc) * 256))
    print("   no search over Z, no search over D0/D1, no traces; %.2fs total (%.2fs algebra)"
          % (time.time() - t_start, t_peel))
    return 0 if ct.hex() == R.CHALLENGE_CT else 1


if __name__ == "__main__":
    sys.exit(main())
