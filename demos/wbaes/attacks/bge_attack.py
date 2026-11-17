#!/usr/bin/env python3
"""BGE-style attempt on wbaes dl4: can the encoded table network be peeled down to
round-key bytes with algebra instead of traces?

This attacks the *table bytes* (offline, T1). The network is rebuilt as a Python model
from the generator's own parameters, which is what the design says an attacker would
have to reason about:

    lane(row,k)[x] = E[row][k][ MC[row][k] . S(x ^ rk) ]        E: random bijection
    pair(row,p)[a,b] = D[row][2p][a] ^ D[row][2p+1][b]          D = E^-1
    out(row,dst)[u]  = P[r][dst][ u ^ rk_next ]                 P: random bijection

The design's claim (demos/wbaes/AFFINE-ROUNDS.md sec. 8) is that E is not recoverable
because its inverse D "cannot fit into one 256-entry table"; the 64K pair table is the
only place the inverse exists, and that table is opaque. This script tests that claim:

  step 1  Is the 64K pair table opaque?  It is built as D0[a] ^ D1[b], i.e. an XOR
          (rank-1) tensor. Test: read it, fit d0[a] = Q[a][0] ^ Q[0][0] and
          d1[b] = Q[0][b] ^ Q[0][0], and count how many entries the fit reproduces.
          A perfect fit means both inverse bijections are handed over.
  step 2  Invert D to get E (up to one XOR constant per lane) and check it is a
          permutation.
  step 3  With E known backwards, each round-0 lane table gives
          MC[row][k] . S(pt ^ key) for every pt; the key byte is the candidate for
          which that expression is constant across all 256 pt. Report candidates.

If step 3 returns one candidate per (col,k), the master key falls out of round 0 alone:
no cross-round system and no BGE linearisation is needed. The script reports that
state honestly (and what would have blocked it) instead of pretending otherwise.

usage: python3 bge_attack.py [--binary ...] [--seed 0x...] [--cache FILE] [--full]
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wblib as wb

PUBLISHED_KEY = "755e563b1dffd249ef552c1bb778de29"  # used only on the verify line
CHALLENGE_PT = "6bc1bee22e409f96e93d7e117393172a"
CHALLENGE_CT = "abe296eea2625f251ba57ed0b408272c"

MUL = {1: [wb.gmul(i, 1) for i in range(256)],
       2: [wb.gmul(i, 2) for i in range(256)],
       3: [wb.gmul(i, 3) for i in range(256)]}


def q_off(col, row, pair):
    return wb.enc_col(0, col) + wb.Q_OFF + (2 * row + pair) * wb.N


def lane_off(col, k):
    return wb.enc_col(0, col) + k * wb.W1024


def decode_pair(tab, col, row, pair, env, sample=0):
    """Read the 64K pair table and test whether it is D0[a] ^ D1[b].
    Returns (d0, d1, entries_checked, mismatches, is_perm0, is_perm1)."""
    off = q_off(col, row, pair)
    tag = wb.hy_tag(0, 0, col, wb.K_T32_Q + 2 * row + pair)
    d0 = [0] * 256
    d1 = [0] * 256
    d00 = tab.r8(off, 0, tag)
    for a in range(256):
        d0[a] = tab.r8(off, a, tag) ^ d00
    for b in range(256):
        d1[b] = tab.r8(off, b << 8, tag) ^ d00
    bad = 0
    if sample:
        # deterministic spread over the 65536 entries
        step = 65536 // sample
        pairs = range(0, 65536, step)
    else:
        pairs = range(65536)
    for li in pairs:
        v = tab.r8(off, li, tag)
        pred = d0[li & 255] ^ d1[li >> 8] ^ d00
        if v != pred:
            bad += 1
    n = sample if sample else 65536
    return d0, d1, n, bad, len(set(d0)) == 256, len(set(d1)) == 256


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--binary", default=wb.DEFAULT_BIN)
    ap.add_argument("--seed", type=lambda s: int(s, 0))
    ap.add_argument("--cache", default=None)
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--sample", type=int, default=4096,
                    help="entries verified per pair table (0 = all 65536)")
    a = ap.parse_args(argv)

    env = wb.hy_env_mix(a.pagesize, a.ncpu, a.cls)
    print("binary : %s" % a.binary)
    print("env    : 0x%08x" % env)
    t0 = time.time()
    seed = a.seed
    if seed is None:
        seed, frag_off, tried = wb.find_mask_seed(a.binary, *wb.find_section(a.binary, "__hytab"))
    tab_b = wb.load_plain_table(a.binary, seed=seed, cache=a.cache)
    data = open(a.binary, "rb").read()
    p0 = wb.find_input_bijection(data)[0][1]
    p0i = [[0] * 256 for _ in range(16)]
    for i in range(16):
        for v in range(256):
            p0i[i][p0[i][v]] = v
    tab = wb.Tab(tab_b, env)
    sched = [tab_b[wb.SCHED_OFF + r] for r in range(wb.HY_MC_ROUNDS)]
    print("mask seed 0x%08x, table %d B, round-0 family %s (schedule %s)"
          % (seed, len(tab_b), wb.FAM_NAMES[sched[0]],
             [wb.FAM_NAMES[s] for s in sched]))

    print("== 0. model ==")
    print("   round-0 column slot: 4 lane tables (256 x 4 B) feeding 8 pair tables")
    print("   (64K each) and 4 boundary permutation tables (256 B); key sits in the")
    print("   lane value (S(x ^ rk0)), boundary table carries rk1.")

    # ---- step 1: XOR separability of the pair tables ----------------------
    print("== 1. peel step 1: is the 64K pair table opaque? ==")
    print("   pair(row,p)[a,b] = D[row][2p][a] ^ D[row][2p+1][b]  (by construction)")
    t1 = time.time()
    d = {}
    tot = bad = perm = 0
    for col in range(4):
        for row in range(4):
            for p in range(2):
                d0, d1, n, b, ok0, ok1 = decode_pair(tab, col, row, p, env, a.sample)
                d[(col, row, p)] = (d0, d1)
                tot += n
                bad += b
                perm += (ok0 and ok1)
    print("   %d/%d pair tables decomposed; %d of %d entries reproduced exactly by two"
          % (32, 32, tot - bad, tot))
    print("   256-byte arrays (%.2fs); recovered D is a permutation in %d/32 tables"
          % (time.time() - t1, perm))
    print("   -> the inverse bijections E^-1 are in the table in plain form, one XOR")
    print("      constant away: a rank-1 tensor has only 2*256 degrees of freedom, so")
    print("      'it only fits in a 64K table' buys nothing.")

    # ---- step 2 + 3: recover E, then the key byte ------------------------
    print("== 2/3. peel step 2/3: lane encodings back, then round-0 key bytes ==")
    print("   col k row  lane row is a bijection  distinct key candidates")
    t2 = time.time()
    rec = {}
    cand_rows = []
    for col in range(4):
        for k in range(4):
            src = wb.sr_src(k + 4 * col)
            off = lane_off(col, k)
            tag = wb.hy_tag(0, 0, col, wb.K_T32_W + k)
            for row in range(4):
                m = wb.MC[row][k]
                d0, d1 = d[(col, row, k // 2)]
                dd = d0 if (k % 2 == 0) else d1
                a = [(tab.r32t(off, enc, tag) >> (8 * row)) & 255 for enc in range(256)]
                is_perm = len(set(a)) == 256
                val = [dd[x] for x in a]                 # = MC . S(pt ^ rk) ^ const
                cands = []
                for g in range(256):
                    c0 = None
                    ok = True
                    for enc in range(256):
                        pt = p0i[src][enc]
                        t = val[enc] ^ MUL[m][wb.SBOX[pt ^ g]]
                        if c0 is None:
                            c0 = t
                        elif t != c0:
                            ok = False
                            break
                    if ok:
                        cands.append(g)
                if row == 0:
                    print("   %3d %d %3d  %s               %d %s"
                          % (col, k, row, "yes" if is_perm else "no ", len(cands),
                             [hex(c) for c in cands[:4]]))
                cand_rows.append((col, k, row, len(cands), cands[0] if cands else None))
                if len(cands) == 1 and row == 0:
                    rec[src] = cands[0]
    agree = all(len(set(r[3] for r in cand_rows if r[0] == c and r[1] == k)) == 1
                for c in range(4) for k in range(4))
    print("   all four MC rows agree on the candidate set: %s" % agree)

    print("== result ==")
    if len(rec) == 16:
        rk = bytes(rec[i] for i in range(16))
        ct = wb.aes_encrypt(bytes.fromhex(CHALLENGE_PT), rk)
        print("   AES-128 key recovered statically from round-0 tables: %s" % rk.hex())
        print("   AES-128(6bc1...172a) = %s" % ct.hex())
        print("   shipped ciphertext    = %s" % CHALLENGE_CT)
        print("   reproduces the shipped ciphertext: %s"
              % ("YES" if ct.hex() == CHALLENGE_CT else "NO"))
        print("   equals the published dl4 key: %s"
              % ("YES" if rk.hex() == PUBLISHED_KEY else "NO"))
        print("   wall time after the table was unmasked: %.2fs" % (time.time() - t2))
        print("   cross-round algebra rounds needed: 0 -- round 0 alone is the whole key")
    else:
        print("   incomplete (%d/16 bytes): round 0 did not yield the key" % len(rec))
        return 1
    print("== what this means for the design claim ==")
    print("   AFFINE-ROUNDS.md sec. 8 argued that a 256-entry table cannot hold the")
    print("   inverse of a lane bijection, so reading one row of one table returns")
    print("   nothing. That is true and measured (each lane row is a 256-element")
    print("   bijection image: any of the 256 key bytes fits it). What the argument")
    print("   missed is that the 64K table *does* contain the inverse, in XOR-separated")
    print("   form: Q[a][b] = D0[a] ^ D1[b] is recoverable from one row and one column")
    print("   of Q. Because the mix step is XOR, an elementwise bijection on a lane is")
    print("   not a mixing: to hide D, the inverse has to depend on a value that is not")
    print("   itself a table entry (Chow-style cross-lane nonlinear recoding), not just")
    print("   sit in a bigger table.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
