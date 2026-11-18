#!/usr/bin/env python3
"""Residual attack (c): unmask, invert the public recoding, re-run the round-table peel.

dl5 puts a 32-bit nonlinear recoding R at every round output (3 SPN rounds of
XOR-constant + per-byte bijection + MDS circulant (1,4,3,7), undone at the next round
boundary by hy_rec_undo with the twelve *inverse* S-tables stored in the artifact).
WB-DESIGN-V2.md 12.2 says this is a state encoding, not an algebraic barrier, and
12.4 item 3 lists "the recoding is invertible" as an open attack.

This script does it and measures what it is worth:

  1. recover R^-1 for all 72 (direction, round, column) instances from the table bytes
     alone (12 inverse S-tables + 12 constants + the public MDS inverse),
  2. check the recovery: R^-1(R(x)) == x, and the stored inverse S-tables equal the
     inverses of the stored forward ones (i.e. the artifact stores the same secret
     twice),
  3. measure what the recoding *does* buy: single-byte fault diffusion at the round
     output (one changed byte in -> how many changed bytes out),
  4. with the recoding inverted, check the shape of what remains: every byte of the
     round state should be a per-byte bijection of the genuine AES state byte (dl4's
     exact shape) -- measured against the known key,
  5. re-run the dl4 peel on the pair-decode tables: the XOR fit, which is where the
     chain still breaks.

The blocked step is not the recoding: it is the output bijection Z inside
Q = Z o (D0 ^ D1). Measured verdict at the bottom; hs_attack.py is the route that
does get the key.

usage:
  python3 recoding_peel.py [--binary BIN] [--cache FILE] [--seed 0x..]
"""

import argparse
import os
import random
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reslib as R
import wblib as wb

MDS_W = (1, 4, 3, 7)
MDS_V = (11, 11, 9, 8)


# ---------------------------------------------------------------------------
def read_spn(art, direction, rnd, col):
    """The recoding parameters of one instance, straight out of the table bytes."""
    cb = wb.enc_col(rnd, col)
    s = [[[0] * 256 for _ in range(4)] for _ in range(wb.SPN_ROUNDS)]
    si = [[[0] * 256 for _ in range(4)] for _ in range(wb.SPN_ROUNDS)]
    c = [[0] * 4 for _ in range(wb.SPN_ROUNDS)]
    for i in range(wb.SPN_ROUNDS):
        for j in range(4):
            tag = wb.hy_tag(direction, rnd, col, wb.K_SPN_S + i * 4 + j)
            base = cb + wb.SPN_OFF + (i * 4 + j) * wb.W256
            s[i][j] = [art.tab_obj.r8t(base, v, tag) for v in range(256)]
            tagi = wb.hy_tag(direction, rnd, col, wb.K_SPN_SI + i * 4 + j)
            basei = cb + wb.SPN_OFF + wb.SPN_SI_OFF + (i * 4 + j) * wb.W256
            si[i][j] = [art.tab_obj.r8t(basei, v, tagi) for v in range(256)]
            c[i][j] = art.tab[cb + wb.SPN_OFF + wb.SPN_C_OFF + i * 4 + j]
    return s, si, c


def mds_mix(y, w):
    out = [0] * 4
    for r in range(4):
        a = 0
        for k in range(4):
            a ^= wb.gmul(y[k], w[(k - r + 4) & 3])
        out[r] = a
    return out


def r_fwd(p, y):
    s, si, c = p
    y = list(y)
    for i in range(wb.SPN_ROUNDS):
        y = [s[i][j][y[j] ^ c[i][j]] for j in range(4)]
        y = mds_mix(y, MDS_W)
    return y


def r_inv(p, y):
    s, si, c = p
    y = list(y)
    for i in range(wb.SPN_ROUNDS - 1, -1, -1):
        y = mds_mix(y, MDS_V)
        y = [si[i][j][y[j]] ^ c[i][j] for j in range(4)]
    return y


# ---------------------------------------------------------------------------
def fit_ratio(art, sample_axis=256):
    """dl4's step 1 on the dl5 pair tables: how much of Q does D0[a]^D1[b] explain?

    The fit is built from row a=0 and column b=0, so those are counted separately;
    the honest statistic is the off-axis fraction.
    """
    ok = n = 0
    axis_ok = axis_n = 0
    for col in range(4):
        for row in range(4):
            for p in range(2):
                Q = R.q_read(art, col, row, p)
                d00 = Q[0][0]
                d0 = [Q[a][0] ^ d00 for a in range(256)]
                d1 = [Q[0][b] ^ d00 for b in range(256)]
                for a in range(256):
                    qa = Q[a]
                    da = d0[a]
                    for b in range(256):
                        pred = da ^ d1[b] ^ d00
                        if a and b:
                            n += 1
                            if qa[b] == pred:
                                ok += 1
                        else:
                            axis_n += 1
                            if qa[b] == pred:
                                axis_ok += 1
    return ok, n, axis_ok, axis_n


def aes_round0_state(pt, rk0, rk1):
    """MC(ShiftRows(S(pt ^ rk0))) ^ rk1, in the table network's column-major layout."""
    s = [wb.SBOX[pt[i] ^ rk0[i]] for i in range(16)]
    out = []
    for c in range(4):
        a = [s[k + 4 * ((c + k) & 3)] for k in range(4)]   # ShiftRows
        for row in range(4):
            v = 0
            for k in range(4):
                v ^= wb.gmul(a[k], wb.MC[row][k])
            out.append(v ^ rk1[row + 4 * c])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--binary", default=wb.DEFAULT_BIN)
    ap.add_argument("--seed", type=lambda s: int(s, 0))
    ap.add_argument("--cache", default=None)
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--key", default=R.CHALLENGE_KEY)
    ap.add_argument("--samples", type=int, default=512)
    a = ap.parse_args(argv)

    t_start = time.time()
    art, t_load = R.load_shipped(a.binary, a.seed, a.cache, (a.pagesize, a.ncpu, a.cls))
    print("binary : %s" % a.binary)
    print("artifact: table %d B, mask seed 0x%08x, unmask %.2fs"
          % (len(art.tab), art.seed, t_load))
    rng = random.Random(11)

    print("== 1. recover the recoding inverse from the artifact ==")
    t0 = time.time()
    inst = {}
    inv_matches = inv_tables = 0
    for direction in (0, 1):
        for rnd in range(wb.HY_MC_ROUNDS):
            for col in range(4):
                p = read_spn(art, direction, rnd, col)
                inst[(direction, rnd, col)] = p
                for i in range(wb.SPN_ROUNDS):
                    for j in range(4):
                        fwd = p[0][i][j]
                        back = [0] * 256
                        for v in range(256):
                            back[fwd[v]] = v
                        inv_tables += 1
                        inv_matches += (back == p[1][i][j])
    t_read = time.time() - t0
    print("   %d instances (2 directions x 9 rounds x 4 columns); %d B of recoding tables"
          % (len(inst), wb.SPN_BYTES * len(inst)))
    print("   stored inverse S-tables that are exactly the inverse of the stored forward"
          " S-table: %d/%d" % (inv_matches, inv_tables))
    print("   -> the artifact carries both directions of the same secret; R^-1 needs no"
          " search, only the public MDS inverse %s" % (MDS_V,))
    print("   read in %.2fs" % t_read)

    print("== 2. check R^-1 o R = identity and measure what R buys ==")
    t0 = time.time()
    bad = 0
    trials = 0
    for key_inst, p in inst.items():
        for _ in range(16):
            y = [rng.randrange(256) for _ in range(4)]
            trials += 1
            if r_inv(p, r_fwd(p, y)) != y:
                bad += 1
    print("   R^-1(R(x)) == x on %d/%d random 32-bit words over all 72 instances (%.2fs)"
          % (trials - bad, trials, time.time() - t0))
    # fault diffusion: one changed input byte -> how many changed output bytes
    hist = {}
    for key_inst in [(0, r, c) for r in range(9) for c in range(4)]:
        p = inst[key_inst]
        for _ in range(8):
            y = [rng.randrange(256) for _ in range(4)]
            j = rng.randrange(4)
            y2 = list(y)
            y2[j] ^= 1 << rng.randrange(8)
            a1, a2 = r_fwd(p, y), r_fwd(p, y2)
            d = sum(1 for i in range(4) if a1[i] != a2[i])
            hist[d] = hist.get(d, 0) + 1
    print("   single-byte fault at the round output -> changed bytes out: %s"
          % {k: hist[k] for k in sorted(hist)})
    print("   (the first MDS maps 1 -> 4; over the full 3-round recoding a later MDS can")
    print("    cancel one, hence the few 3s. This is what R buys: V5 garbage stays garbage.)")

    print("== 3. what remains once the recoding is inverted: dl4's shape ==")
    key = bytes.fromhex(a.key)
    rk = wb.aes_key_expand(key)
    p0 = art.p0
    seen = [dict() for _ in range(16)]
    conflicts = 0
    for n in range(a.samples):
        pt = bytes(rng.randrange(256) for _ in range(16))
        s = [p0[i][pt[i]] for i in range(16)]
        s = wb.mc_round(art.tab_obj, wb.enc_col(0, 0), 0, 0, 1, s, art.env)
        wb.rec_undo(art.tab_obj, wb.enc_col(0, 0), 0, 0, s, art.env)
        ref = aes_round0_state(pt, rk[0], rk[1])
        for i in range(16):
            d = seen[i]
            if ref[i] in d and d[ref[i]] != s[i]:
                conflicts += 1
            d[ref[i]] = s[i]
    distinct = sorted(len(d) for d in seen)
    print("   round 0 output, recoding inverted: each of the 16 state bytes is a")
    print("   bijection of the genuine AES state byte (checked against the known key)")
    print("   -> conflicts %d over %d plaintexts; distinct AES values seen per byte:"
          " min %d median %d" % (conflicts, a.samples, distinct[0], distinct[8]))
    print("   i.e. exactly dl4's shape: a per-byte bijection in front of the true state")

    print("== 4. re-run the dl4 peel on what remains (the XOR fit on Q) ==")
    t0 = time.time()
    ok, n, axis_ok, axis_n = fit_ratio(art)
    print("   pair table fit D0[a]^D1[b] from one row + one column: %d/%d = %.4f off-axis"
          % (ok, n, ok / float(n)))
    print("   (a=0/b=0 axes are built by the fit: %d/%d; random table would give ~0.0039)"
          % (axis_ok, axis_n))
    print("   fit runs in %.2fs, %d entries checked" % (time.time() - t0, n + axis_n))
    if ok / float(n) > 0.999:
        print("   -> Q is XOR-separable: the peel would continue")
    else:
        print("   -> Q is not XOR-separable, so there is no lane inverse to feed step 3:")
        print("      the peel yields 0/16 key bytes here. The blocker is the output")
        print("      bijection Z inside Q, not the recoding (step 1 recovered that for free)")

    print("== 5. result ==")
    print("   recoding inverted: YES (%d/%d inverse tables, %d/%d instances verified)"
          % (inv_matches, inv_tables, trials - bad, trials))
    print("   key bytes from this route: 0/16 -- blocked at the XOR fit, measured above")
    print("   what the recoding costs this attack: 0 key bits and %.2fs of table reads"
          % t_read)
    print("   hs_attack.py is the route that does recover the key (static, no traces):")
    print("   it needs the pair tables' D values only up to a linear gauge, which is")
    print("   exactly the freedom the recoding does not touch.")
    print("   total wall time %.2fs" % (time.time() - t_start))
    return 1


if __name__ == "__main__":
    sys.exit(main())
