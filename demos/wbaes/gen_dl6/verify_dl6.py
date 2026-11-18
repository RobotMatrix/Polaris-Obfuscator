#!/usr/bin/env python3
"""Independent check of a dl6 table: encrypt with the table bytes and compare to openssl.

Nothing here imports the generator. The round function is re-derived from the table
bytes with wblib's readers (the same ones the attacks use), plus the dl6 layer,
which is applied where the generator applies it: after round 0's recoding has been
undone, before round 1's first lookup.

Layer, per column (`cb` = HY_RKZ_OFF + col * 3072, tables P/U/T 256 entries each):

    y = P[dst][state[dst]]            # undo round 0's output bijection P[0]
    y = IMC(y)                        # = S(pt) ^ d, d = IMC(rk1)
    y = U[dst][y]                     # = S(pt ^ rk0)
    y = MC(y)
    state[dst] = T[dst][y]            # = P[0](y ^ rk1)

usage: python3 verify_dl6.py --table DIR/hy_table.bin --work DIR [--n 8]
"""

import argparse
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "attacks"))
sys.path.insert(0, os.path.join(HERE, "..", "attacks", "residual"))
import reslib as R
import wblib as wb

HY_RKZ_OFF = 70090816          # HY_TABLES + HY_SCHED_BYTES
HY_RKZ_COL = 12 * 256
HY_RKZ_BYTES = 4 * HY_RKZ_COL
VAR_TOTAL = HY_RKZ_OFF + HY_RKZ_BYTES
K_RKZ_P, K_RKZ_U, K_RKZ_T = 168, 184, 188


def aes_mix(y, M):
    """AES MixColumns (M = wb.MC) or its inverse (M = wb.IMC) on one column."""
    t = [0] * 4
    for r in range(4):
        a = 0
        for k in range(4):
            a ^= wb.gmul(y[k], M[r][k])
        t[r] = a
    y[:] = t


def rkz_apply(art, s):
    for col in range(4):
        cb = HY_RKZ_OFF + col * HY_RKZ_COL
        y = [0] * 4
        for j in range(4):
            tag = wb.hy_tag(0, 0, col, K_RKZ_P + j)
            y[j] = art.tab_obj.r8t(cb + j * 256, s[4 * col + j], tag)
        aes_mix(y, wb.IMC)                        # IMC(.)
        for j in range(4):
            tag = wb.hy_tag(0, 0, col, K_RKZ_U + j)
            y[j] = art.tab_obj.r8t(cb + (4 + j) * 256, y[j], tag)
        aes_mix(y, wb.MC)                         # MC(.)
        for j in range(4):
            tag = wb.hy_tag(0, 0, col, K_RKZ_T + j)
            s[4 * col + j] = art.tab_obj.r8t(cb + (8 + j) * 256, y[j], tag)
    return s


def encrypt(art, pt):
    s = [art.p0[i][pt[i]] for i in range(16)]
    for r in range(wb.HY_MC_ROUNDS):
        if r:
            wb.rec_undo(art.tab_obj, wb.enc_col(r - 1, 0), 0, r - 1, s, art.env)
        if r == 1:
            rkz_apply(art, s)
        s = wb.mc_round(art.tab_obj, wb.enc_col(r, 0), r, 0, 1, s, art.env)
    wb.rec_undo(art.tab_obj, wb.enc_col(wb.HY_MC_ROUNDS - 1, 0), 0, wb.HY_MC_ROUNDS - 1,
                s, art.env)
    return bytes(wb.pair_map(art.tab_obj, wb.enc_final(), s, art.env, 0, 9, 1))


def openssl(key, pt):
    return subprocess.run(["openssl", "enc", "-aes-128-ecb", "-K", key.hex(), "-nopad"],
                          input=pt, capture_output=True, check=True).stdout


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--table", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--key", required=True, help="master key of this build, for openssl")
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    a = ap.parse_args(argv)

    art, seed = R.load_variant(a.table, a.work, (a.pagesize, a.ncpu, a.cls), VAR_TOTAL)
    print("table %s (%d B), mask seed 0x%08x, schedule %s"
          % (a.table, len(art.tab), seed, [wb.FAM_NAMES[s] for s in art.schedule]))
    key = bytes.fromhex(a.key)
    pts = [bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")]
    for i in range(a.n):
        pts.append(bytes((7 * i + j * 31 + 5) & 0xFF for j in range(16)))
    bad = 0
    for pt in pts:
        got = encrypt(art, pt)
        want = openssl(key, pt)
        ok = got == want
        bad += 0 if ok else 1
        print("  pt %s -> table %s  openssl %s  %s"
              % (pt.hex(), got.hex(), want.hex(), "OK" if ok else "MISMATCH"))
    print("%d/%d vectors match openssl AES-128-ECB" % (len(pts) - bad, len(pts)))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
