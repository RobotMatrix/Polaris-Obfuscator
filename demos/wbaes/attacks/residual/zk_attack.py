#!/usr/bin/env python3
"""Experiment: does moving rk0 out of the round-0 lane tables and into the output
bijection buy anything?

The variant (built in /tmp from a copy of gen_hybrid.cpp + wbaes_hybrid.h) keeps
every shipped offset and every shipped table shape, and changes exactly two things:

  * round 0's lane tables lose rk0: they compute MC(row,:) . S(pt) instead of
    MC(row,:) . S(pt ^ rk0), i.e. the input side is now key-free;
  * a new 4x4-byte layer Z_k sits between the round-0 boundary and the 32-bit
    recoding, built from four 256-entry tables per byte

        Z_k = P0 . MC . S . sigma_rk0 . S^-1 . sigma_d . MC^-1 . P0^-1,  d = MC^-1 rk1

    (P0^-1, S^-1.sigma_d, S.sigma_rk0, P0.sigma_rk1), with MC^-1/MC in code,
    so that the ciphertext is bit-identical to the shipped one.

What this script measures
-------------------------
1. the shipped gauge-invariant key test (reslib.round0_peel, i.e. exactly what
   hs_attack.py runs) on the variant: the lane tables are key-free, so the only
   candidate for every byte is g = 0 -> hs_attack returns the all-zero key;
2. the new, cheaper test the variant hands over: the Z_k tables are byte-slice
   tables whose shape is forced by the round function, and two of them are a
   public-shaped map composed with one byte of round key:

        T2[x] = S(x ^ rk0[src])        ->  rk0 = S^-1(T2[x]) ^ x    (256 tests)
        T3[x] = P0(x ^ rk1[dst])       ->  rk1 = x ^ P0^-1(T3[x])   (256 tests)

   both recovered here from table bytes alone, no traces, no algebra;
3. the verification: AES-128(pt, rk0) == the shipped ciphertext, and rk1 == the
   key schedule's round-1 key.

usage:
  python3 zk_attack.py --table /tmp/wbaes-zkey/zk/work/zk_table.bin --work /tmp/wbaes-zkey/zk
"""

import argparse
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reslib as R
import wblib as wb

# ---- the variant's layout (from the patched wbaes_hybrid.h copy) ------------
ZK_OFF = 70090816          # HY_TABLES + HY_SCHED_BYTES
ZK_COL = 16 * 256          # four 4-table groups per column
ZK_BYTES = 4 * ZK_COL
VAR_TOTAL = ZK_OFF + ZK_BYTES
K_ZK_P0I, K_ZK_SI, K_ZK_S, K_ZK_P0 = 168, 172, 176, 180

# The published challenge pair this variant was generated for. These are spelled
# out rather than taken from reslib, whose CHALLENGE_* constants follow the
# current shipped generation (a rotated key), not this experiment's artifact.
CHALLENGE_KEY = "46f6abe52990556a6713141f65fed9a5"
CHALLENGE_PT = "6bc1bee22e409f96e93d7e117393172a"
CHALLENGE_CT = "80aadc09777696c9d492a7e53b3b15b0"

PY_SEAL = R.PY_SEAL


def load_variant(table_path, workdir, env_args=wb.DEFAULT_ENV):
    """Unmask a table written by the patched generator (hy_in.h / hy_seal.h live
    next to the table, exactly as reslib.load_generated expects)."""
    env = wb.hy_env_mix(*env_args)
    masked = open(table_path, "rb").read()
    if len(masked) != VAR_TOTAL:
        raise SystemExit("%s: %d bytes, expected %d" % (table_path, len(masked), VAR_TOTAL))
    in_h = open(os.path.join(workdir, "hy_in.h")).read()
    m = R.PY_IN_H.search(in_h)
    vals = [int(x) for x in re.findall(r"\d+", m.group(1))]
    p0 = [vals[256 * i:256 * (i + 1)] for i in range(16)]
    seal = open(os.path.join(workdir, "hy_seal.h")).read()
    words = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", PY_SEAL.search(seal).group(1))]
    seed = words[0] ^ words[1] ^ words[2] ^ words[3]
    tab = bytearray(masked)
    st = seed
    for i in range(len(tab)):
        st = wb.mask_next(st)
        tab[i] ^= (st >> 24) & 0xFF
    return R.Artifact(bytes(tab), env, p0, table_path, seed), seed


def read_zk(art, col, idx):
    """One 256-entry Z_k table (idx = 0..15) of a column, un-scattered."""
    off = ZK_OFF + col * ZK_COL + idx * 256
    kind = (K_ZK_P0I, K_ZK_SI, K_ZK_S, K_ZK_P0)[idx // 4] + (idx % 4)
    tag = wb.hy_tag(0, 0, col, kind)
    return [art.tab_obj.r8t(off, v, tag) for v in range(256)]


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--table", required=True)
    ap.add_argument("--work", required=True, help="directory holding hy_in.h / hy_seal.h")
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--key", default=CHALLENGE_KEY, help="only used on the verify lines")
    ap.add_argument("--traces", default=None,
                    help="optional trace file: show that the Z_k layer's addresses are key-free")
    a = ap.parse_args(argv)

    t_start = time.time()
    art, seed = R.load_variant(a.table, a.work, (a.pagesize, a.ncpu, a.cls), VAR_TOTAL)
    print("table  : %s (%d B, +%d over the shipped layout)" % (a.table, len(art.tab), ZK_BYTES))
    print("mask seed 0x%08x, schedule enc %s"
          % (seed, [wb.FAM_NAMES[s] for s in art.schedule]))

    print("== 1. the shipped gauge-invariant test (hs_attack's step 2) ==")
    t_unmask = time.time() - t_start
    t0 = time.time()
    res = R.round0_peel(art)
    dt = time.time() - t0
    nc = res["cand"]
    print("   64 byte positions: candidates min %d median %d max %d, %.2fs"
          % (min(nc), sorted(nc)[len(nc) // 2], max(nc), dt))
    print("   distinct candidate values over all positions: %s"
          % sorted({c for (col, k) in res["detail"] for (_r, cs) in res["detail"][(col, k)]
                    for c in cs}))
    decoy = res["key"]
    print("   the test's answer: %s" % (decoy.hex() if decoy else "incomplete"))
    if decoy:
        ct = wb.aes_encrypt(bytes.fromhex(CHALLENGE_PT), decoy)
        print("   AES-128(pt, that key) = %s  (shipped %s) -> %s"
              % (ct.hex(), CHALLENGE_CT, "MATCH" if ct.hex() == CHALLENGE_CT else "not the key"))

    print("== 2. the test the variant hands over: shape of the Z_k tables ==")
    t0 = time.time()
    key = [None] * 16
    rk1 = [None] * 16
    agree0 = agree1 = 0
    total = 0
    for col in range(4):
        for j in range(4):
            dst = j + 4 * col
            src = wb.sr_src(dst)
            t0tab = read_zk(art, col, j)          # P0^-1
            t1tab = read_zk(art, col, 4 + j)      # S^-1 . sigma_d
            t2tab = read_zk(art, col, 8 + j)      # S . sigma_rk0
            t3tab = read_zk(art, col, 12 + j)     # P0 . sigma_rk1
            # rk0: T2 is the AES S-box with a hidden input translation
            c0 = {wb.INV_SBOX[t2tab[x]] ^ x for x in range(256)}
            # rk1: T3 = P0(x ^ rk1) and T0 = P0^-1, so x ^ T0(T3(x)) is constant
            c1 = {x ^ t0tab[t3tab[x]] for x in range(256)}
            agree0 += 1 if len(c0) == 1 else 0
            agree1 += 1 if len(c1) == 1 else 0
            total += 1
            if len(c0) == 1:
                key[src] = c0.pop()
            if len(c1) == 1:
                rk1[dst] = c1.pop()
    print("   (col,byte) positions with a single rk0 candidate: %d/16" % agree0)
    print("   (col,byte) positions with a single rk1 candidate: %d/16" % agree1)
    print("   S^-1(T2[x]) ^ x is constant for all 256 x in %d/%d tables (%.2fs)"
          % (agree0, total, time.time() - t0))
    if None in key:
        print("   incomplete")
        return 1
    rk0 = bytes(key)
    print("   rk0 = %s" % rk0.hex())
    print("   rk1 = %s" % bytes(rk1).hex())
    rk_ref = wb.aes_key_expand(rk0)
    print("   key schedule of rk0 gives rk1 = %s -> %s"
          % (bytes(rk_ref[1]).hex(),
             "MATCH" if bytes(rk_ref[1]) == bytes(rk1) else "no"))

    if a.traces:
        print("== 2b. and the addresses of that layer are key-free ==")
        addrs, pts = R.trace_addresses(a.traces)
        tot = hit = 0
        for col in range(4):
            for j in range(4):
                base = ZK_OFF + col * ZK_COL + (8 + j) * 256
                tag = wb.hy_tag(0, 0, col, K_ZK_S + j)
                src = wb.sr_src(j + 4 * col)
                for tr, pt in zip(addrs, pts):
                    a0 = next((x for x in tr if base <= x < base + 256), None)
                    if a0 is None:
                        continue
                    idx = wb.hy_scatter8_inv((a0 - base) & 0xFF, art.env, tag)
                    tot += 1
                    hit += 1 if idx == pt[src] else 0
        print("   keyed S-box lookups traced: %d; recovered index == pt[src] (i.e. the" % tot)
        print("   index is a public function of the plaintext) on %d of them" % hit)
        print("   -> no address dependence on rk0: the key is in the table *values*,")
        print("      which is why the four committed attacks stay dead")

    print("== 3. verify ==")
    ct = wb.aes_encrypt(bytes.fromhex(CHALLENGE_PT), rk0)
    print("   AES-128(%s) = %s" % (CHALLENGE_PT, ct.hex()))
    print("   shipped ct  = %s" % CHALLENGE_CT)
    print("   reproduces the shipped ciphertext: %s"
          % ("YES" if ct.hex() == CHALLENGE_CT else "NO"))
    print("   equals the published key: %s" % ("YES" if rk0.hex() == a.key else "NO"))
    print("   cost: 2 x 256 table lookups per key byte, 16 bytes; %.2fs total, of which"
          " %.2fs is the one-off 70 MB unmask" % (time.time() - t_start, t_unmask))
    return 0 if ct.hex() == CHALLENGE_CT else 1


if __name__ == "__main__":
    sys.exit(main())
