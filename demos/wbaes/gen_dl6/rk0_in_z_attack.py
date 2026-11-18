#!/usr/bin/env python3
"""Read rk0 / rk1 out of the dl6 round-0 key layer, and time it.

dl6 moves round key 0 out of round 0's S-box input and into the output-side
relabelling, so `hs_attack.py`'s gauge-invariant test - which asks whether a lane
value is an affine image of m.S(pt ^ g) - has nothing keyed left to measure: it
returns 16/16 bytes and they are all zero (section 1, and the run of the unchanged
script in reports/RK0-IN-Z.md).

This script is the test the move hands over. It reads the 12 KiB the layer appended
after the schedule block and classifies every 256-entry table in it by shape:

  * S.sigma_k    T[x] = S(x ^ k)          ->  S^-1(T[x]) ^ x is constant  = k
  * P.sigma_k    T[x] = P(x ^ k), P public ->  x ^ P^-1(T[x]) is constant = k
  * merged U     U[x] = S(S^-1(x ^ d) ^ k) ->  exactly one d makes
                                              S^-1(U[x]) ^ S^-1(x ^ d) constant (= k)
  * P^-1         T[x] = P^-1(x)            ->  a permutation, no keyed shape

P is the round-0 input bijection from hy_in.h (public). The point of the merged
form is to cost the attacker 2^16 candidate (d, k) pairs per byte instead of 2^8;
section 4 measures what that costs, and section 3 shows the cheaper door: the P.sigma
tables give rk1 in 2^8 per byte, and rk1 inverts the AES-128 key schedule to rk0.

usage: python3 rk0_in_z_attack.py --table T --work W [--ct HEX] [--key HEX]
"""

import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "attacks"))
sys.path.insert(0, os.path.join(HERE, "..", "attacks", "residual"))
import reslib as R
import wblib as wb

HY_RKZ_OFF = 70090816           # HY_TOTAL_DL5 = HY_TABLES + HY_SCHED_BYTES
HY_RKZ_COL = 12 * 256
HY_RKZ_BYTES = 4 * HY_RKZ_COL
VAR_TOTAL = HY_RKZ_OFF + HY_RKZ_BYTES
K_P, K_U, K_T = 168, 184, 188   # layer table kinds: P^-1, U, T

RCO = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def invert_key_schedule(rk1):
    """Recover the master key from round key 1 (AES-128), by inverting the schedule."""
    # w[4..7] = rk1, w[i] = w[i-4] ^ f(w[i-1]); f is SubWord(RotWord) ^ rcon for i%4==0
    w = [[0] * 4 for _ in range(8)]
    for i in range(4):
        w[4 + i] = list(rk1[4 * i:4 * i + 4])
    for i in (7, 6, 5, 4):
        if i % 4 == 0:
            prev = w[i - 1]
            t = prev[1:] + prev[:1]
            t = [wb.SBOX[b] for b in t]
            t[0] ^= RCO[i // 4 - 1]
        else:
            t = w[i - 1]
        w[i - 4] = [w[i][k] ^ t[k] for k in range(4)]
    return bytes(b for r in w[:4] for b in r)


def layer_table(art, col, slot):
    """One 256-entry layer table. slot = 0..11 within the column: P (0-3), U (4-7),
    T (8-11); the table kind follows from the slot."""
    off = HY_RKZ_OFF + col * HY_RKZ_COL + slot * 256
    kind = K_P + slot if slot < 4 else (K_U + slot - 4 if slot < 8 else K_T + slot - 8)
    tag = wb.hy_tag(0, 0, col, kind)
    return [art.tab_obj.r8t(off, v, tag) for v in range(256)]


def classify(T, pinv=None):
    """Return (shape, payload, cost) for one 256-entry table.

    pinv is the P^-1 table of the same (column, byte): it is what makes the
    P.sigma shape testable, because P itself is not a table in the artifact - only
    its inverse is, and inverting a 256-entry permutation is free.
    """
    # S.sigma_k
    ks = {wb.INV_SBOX[T[x]] ^ x for x in range(256)}
    if len(ks) == 1:
        return "S.sigma_k", ks.pop(), 256
    # P.sigma_k
    if pinv is not None:
        ks = {x ^ pinv[T[x]] for x in range(256)}
        if len(ks) == 1:
            return "P.sigma_k", ks.pop(), 256
    # merged U: one d such that S^-1(U[x]) ^ S^-1(x ^ d) is constant
    hits = []
    for d in range(256):
        v = wb.INV_SBOX[T[0]] ^ wb.INV_SBOX[d]
        ok = True
        for x in range(1, 256):
            if (wb.INV_SBOX[T[x]] ^ wb.INV_SBOX[x ^ d]) != v:
                ok = False
                break
        if ok:
            hits.append((d, v))
    if len(hits) == 1:
        return "merged U", hits[0], 256 * 256
    if len(set(T)) == 256:
        return "bijection, no keyed shape", None, 256
    return "other", None, 256


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--table", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--key", default=None, help="only used on the verify line")
    ap.add_argument("--ct", default=None, help="the artifact's ciphertext for the test pt")
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    a = ap.parse_args(argv)

    t_start = time.time()
    art, seed = R.load_variant(a.table, a.work, (a.pagesize, a.ncpu, a.cls), VAR_TOTAL)
    t_unmask = time.time() - t_start
    print("table  : %s (%d B: dl5 layout + %d of key layer)"
          % (a.table, len(art.tab), HY_RKZ_BYTES))
    print("mask seed 0x%08x, schedule %s" % (seed, [wb.FAM_NAMES[s] for s in art.schedule]))

    print("== 1. the committed gate: hs_attack's gauge-invariant test ==")
    t0 = time.time()
    res = R.round0_peel(art)
    dt = time.time() - t0
    nc = res["cand"]
    print("   64 byte positions: candidates min %d median %d max %d (%.2fs)"
          % (min(nc), sorted(nc)[len(nc) // 2], max(nc), dt))
    print("   distinct candidates over all positions: %s"
          % sorted({c for (col, k) in res["detail"] for (_r, cs) in res["detail"][(col, k)]
                    for c in cs}))
    decoy = res["key"]
    print("   the test's answer: %s" % (decoy.hex() if decoy else "incomplete"))

    print("== 2. shape scan of the layer: 48 tables of 256 entries ==")
    p0inv = art.p0i
    t0 = time.time()
    found = {"S.sigma_k": [], "P.sigma_k": [], "merged U": []}
    other = 0
    for col in range(4):
        pinv = [layer_table(art, col, j) for j in range(4)]
        for j in range(4):
            for idx in (j, 4 + j, 8 + j):
                T = layer_table(art, col, idx)
                shape, payload, _cost = classify(T, pinv[j])
                if shape in found:
                    found[shape].append((col, idx, payload))
                else:
                    other += 1
    dt = time.time() - t0
    note = {"S.sigma_k": "rk0 byte direct", "P.sigma_k": "a round-key byte direct",
            "merged U": "(d, k) pair, 2^16 to find"}
    for shape in ("S.sigma_k", "P.sigma_k", "merged U"):
        print("   %-10s tables: %2d/48  (%s)" % (shape, len(found[shape]), note[shape]))
    print("   tables with no keyed shape: %d/48" % other)
    print("   classification cost: %.2fs (%d table reads + 12x256..65536 tests each)"
          % (dt, 48 * 256))

    print("== 3. the cheap door: rk1 from the P.sigma tables, then invert the schedule ==")
    t0 = time.time()
    rk1 = [None] * 16
    rk0_direct = [None] * 16
    for col, idx, payload in found["P.sigma_k"]:
        dst = idx % 4 + 4 * col
        rk1[dst] = payload
    for col, idx, payload in found["S.sigma_k"]:
        dst = idx % 4 + 4 * col
        rk0_direct[dst] = payload
    if None in rk1:
        print("   incomplete rk1: %s" % rk1)
        return 1
    key = invert_key_schedule(bytes(rk1))
    dt3 = time.time() - t0
    ref = wb.aes_key_expand(key)
    print("   rk1 = %s  (16/16 bytes, 2 table reads each)" % bytes(rk1).hex())
    print("   key schedule of the inverted rk1 -> rk1 again: %s"
          % ("MATCH" if bytes(ref[1]) == bytes(rk1) else "no"))
    print("   master key = %s   [%.4fs]" % (key.hex(), dt3))

    print("== 4. the merged door: rk0 from U alone (the merge costs the attacker 2^16) ==")
    # Re-scan the 16 U tables on their own, so the timing below is the scan and not
    # the earlier classification pass.
    t0 = time.time()
    rk0_u = [None] * 16
    dseen = {}
    for col in range(4):
        for j in range(4):
            T = layer_table(art, col, 4 + j)
            shape, payload, _c = classify(T)
            if shape != "merged U":
                continue
            dst = j + 4 * col
            d, k = payload
            # U[j] holds S(x ^ rk0[sr_src(dst)]): the key byte belongs to the
            # ShiftRows source position of this output byte, not to dst itself.
            rk0_u[wb.sr_src(dst)] = k
            dseen[dst] = d
    dt4 = time.time() - t0
    print("   (d, k) pairs found for %d/16 bytes in %.1f ms" % (len(found["merged U"]), dt4 * 1e3))
    if None in rk0_u:
        print("   incomplete")
        return 1
    key_u = bytes(rk0_u)
    print("   rk0 from U = %s" % key_u.hex())
    print("   agrees with the P.sigma door: %s" % ("YES" if key_u == key else "NO"))
    # the d the scan found must be IMC(rk1), which is checkable once rk1 is known
    ok = True
    for col in range(4):
        y = [rk1[r + 4 * col] for r in range(4)]
        t = [0] * 4
        for r in range(4):
            acc = 0
            for k2 in range(4):
                acc ^= wb.gmul(y[k2], wb.IMC[r][k2])
            t[r] = acc
        for r in range(4):
            ok = ok and dseen.get(r + 4 * col) == t[r]
    print("   every d the U scan found is IMC(rk1): %s" % ("YES" if ok else "NO"))

    if a.ct:
        want = a.ct.lower()
        for label, k in (("rk1 -> schedule", key), ("U (2^16/byte)", key_u)):
            ct = wb.aes_encrypt(bytes.fromhex(R.CHALLENGE_PT), k)
            print("   AES-128(6bc1bee2..., %s key) = %s  %s"
                  % (label, ct.hex(), "MATCH" if ct.hex() == want else "NO"))
    print("   equals --key: %s" % ("YES" if a.key and key.hex() == a.key else "n/a"))
    print("== 5. cost ==")
    print("   %.2fs total, of which %.2fs is the one-off 70 MB unmask." % (time.time() - t_start, t_unmask))
    print("   the key reads themselves: %.2f ms (rk1 door, 2^8 per byte) / %.2f ms (U door,"
          " 2^16 per byte worst case)." % (dt3 * 1e3, dt4 * 1e3))
    return 0


if __name__ == "__main__":
    sys.exit(main())
