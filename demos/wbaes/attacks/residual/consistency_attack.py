#!/usr/bin/env python3
"""Residual attack (b): consistency over the unknown boundary bijections.

dl5 replaced the round-boundary permutation (256 entries, byte index) with a 64K
two-byte table, and measured that the recovered index is still a *function* of the
two pair sums with 0 conflicts -- but 0/8 traces where it equals the sum, i.e. an
unknown bijection Zl/Zr sits in between. dca_attack.py could not use that, and
WB-DESIGN-V2.md 12.4 item 2 records the follow-up (a consistency statistic needing
~2^12 traces) as unimplemented.

This script implements it, from addresses only:

  recovered index half   u_t = Zl( x_t ),   x_t = MC[row][0].S(pt0^k0) ^ MC[row][1].S(pt1^k1)
  recovered index half   v_t = Zr( y_t ),   y_t = MC[row][2].S(pt2^k2) ^ MC[row][3].S(pt3^k3)

Zl/Zr are unknown but *fixed* bijections, so for any two traces with u_t == u_t' the
pair sums must be equal. With 2^12 traces u takes each of its 256 values ~16 times,
which gives thousands of collision pairs = thousands of byte equations in (k0,k1).
Each hypothesis (k0,k1) yields a signature over those pairs

    sig_k0 = ( m0 . (S(pt0_a^k0) ^ S(pt0_b^k0)) ) over pairs,  sig_k1 likewise

and the true pair is the one whose two signatures are *equal* (that is exactly
x_t == x_t' written per lane). Hashing 256 signatures and intersecting is a
meet-in-the-middle, so the 2^32 candidate space per column half collapses to
2 x 256 signature evaluations.

usage:
  python3 consistency_attack.py                       # builds 4096 real traces, attacks
  python3 consistency_attack.py --traces /tmp/t/dl4_traces.bin
  python3 consistency_attack.py --traces ... --skip-curve
"""

import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reslib as R
import wblib as wb

TRACE_BUILDER = os.path.join(os.path.dirname(HERE), "trace_harness", "build_traces.py")


def build_traces(n, work, binary):
    cmd = [sys.executable, TRACE_BUILDER, "--n", str(n), "--work", work, "--binary", binary]
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("trace build failed:\n%s\n%s" % (out.stdout, out.stderr))
    return os.path.join(work, "dl4_traces.bin")


def collision_pairs(u, cap):
    """Index pairs (i,j) with u_i == u_j; capped deterministically."""
    groups = {}
    for i, val in enumerate(u):
        groups.setdefault(val, []).append(i)
    pairs = []
    for val in sorted(groups):
        lst = groups[val]
        for a in range(len(lst)):
            for b in range(a + 1, len(lst)):
                pairs.append((lst[a], lst[b]))
    pairs.sort()
    if cap and len(pairs) > cap:
        step = len(pairs) // cap
        pairs = pairs[::step][:cap]
    return pairs


def signature(pts, pairs, src, g, m):
    sm = R.MUL[m]
    sb = wb.SBOX
    return bytes(sm[sb[pts[a][src] ^ g] ^ sb[pts[b][src] ^ g]] for a, b in pairs)


def solve_half(pts, pairs, src0, src1, m0, m1):
    """Meet-in-the-middle on the two key bytes of one index half."""
    sigs = {}
    for g in range(256):
        sigs.setdefault(signature(pts, pairs, src0, g, m0), []).append(g)
    hits = []
    for g in range(256):
        h = sigs.get(signature(pts, pairs, src1, g, m1))
        if h:
            hits.extend((a, g) for a in h)
    return hits


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--binary", default=wb.DEFAULT_BIN)
    ap.add_argument("--traces", default=None)
    ap.add_argument("--n", type=int, default=4096, help="traces to build when --traces is absent")
    ap.add_argument("--work", default="/tmp/wbaes-res/traces")
    ap.add_argument("--row", type=int, default=0)
    ap.add_argument("--cap", type=int, default=2000, help="collision pairs used (0 = all)")
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--key", default=R.CHALLENGE_KEY)
    ap.add_argument("--skip-curve", action="store_true")
    a = ap.parse_args(argv)

    env = wb.hy_env_mix(a.pagesize, a.ncpu, a.cls)
    t_start = time.time()
    tpath = a.traces
    if not tpath:
        print("building %d real traces with trace_harness (no demos/wbaes file is touched)"
              % a.n)
        os.makedirs(a.work, exist_ok=True)
        tpath = build_traces(a.n, a.work, a.binary)
    addrs, pts = R.trace_addresses(tpath)
    print("traces : %s" % tpath)
    print("         %d traces x %d accesses, %d plaintexts, load %.2fs"
          % (len(addrs), len(addrs[0]), len(pts), time.time() - t_start))
    key = bytes.fromhex(a.key)

    print("== 1. what the recovered index is (row %d, round 0, family F1) ==" % a.row)
    t0 = time.time()
    halves = {}
    for col in range(4):
        u, v = R.boundary_halves(env, addrs, col, a.row)
        halves[col] = (u, v)
    print("     boundary index halves inverted from addresses (16-bit Feistel): %.2fs"
          % (time.time() - t0))
    for col in range(4):
        u, v = halves[col]
        m = wb.MC[a.row]
        srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
        left = []
        right = []
        for pt in pts:
            left.append(R.MUL[m[0]][wb.SBOX[pt[srcs[0]] ^ key[srcs[0]]]] ^
                        R.MUL[m[1]][wb.SBOX[pt[srcs[1]] ^ key[srcs[1]]]])
            right.append(R.MUL[m[2]][wb.SBOX[pt[srcs[2]] ^ key[srcs[2]]]] ^
                         R.MUL[m[3]][wb.SBOX[pt[srcs[3]] ^ key[srcs[3]]]])
        cl = sum(1 for x, y in zip(left, u) if x == y)
        cf = sum(1 for x, y in zip(right, v) if x == y)
        seen = {}
        conf = 0
        for x, y in zip(left, u):
            if x in seen and seen[x] != y:
                conf += 1
            seen[x] = y
        print("     col %d: u is a function of the left pair sum (conflicts %d), equals it"
              " on %d/%d; v likewise %d/%d (distinct u values %d)"
              % (col, conf, cl, len(pts), cf, len(pts), len(set(u))))

    print("== 2. agreement over collision pairs (unknown bijection, no key guessing on Z) ==")
    t0 = time.time()
    rec = {}
    all_counts = []
    for col in range(4):
        u, v = halves[col]
        srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
        m = wb.MC[a.row]
        for half, obs in ((0, u), (1, v)):
            pairs = collision_pairs(obs, a.cap)
            s0, s1 = srcs[2 * half], srcs[2 * half + 1]
            hits = solve_half(pts, pairs, s0, s1, m[2 * half], m[2 * half + 1])
            all_counts.append(len(hits))
            print("     col %d half %d: %5d collision pairs -> %d candidate 2-byte key(s)"
                  "  %s   [%.2fs]"
                  % (col, half, len(pairs), len(hits),
                     [hex(h[0]) + hex(h[1]) for h in hits[:3]], time.time() - t0))
            if len(hits) == 1:
                rec[s0] = hits[0][0]
                rec[s1] = hits[0][1]
    t_solve = time.time() - t0

    print("== 3. trace-count curve, all 8 halves ==")
    if not a.skip_curve:
        m = wb.MC[a.row]
        for T in (32, 64, 128, 256, 512, 1024, 4096):
            if T > len(addrs):
                continue
            counts = []
            pair_counts = []
            for col in range(4):
                srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
                for half in (0, 1):
                    obs = halves[col][half]
                    pairs = collision_pairs(obs[:T], a.cap)
                    pair_counts.append(len(pairs))
                    hits = (solve_half(pts[:T], pairs, srcs[2 * half], srcs[2 * half + 1],
                                       m[2 * half], m[2 * half + 1]) if pairs else [])
                    counts.append(len(hits))
            print("     %5d traces: %d..%d collision pairs/half -> halves with exactly 1"
                  " candidate: %d/8, widest %d, empty %d"
                  % (T, min(pair_counts), max(pair_counts),
                     sum(1 for c in counts if c == 1), max(counts),
                     sum(1 for c in counts if c == 0)))

    print("== 4. result ==")
    if len(rec) != 16:
        print("   incomplete: %d/16 key bytes" % len(rec))
        return 1
    rk = bytes(rec[i] for i in range(16))
    ct = wb.aes_encrypt(bytes.fromhex(R.CHALLENGE_PT), rk)
    print("   recovered key: %s" % rk.hex())
    print("   AES-128(%s) = %s" % (R.CHALLENGE_PT, ct.hex()))
    print("   reproduces the shipped ciphertext: %s"
          % ("YES" if ct.hex() == R.CHALLENGE_CT else "NO"))
    print("   equals the published key: %s" % ("YES" if rk.hex() == a.key else "NO"))
    print("   traces used: %d; candidate 2-byte sets per half: %s (max %d)"
          % (len(addrs), all_counts, max(all_counts)))
    print("   MITM cost: 512 signature evaluations per half, %d halves, %.2fs;"
          " %.2fs end to end" % (8, t_solve, time.time() - t_start))
    return 0 if ct.hex() == R.CHALLENGE_CT else 1


if __name__ == "__main__":
    sys.exit(main())
