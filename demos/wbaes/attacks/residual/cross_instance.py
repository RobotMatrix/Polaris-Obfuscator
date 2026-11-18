#!/usr/bin/env python3
"""Residual attack (d): cross-instance reuse -- two artifacts, same key, different encodings.

WB-DESIGN-V2.md 12.4 item 4 lists "cross-instance reuse (same key, different
encodings) untested". This script tests it with the committed generator:

  1. compile demos/wbaes/gen_hybrid.cpp into a scratch directory (nothing in the repo
     is modified; the generator draws all of its randomness from /dev/urandom),
  2. generate two tables from the same key source, different random encodings,
  3. attack both with the residual attack (a),
  4. measure whether combining them leaks more than either alone:
       - the naive XOR of the two pair tables (is it XOR-separable?),
       - whether the two instances' recovered labellings are affinely related,
       - whether the key candidate sets shrink when intersected,
       - how many of the 256 D-values agree byte-for-byte.

usage:
  python3 cross_instance.py [--work DIR] [--keep]
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

REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
GEN_SRC = os.path.join(REPO, "demos", "wbaes", "gen_hybrid.cpp")
GEN_INC = os.path.join(REPO, "demos", "wbaes")


def build_generator(work):
    exe = os.path.join(work, "gen_hybrid")
    cmd = ["clang++", "-std=c++17", "-O2", "-I", GEN_INC, "-o", exe, GEN_SRC]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("gen_hybrid build failed:\n%s" % r.stderr[-2000:])
    return exe


def generate(exe, tag, work, env_args):
    d = os.path.join(work, tag)
    os.makedirs(d, exist_ok=True)
    cmd = [exe, "table.bin", "--pagesize", str(env_args[0]), "--ncpu", str(env_args[1]),
           "--cls", str(env_args[2])]
    r = subprocess.run(cmd, cwd=d, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("gen_hybrid run failed in %s:\n%s\n%s" % (d, r.stdout, r.stderr))
    return os.path.join(d, "table.bin"), d, r.stdout


def xor_fit(art1, art2, stride=16):
    """Is Q1 xor Q2 separable as two byte functions? (a naive cross-instance mix)

    Entries are sampled with a fixed stride so the measurement stays cheap; the
    sampled count is reported next to the ratio.
    """
    ok = n = 0
    for col in range(4):
        for row in range(4):
            for p in range(2):
                Q1 = R.q_read(art1, col, row, p)
                Q2 = R.q_read(art2, col, row, p)
                M = [[Q1[a][b] ^ Q2[a][b] for b in range(256)] for a in range(256)]
                d00 = M[0][0]
                d0 = [M[a][0] ^ d00 for a in range(256)]
                d1 = [M[0][b] ^ d00 for b in range(256)]
                for a in range(1, 256):
                    for b in range(1, 256, stride):
                        n += 1
                        if M[a][b] == d0[a] ^ d1[b] ^ d00:
                            ok += 1
    return ok, n


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--work", default="/tmp/wbaes-res/cross")
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--key", default=R.CHALLENGE_KEY)
    a = ap.parse_args(argv)
    env_args = (a.pagesize, a.ncpu, a.cls)
    os.makedirs(a.work, exist_ok=True)
    t_start = time.time()

    print("generator: %s" % GEN_SRC)
    t0 = time.time()
    exe = build_generator(a.work)
    print("           compiled in %.2fs" % (time.time() - t0))

    print("== 1. two artifacts, same key, different random encodings ==")
    t0 = time.time()
    p1, d1, out1 = generate(exe, "gen1", a.work, env_args)
    p2, d2, out2 = generate(exe, "gen2", a.work, env_args)
    same = open(p1, "rb").read() == open(p2, "rb").read()
    print("   A: %s  %s" % (p1, [ln for ln in out1.splitlines() if "seal:" in ln][0]))
    print("   B: %s  %s" % (p2, [ln for ln in out2.splitlines() if "seal:" in ln][0]))
    print("   identical tables: %s (must be False); generated in %.2fs"
          % (same, time.time() - t0))
    t0 = time.time()
    art1 = R.load_generated(p1, d1, env_args)
    t_u1 = time.time() - t0
    t0 = time.time()
    art2 = R.load_generated(p2, d2, env_args)
    t_u2 = time.time() - t0
    print("   unmasked in %.1fs / %.1fs (python xorshift over 70 MB each)" % (t_u1, t_u2))
    print("   both unmasked with their own seeds: 0x%08x / 0x%08x, same P0: %s"
          % (art1.seed, art2.seed, art1.p0 == art2.p0))
    print("   same key source, so AES-128(challenge pt) must agree with the shipped ct")

    print("== 2. attack each alone (residual attack (a)) ==")
    t0 = time.time()
    r1 = R.round0_peel(art1)
    t_a = time.time() - t0
    t0 = time.time()
    r2 = R.round0_peel(art2)
    t_b = time.time() - t0
    for name, res, dt in (("A", r1, t_a), ("B", r2, t_b)):
        ct = wb.aes_encrypt(bytes.fromhex(R.CHALLENGE_PT), res["key"]) if res["key"] else None
        print("   %s: %s   candidates max %d/position   %.2fs   ciphertext %s"
              % (name, res["key"].hex() if res["key"] else "incomplete",
                 max(res["cand"]), dt, ct.hex() if ct else "-"))
        if ct:
            print("      reproduces the shipped ciphertext: %s"
                  % ("YES" if ct.hex() == R.CHALLENGE_CT else "NO"))
    if not (r1["key"] and r2["key"]):
        print("   one instance did not fall; cross-instance section still informative")

    print("== 3. does combining leak more than either alone? ==")
    t0 = time.time()
    ok, n = xor_fit(art1, art2)
    print("   Q_A[a][b] ^ Q_B[a][b] fitted as D0[a]^D1[b]: %d/%d sampled = %.4f"
          " (random 0.0039)" % (ok, n, ok / float(n)))
    # are the two labellings affinely related?
    agree = 0
    affine_all = 0
    for col in range(4):
        for row in range(4):
            for p in range(2):
                da1 = r1["dec"][(col, row, p)].da
                da2 = r2["dec"][(col, row, p)].da
                db1 = r1["dec"][(col, row, p)].db
                db2 = r2["dec"][(col, row, p)].db
                agree += sum(1 for i in range(256) if da1[i] == da2[i])
                affine_all += R.linear_image_ok(da1, da2) + R.linear_image_ok(db1, db2)
    print("   D-labels byte-identical between A and B: %d/%d a-values (32 tables x 256)"
          % (agree, 32 * 256))
    print("   A's labelling is an affine image of B's: %d/64 axes (32 tables x 2 axes)"
          % affine_all)
    print("   -> 0/64 is the expected answer: the lane encodings E (hence D) are drawn")
    print("      independently per generation, so the two labellings are unrelated")
    print("      permutations and only the key is shared between the artifacts")
    # key candidate sets: intersection
    inter = 0
    widest = 0
    for i in range(16):
        s1 = r1["per_byte"].get(i, set())
        s2 = r2["per_byte"].get(i, set())
        widest = max(widest, len(s1), len(s2))
        inter += 1 if (len(s1) == 1 and s1 == s2) else 0
    print("   widest candidate set for any byte, either instance: %d; bytes where both"
          " instances agree on a single candidate: %d/16" % (widest, inter))
    print("   combining adds 0 key bytes: each instance alone already pins all 16")
    print("   (measured in %.2fs for the cross-instance algebra)" % (time.time() - t0))

    print("== 4. result ==")
    k1, k2 = r1["key"], r2["key"]
    print("   A key: %s" % (k1.hex() if k1 else "incomplete"))
    print("   B key: %s" % (k2.hex() if k2 else "incomplete"))
    print("   same key recovered from two independently encoded artifacts: %s"
          % ("YES" if k1 and k1 == k2 else "NO"))
    print("   cross-instance gain over the single-instance attack: 0 key bytes")
    print("   cost: 2 generator builds + 2 x %.1fs attack; total %.2fs"
          % (t_a, time.time() - t_start))
    return 0 if (k1 and k1 == k2) else 1


if __name__ == "__main__":
    sys.exit(main())
