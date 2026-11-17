#!/usr/bin/env python3
"""DCA on wbaes dl4: does the table-ACCESS ADDRESS still leak round-key bytes?

Threat model (instrumented attacker): the adversary runs the shipped binary under a
debugger / Frida-class hook and records, per block encryption, the sequence of
(table offset, access width) pairs. No table contents are read and no mask seed is
needed -- this attack works from addresses alone, which is the
Bos-Hubain-Michiels-Teuwen setting (CHES 2016, ePrint 2015-753).

One extra handicap sits on top of that in dl4: the index->address map is scrambled
(hy_scatter for 64K tables, hy_scatter8 for 256-entry tables). Both maps are keyed
only by (env, tag), and both are inline code in the binary, so the adversary inverts
them: hy_scatter8 is affine mod 256, hy_scatter a 4-round 16-bit Feistel.

Two experiments, in the order a DCA attacker would try them:

  A. classic single-byte CPA: guess one key byte, model S(pt ^ k), correlate against
     the address of the round-0 lane table. Reported: |r| per hypothesis, rank of the
     true byte, and a Monte-Carlo null for the same statistic. The structural fact
     that decides the outcome is printed too: the index is P0(pt), a public bijection
     of the plaintext byte, so the address has zero key dependence.

  B. exact-index recovery + 4-byte meet-in-the-middle: dl4's 256-entry boundary
     permutation tables are indexed by the round output *before* AddRoundKey,
     MC(row,:) . S(pt ^ rk0). Their address inverts (affine) to that byte exactly, so
     one trace is one 8-bit equation in four key bytes; meet-in-the-middle over
     (k0,k1) x (k2,k3) with a signature over a few traces solves each column.

usage:
  python3 dca_attack.py                     # traces from the Python model (no build)
  python3 dca_attack.py --traces t.bin      # traces from trace_harness/ (real runtime)
  python3 dca_attack.py --n-traces 16 --b-traces 6
"""

import argparse
import os
import random
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


def hw(v):
    return bin(v).count("1")


def pearson(x, y):
    n = len(x)
    mx = sum(x) / n
    my = sum(y) / n
    sxy = sum((a - mx) * (b - my) for a, b in zip(x, y))
    sxx = sum((a - mx) ** 2 for a in x)
    syy = sum((b - my) ** 2 for b in y)
    if sxx == 0 or syy == 0:
        return 0.0
    return sxy / (sxx * syy) ** 0.5


# ---------------------------------------------------------------------------
def build_traces(tab, p0, env, n, src):
    """Return (address sequences, plaintexts). Model traces drop the logical index
    the model happens to know, so the attack sees exactly what a hook would."""
    t0 = time.time()
    if src:
        traces, pts = wb.read_traces(src)
        traces = [[r[0] for r in tr] for tr in traces]  # addresses only
        if n and n < len(traces):
            traces, pts = traces[:n], pts[:n]
    else:
        pts = wb.prng_pts(n)
        traces = []
        for pt in pts:
            rec = []
            wb.encrypt(tab, p0, pt, env, log=lambda a, l, w: rec.append(a))
            traces.append(rec)
    return [list(tr) for tr in traces], pts, time.time() - t0


# ---------------------------------------------------------------------------
def lane_slot_index(addrs, col, k, env):
    """Logical index of the round-0 lane table (col,k), recovered from addresses."""
    base = wb.enc_col(0, col) + k * wb.W1024
    tag = wb.hy_tag(0, 0, col, wb.K_T32_W + k)
    out = []
    for tr in addrs:
        hit = [a for a in tr if base <= a < base + wb.W1024]
        if not hit:
            raise SystemExit("lane slot (col %d, k %d) not in trace" % (col, k))
        out.append(wb.hy_scatter8_inv(((hit[0] - base) // 4) & 0xFF, env, tag))
    return out


def null_max_corr(obs, pts, src, reps=10):
    """Same statistic with 256 random 8-bit functions of the plaintext byte as
    hypotheses: separates a real leak from the maximum of 256 correlates."""
    rnd = random.Random(7)
    best_of_rep = []
    for _ in range(reps):
        best = 0.0
        for _g in range(256):
            f = [rnd.randrange(256) for _ in range(256)]
            r = abs(pearson([hw(f[pt[src]]) for pt in pts], obs))
            if r > best:
                best = r
        best_of_rep.append(best)
    return sum(best_of_rep) / len(best_of_rep)


def experiment_a(addrs, pts, env, key, p0):
    print("== A. single-byte CPA against the round-0 lane-table address ==")
    print("   col k src  best_g |r|   |r|(true)  rank/256  index==P0(pt)")
    worst = 0.0
    ranks = []
    free_all = 0
    first = None
    for col in range(4):
        for k in range(4):
            src = wb.sr_src(k + 4 * col)
            idx = lane_slot_index(addrs, col, k, env)
            obs = [hw(v) for v in idx]
            scores = [abs(pearson([hw(wb.SBOX[pt[src] ^ g]) for pt in pts], obs))
                      for g in range(256)]
            bg = max(range(256), key=lambda g: scores[g])
            truth = key[src]
            rank = 1 + sum(1 for s in scores if s > scores[truth])
            free = sum(1 for pt, v in zip(pts, idx) if v == p0[src][pt[src]])
            free_all += (free == len(pts))
            worst = max(worst, scores[bg])
            ranks.append(rank)
            print("   %3d %d %3d  %3d    %.3f  %.3f     %4d      %d/%d"
                  % (col, k, src, bg, scores[bg], scores[truth], rank, free, len(pts)))
            if first is None:
                first = obs
    null = null_max_corr(first, pts, wb.sr_src(0))
    print("   max |r| over 16 slots x 256 hypotheses: %.3f" % worst)
    print("   Monte-Carlo null, same statistic (256 random models, 10 reps): %.3f" % null)
    print("   rank of the true key byte: min %d, median %d, max %d"
          % (min(ranks), sorted(ranks)[len(ranks) // 2], max(ranks)))
    print("   slots whose index is bit-exactly P0(pt) on every trace: %d/16" % free_all)
    print("   -> the lane-table address carries no key: the index is a public bijection")
    print("      of the plaintext byte, so all 256 hypotheses fit equally well. Classic")
    print("      1-byte DCA is closed here by keeping rk0 inside the table *value*.")


# ---------------------------------------------------------------------------
def boundary_index(addrs, col, row, env, rb):
    """Round-0 boundary table: 256 entries, index = plain MixColumns row output."""
    base = wb.enc_col(0, col) + wb.T32_R_OFF + row * wb.W256   # same slot for F1/F2/F3
    tag = wb.hy_tag(0, 0, col, rb + row)
    out = []
    for tr in addrs:
        hit = [a for a in tr if base <= a < base + wb.W256]
        if not hit:
            raise SystemExit("boundary slot (col %d row %d) not in trace" % (col, row))
        out.append(wb.hy_scatter8_inv(hit[0] - base, env, tag))
    return out


def recover_column(addrs, pts, col, row, env, sig_traces, rb):
    """MITM over (k_a,k_b) x (k_c,k_d): u = XOR_k MC[row][k] . S(pt_k ^ key_k)."""
    u = boundary_index(addrs, col, row, env, rb)
    srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
    m = [wb.MC[row][k] for k in range(4)]
    v = [[[MUL[m[k]][wb.SBOX[pt[srcs[k]] ^ g]] for pt in pts] for g in range(256)]
         for k in range(4)]
    nsig = min(sig_traces, len(pts) - 1)
    left = {}
    for g2 in range(256):
        v2 = v[2][g2]
        for g3 in range(256):
            v3 = v[3][g3]
            left.setdefault(tuple(v2[t] ^ v3[t] for t in range(nsig)), []).append((g2, g3))
    cands = []
    for g0 in range(256):
        v0 = v[0][g0]
        for g1 in range(256):
            v1 = v[1][g1]
            sig = tuple(u[t] ^ v0[t] ^ v1[t] for t in range(nsig))
            for (g2, g3) in left.get(sig, ()):
                v2, v3 = v[2][g2], v[3][g3]
                if all(u[t] == v0[t] ^ v1[t] ^ v2[t] ^ v3[t]
                       for t in range(nsig, len(pts))):
                    cands.append((g0, g1, g2, g3))
    return srcs, cands


def experiment_b(addrs, pts, env, key, rb, row=0, sig_traces=3, quiet=False):
    """One run with a fixed guess for round 0's family tag. Returns (key bytes, counts)."""
    t0 = time.time()
    rec = {}
    counts = []
    for col in range(4):
        srcs, cands = recover_column(addrs, pts, col, row, env, sig_traces, rb)
        counts.append(len(cands))
        if not quiet:
            print("   col %d: %2d candidate 4-byte key(s) for key bytes %s  [%.2fs]"
                  % (col, len(cands), [hex(key[s]) for s in srcs], time.time() - t0))
        if len(cands) == 1:
            for k, s in enumerate(srcs):
                rec[s] = cands[0][k]
        elif not quiet:
            for c in cands[:5]:
                print("       %s" % [hex(x) for x in c])
    return rec, counts, time.time() - t0


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--binary", default=wb.DEFAULT_BIN)
    ap.add_argument("--traces", help="trace file written by trace_harness/")
    ap.add_argument("--n-traces", type=int, default=64,
                    help="traces recorded (A uses all, B needs about 8)")
    ap.add_argument("--b-traces", type=int, default=8, help="traces given to experiment B")
    ap.add_argument("--sig-traces", type=int, default=3,
                    help="traces hashed for the MITM signature; the rest verify")
    ap.add_argument("--row", type=int, default=0, help="MixColumns row used by B")
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--seed", type=lambda s: int(s, 0), help="mask seed (found if omitted)")
    ap.add_argument("--cache", default=None, help="cache the unmasked table here")
    ap.add_argument("--skip-a", action="store_true")
    ap.add_argument("--skip-b", action="store_true")
    a = ap.parse_args(argv)

    env = wb.hy_env_mix(a.pagesize, a.ncpu, a.cls)
    print("binary : %s" % a.binary)
    print("env    : pagesize=%d ncpu=%d cls=%d -> 0x%08x" % (a.pagesize, a.ncpu, a.cls, env))

    t0 = time.time()
    seed = a.seed
    if seed is None:
        tab_off, tab_size = wb.find_section(a.binary, "__hytab")
        seed, frag_off, tried = wb.find_mask_seed(a.binary, tab_off, tab_size)
        print("mask seed: 0x%08x (%d candidate 4-word XORs in __const, %.2fs)"
              % (seed, tried, time.time() - t0))
    data = open(a.binary, "rb").read()
    p0 = wb.find_input_bijection(data)[0][1]
    tab = None
    if a.traces:
        print("table  : not read -- with a trace file the attack needs no table bytes")
    else:
        t0 = time.time()
        tab_b = wb.load_plain_table(a.binary, seed=seed, cache=a.cache)
        tab = wb.Tab(tab_b, env)
        sched = [tab_b[wb.SCHED_OFF + r] for r in range(wb.HY_MC_ROUNDS)]
        print("table  : %d bytes unmasked in %.2fs (needed to model traces)"
              % (len(tab_b), time.time() - t0))
        print("enc schedule (sealed block): %s"
              % [wb.FAM_NAMES[s] for s in sched])

    addrs, pts, dt = build_traces(tab, p0, env, a.n_traces, a.traces)
    print("traces : %d x %d accesses, %s, %.2fs"
          % (len(addrs), len(addrs[0]),
             "harness file" if a.traces else "python model", dt))
    if tab is not None:
        print("         pt[0]=%s -> table-network ciphertext %s"
              % (pts[0].hex(), wb.encrypt(tab, p0, pts[0], env).hex()))

    key = bytes.fromhex(PUBLISHED_KEY)
    if not a.skip_a:
        experiment_a(addrs, pts, env, key, p0)
    if a.skip_b:
        return 0
    n_b = min(a.b_traces, len(addrs))
    print("== B. round-0 boundary-table address -> 4-byte meet-in-the-middle ==")
    print("   the 256-entry boundary table is indexed by MC(%d,:) . S(pt ^ rk0), the round"
          % a.row)
    print("   output before AddRoundKey, recovered exactly from the affine scatter. The")
    print("   schedule block is sealed, so the attacker tries each family's table tag:")
    rec, counts, tb, win = None, None, 0.0, None
    for fam, rb in ((wb.FAM_T32, wb.K_T32_R), (wb.FAM_T8, wb.K_T8_R),
                    (wb.FAM_T32K, wb.K_T32K_R)):
        r, c, t = experiment_b(addrs[:n_b], pts[:n_b], env, key, rb, a.row,
                               a.sig_traces, quiet=True)
        print("     tag %-3s (kind %3d): candidates per column %s -> %s  [%.2fs]"
              % (wb.FAM_NAMES[fam], rb, c,
                 "16/16 key bytes" if len(r) == 16 else "%d/16 key bytes" % len(r), t))
        if rec is None or len(r) > len(rec):
            rec, counts, tb, win = r, c, t, rb
        if len(r) == 16:
            break
    if win is not None:
        print("   per-column detail for the winning tag (kind %d):" % win)
        experiment_b(addrs[:n_b], pts[:n_b], env, key, win, a.row, a.sig_traces)
    print("== recovered key ==")
    if len(rec) != 16:
        print("   incomplete: %d/16 bytes" % len(rec))
        return 1
    rk = bytes(rec[i] for i in range(16))
    print("   %s   (%d address traces, no table bytes)" % (rk.hex(), n_b))
    ct = wb.aes_encrypt(bytes.fromhex(CHALLENGE_PT), rk)
    print("   AES-128(6bc1...172a) = %s" % ct.hex())
    print("   shipped ciphertext    = %s" % CHALLENGE_CT)
    print("   reproduces the shipped ciphertext: %s"
          % ("YES" if ct.hex() == CHALLENGE_CT else "NO"))
    print("   equals the published dl4 key: %s"
          % ("YES" if rk.hex() == PUBLISHED_KEY else "NO"))
    print("experiment B: candidates per column %s with %d traces, %.2fs"
          % (counts, n_b, tb))
    return 0 if ct.hex() == CHALLENGE_CT else 1


if __name__ == "__main__":
    sys.exit(main())
