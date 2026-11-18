#!/usr/bin/env python3
"""What a smarter attacker does about the dummy reads, and whether it is enough.

Three counters, all measured on recorded traces:

  1. sort      re-align by address: take the lowest address inside the table. Needs
               no secret, so it is the first thing anyone tries.
  2. filter    keep only the traces where the table is hit once. A real block hits
               each 64K boundary table exactly once, so the second hit is noise by
               construction. The yield of that filter is the whole cost of the
               randomisation for this attack.
  3. relabel   once the key is known -- it falls out of the clean subset in a few
               seconds -- rebuild the unknown bijections Zl/Zr from the clean
               traces and use them to decide which candidate is real in the
               ambiguous traces. Nothing is discarded.

--truth is a K=0 trace file recorded over the same plaintexts; it is only used to
score sort/relabel, never to solve anything. Accuracy of 100% without it means
nothing, so the scoring is kept explicit.

usage:
  python3 rnd/realign.py --traces /tmp/wbaes-rnd/k16/rnd_k16_s1_traces.bin \
                         --truth  /tmp/wbaes-rnd/k0/rnd_k0_s0_traces.bin
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
ATK = os.path.join(REPO, "demos", "wbaes", "attacks")
sys.path.insert(0, ATK)
sys.path.insert(0, os.path.join(ATK, "residual"))
import wblib as wb
import reslib as R
from consistency_attack import collision_pairs, solve_half

TS = (32, 64, 128, 256, 512, 1024, 4096)
ROW = 0


def candidates(traces, env, row=ROW):
    """cand[(col, half)][trace] = byte halves recovered from that one table."""
    atr = [[x[0] for x in t] for t in traces]
    cand = {}
    for col in range(4):
        base = wb.enc_col(0, col) + wb.BDY_OFF + row * wb.N
        tag = wb.hy_tag(0, 0, col, wb.K_BDY_T32 + row)
        for half in (0, 1):
            cand[(col, half)] = [
                [wb.hy_scatter_inv(a - base, env, tag) >> (8 * half) & 0xFF
                 for a in tr if base <= a < base + wb.N]
                for tr in atr
            ]
    return cand, atr


def solve_from(cand, pts, T=None, cap=2000):
    """The shipped MITM on one candidate set, using the single-hit traces only."""
    rec, counts = {}, []
    m = wb.MC[ROW]
    for col in range(4):
        srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
        for half in (0, 1):
            lst = cand[(col, half)]
            idx = [i for i, v in enumerate(lst) if len(v) == 1]
            if T:
                idx = idx[:T]
            obs = [lst[i][0] for i in idx]
            p = [pts[i] for i in idx]
            pairs = collision_pairs(obs, cap) if obs else []
            hits = (solve_half(p, pairs, srcs[2 * half], srcs[2 * half + 1],
                               m[2 * half], m[2 * half + 1]) if pairs else [])
            counts.append(len(hits))
            if len(hits) == 1:
                rec[srcs[2 * half]] = hits[0][0]
                rec[srcs[2 * half + 1]] = hits[0][1]
    return rec, counts


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--truth", required=True, help="K=0 traces over the same plaintexts (scoring only)")
    ap.add_argument("--key", default=R.CHALLENGE_KEY)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    env = wb.hy_env_mix(*wb.DEFAULT_ENV)
    key = bytes.fromhex(a.key)

    traces, pts = wb.read_traces(a.traces)
    ttruth, _ = wb.read_traces(a.truth)
    cand, atr = candidates(traces, env)
    truth = [set(x[0] for x in t) for t in ttruth]
    out = {"traces": a.traces, "n": len(traces)}

    # ---- 1. sort by address --------------------------------------------------
    multi = wrong_sorted = 0
    for (col, half), lst in cand.items():
        base = wb.enc_col(0, col) + wb.BDY_OFF + ROW * wb.N
        tag = wb.hy_tag(0, 0, col, wb.K_BDY_T32 + ROW)
        for i, v in enumerate(lst):
            if len(v) > 1:
                multi += 1
                hits = [x for x in atr[i] if base <= x < base + wb.N]
                sl = sorted(wb.hy_scatter_inv(x - base, env, tag) >> (8 * half) & 0xFF for x in hits)
                if sl[0] != v[0]:
                    wrong_sorted += 1
    out["sort"] = {"ambiguous_table_reads": multi, "sorted_first_wrong": wrong_sorted,
                   "sorted_first_wrong_frac": wrong_sorted / max(multi, 1)}

    # ---- 2. clean-subset yield ----------------------------------------------
    yields = {k: sum(1 for v in lst if len(v) == 1) / len(lst) for k, lst in cand.items()}
    out["yield"] = {"per_half": sorted(yields.values()), "min": min(yields.values()),
                    "max": max(yields.values()), "mean": sum(yields.values()) / len(yields)}

    # ---- 3. bootstrap: key from the clean subset ----------------------------
    rec, counts = solve_from(cand, pts)
    if len(rec) != 16:
        out["bootstrap"] = {"key": None, "bytes": len(rec), "per_half": counts}
        print(json.dumps(out, indent=1))
        if a.out:
            json.dump(out, open(a.out, "w"), indent=1)
        return 1
    rk = bytes(rec[i] for i in range(16))
    out["bootstrap"] = {"key": rk.hex(), "ok": rk == key,
                        "halves_unique": sum(1 for c in counts if c == 1)}

    # ---- 4. relabel the ambiguous traces with the recovered Z maps -----------
    m = wb.MC[ROW]
    relab = {}
    total_amb = match1 = correct = unseen = 0
    for col in range(4):
        srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
        for half in (0, 1):
            lst = cand[(col, half)]
            base = wb.enc_col(0, col) + wb.BDY_OFF + ROW * wb.N
            tag = wb.hy_tag(0, 0, col, wb.K_BDY_T32 + ROW)

            def x_of(i):
                return R.MUL[m[2 * half]][wb.SBOX[pts[i][srcs[2 * half]] ^ rk[srcs[2 * half]]]] ^ \
                       R.MUL[m[2 * half + 1]][wb.SBOX[pts[i][srcs[2 * half + 1]] ^ rk[srcs[2 * half + 1]]]]

            z = {}
            for i, v in enumerate(lst):
                if len(v) == 1:
                    z.setdefault(x_of(i), v[0])
            obs = []
            for i, v in enumerate(lst):
                if len(v) == 1:
                    obs.append(v[0])
                    continue
                total_amb += 1
                x = x_of(i)
                if x not in z:
                    unseen += 1
                    obs.append(v[0])
                    continue
                pick = [u for u in v if u == z[x]]
                if len(pick) != 1:
                    obs.append(v[0])
                    continue
                match1 += 1
                obs.append(pick[0])
                hits = [q for q in atr[i] if base <= q < base + wb.N]
                real = [wb.hy_scatter_inv(q - base, env, tag) >> (8 * half) & 0xFF
                        for q in hits if q in truth[i]]
                if real and pick[0] == real[0]:
                    correct += 1
            relab[(col, half)] = obs
    out["relabel"] = {"ambiguous_reads": total_amb, "unique_match": match1,
                      "picked_correctly": correct, "x_unseen": unseen,
                      "accuracy": correct / max(match1, 1)}

    # ---- 5. the curve again, on the relabelled full trace set ---------------
    curve = {}
    for T in TS:
        if T > len(pts):
            continue
        rec2, counts2 = {}, []
        for col in range(4):
            srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
            for half in (0, 1):
                obs = relab[(col, half)][:T]
                pairs = collision_pairs(obs, 2000)
                hits = solve_half(pts[:T], pairs, srcs[2 * half], srcs[2 * half + 1],
                                  m[2 * half], m[2 * half + 1]) if pairs else []
                counts2.append(len(hits))
                if len(hits) == 1:
                    rec2[srcs[2 * half]] = hits[0][0]
                    rec2[srcs[2 * half + 1]] = hits[0][1]
        ok = len(rec2) == 16 and bytes(rec2[i] for i in range(16)) == key
        curve[T] = {"unique": sum(1 for c in counts2 if c == 1),
                    "empty": sum(1 for c in counts2 if c == 0),
                    "widest": max(counts2), "key_ok": ok}
        print("%5d traces relabelled: unique %d/8 empty %d widest %d key %s"
              % (T, curve[T]["unique"], curve[T]["empty"], curve[T]["widest"],
                 "OK" if ok else "-"))
    out["curve_relabelled"] = curve
    print(json.dumps({k: v for k, v in out.items() if k != "curve_relabelled"}, indent=1))
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
