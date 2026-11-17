#!/usr/bin/env python3
"""Addendum sweep (not part of the registered grid): ARX psi family.

ADR-006 option B authorised one implementation/variant round. The registered
grid stays untouched at reports/G1-model; this addendum answers a narrower
question: can a cheaper nonlinear family bring the per-step ratio near the 3x
cap at a window width that is not enumerable?

    run_g1_addendum.py --out reports/G1-model-addendum
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
GAMMA = os.path.join(ROOT, "build", "hsvm_gamma")


def points():
    for w in (32, 48, 64):
        for c in (8, 16):
            for rounds in (4, 8):
                yield dict(w=w, c=c, r_bar=2, rounds=rounds, psi="arx")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=os.path.join(ROOT, "reports",
                                                  "G1-model-addendum"))
    ap.add_argument("--states", type=int, default=128)
    ap.add_argument("--dirs", type=int, default=4)
    ap.add_argument("--seed", type=int, default=12345)
    args = ap.parse_args()

    raw_dir = os.path.join(args.out, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    rows = []
    for p in points():
        name = "w%d_c%d_r%d_arx_%d" % (p["w"], p["c"], p["r_bar"], p["rounds"])
        path = os.path.join(raw_dir, name + ".json")
        cmd = [GAMMA, "--n", "512", "--m", "256", "--w", str(p["w"]),
               "--c", str(p["c"]), "--rbar", str(p["r_bar"]),
               "--rounds", str(p["rounds"]), "--psi", "arx",
               "--seed", str(args.seed), "--states", str(args.states),
               "--dirs", str(args.dirs), "--affine", "exhaustive",
               "--bench", "--out", path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print("skip %s: %s" % (name, res.stderr.strip()), file=sys.stderr)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        rows.append({
            "point": name,
            "params_hash": doc.get("params_hash"),
            "w": p["w"], "c": p["c"], "r_bar": p["r_bar"],
            "rounds": p["rounds"], "psi": p["psi"],
            "gamma_p5": doc["gamma_p5"],
            "gamma_min": doc["gamma_min"],
            "affine_nonaffine": doc["affine_nonaffine"],
            "instructions": doc["instructions"],
            "step_cost_ratio": doc["step_cost_ratio"],
            "bench_model_ns": doc["bench_model_ns"],
            "bench_plain_ns": doc["bench_plain_ns"],
            # ARX has no table, so enumerability is a function of w only.
            "enumerable_below_48": p["w"] < 48,
        })

    rows.sort(key=lambda r: r["step_cost_ratio"])
    with open(os.path.join(args.out, "grid.json"), "w", encoding="utf-8") as fh:
        json.dump({"kind": "addendum-arx", "seed": args.seed,
                   "states": args.states, "dirs": args.dirs,
                   "points": rows}, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("addendum points: %d" % len(rows))
    for r in rows:
        print("  %-22s p5=%.3f ratio=%6.2f ns=%.1f"
              % (r["point"], r["gamma_p5"], r["step_cost_ratio"],
                 r["bench_model_ns"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
