#!/usr/bin/env python3
"""Sweep the registered parameter grid at the model layer (stage 1, M2).

For every legal (w, c, r_bar, rounds, psi) combination this runs hsvm_gamma and
collects: Gamma p5, non-affine count, and the step-cost ratio against the plain
VM. The grid is what G1 is judged on, so the sweep itself must be scripted and
the raw per-point JSON kept.

    run_g1_model.py --out reports/G1-model
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
    # Matches protocol.json: w in {8,16,32,48,64}, c in {8,16}, r_bar in {2,4},
    # rounds in {0,2,4}, both psi families where legal.
    for w in (8, 16, 32, 48, 64):
        for c in (8, 16):
            for rbar in (2, 4):
                if c * rbar > 512:
                    continue
                for psi in ("table", "spn"):
                    rounds_list = (0,) if psi == "table" else (2, 4)
                    if psi == "table" and (w > 16 or c > 16):
                        continue
                    for rounds in rounds_list:
                        yield dict(w=w, c=c, r_bar=rbar, rounds=rounds, psi=psi)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=os.path.join(ROOT, "reports", "G1-model"))
    ap.add_argument("--states", type=int, default=128)
    ap.add_argument("--dirs", type=int, default=4)
    ap.add_argument("--seed", type=int, default=12345)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    raw_dir = os.path.join(args.out, "raw")
    os.makedirs(raw_dir, exist_ok=True)

    rows = []
    for p in points():
        name = "w%d_c%d_r%d_%s_%d" % (p["w"], p["c"], p["r_bar"], p["psi"],
                                      p["rounds"])
        path = os.path.join(raw_dir, name + ".json")
        cmd = [GAMMA, "--n", "512", "--m", "256", "--w", str(p["w"]),
               "--c", str(p["c"]), "--rbar", str(p["r_bar"]),
               "--rounds", str(p["rounds"]), "--psi", p["psi"],
               "--seed", str(args.seed), "--states", str(args.states),
               "--dirs", str(args.dirs), "--affine", "exhaustive",
               "--bench", "--out", path]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print("skip %s: %s" % (name, res.stderr.strip()), file=sys.stderr)
            continue
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        row = {
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
        }
        # An attacker who can query psi once per input enumerates it in 2^w
        # steps; below 48 bits that is inside the registered 2^32..2^40 budget
        # range, so the point is only security-relevant with C2 in place.
        row["enumerable_below_48"] = p["psi"] == "table" or p["w"] < 48
        rows.append(row)

    rows.sort(key=lambda r: r["step_cost_ratio"])
    out = {
        "params_hash": rows[0].get("params_hash") if rows else None,
        "seed": args.seed,
        "states": args.states,
        "dirs": args.dirs,
        "points": rows,
    }
    with open(os.path.join(args.out, "grid.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("points: %d" % len(rows))
    for r in rows[:6]:
        print("  %-22s p5=%.3f nonaff=%2d ratio=%7.2f enumerable=%s"
              % (r["point"], r["gamma_p5"], r["affine_nonaffine"],
                 r["step_cost_ratio"], r["enumerable_below_48"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
