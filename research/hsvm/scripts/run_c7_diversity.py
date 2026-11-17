#!/usr/bin/env python3
"""C7 diversity falsification (doc §12.5 P1, stage 4B).

Claim under test: "per-instance diversity raises the attacker's cost". The
cheap way to be wrong is to assume it; this measures it instead, per instance,
on the linear ablation (where a recovery attack actually exists).

For each of the 16 registered seeds the script:
  * builds the model at a fixed point and records Gamma p5 and the step-cost
    ratio (does diversity move the coverage/cost numbers at all?);
  * runs the linear ablation and the A1 recovery attack, recording how many
    queries the attack needs to cover all 16 slots.

If the attack cost is flat across instances while only the encodings differ,
diversity changes nothing an attacker is billed for, and the negative-benefit
hypothesis is confirmed at this level.

    run_c7_diversity.py --out reports/G4B-c7
"""

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RUN = os.path.join(ROOT, "build", "hsvm_run")
GAMMA = os.path.join(ROOT, "build", "hsvm_gamma")
A1 = os.path.join(ROOT, "attacks", "a1_trace_diff.py")

SEEDS = [1001 + i for i in range(16)]


def one(seed, outdir):
    d = os.path.join(outdir, "seed_%d" % seed)
    os.makedirs(d, exist_ok=True)
    trace = os.path.join(d, "trace.jsonl")
    truth = os.path.join(d, "truth.json")

    common = [RUN, "--program", "allops", "--mode", "linear", "--n", "512",
              "--m", "256", "--w", "8", "--c", "8", "--input", "64",
              "--init", "0x%08x" % (0x10203040 ^ seed), "--seed", str(seed),
              "--trace", trace, "--truth", truth]
    r = subprocess.run(common, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("hsvm_run failed for seed %d: %s" % (seed, r.stderr))

    aout = os.path.join(d, "a1.json")
    a = subprocess.run([sys.executable, A1, "--trace", trace, "--truth", truth,
                        "--out", aout], capture_output=True, text=True)
    if a.returncode != 0:
        raise SystemExit("A1 failed for seed %d: %s" % (seed, a.stderr))
    with open(aout, "r", encoding="utf-8") as fh:
        att = json.load(fh)

    g = os.path.join(d, "gamma.json")
    subprocess.run([GAMMA, "--n", "512", "--m", "256", "--w", "8", "--c", "8",
                    "--rbar", "2", "--rounds", "0", "--psi", "table",
                    "--seed", str(seed), "--states", "32", "--dirs", "2",
                    "--affine", "none", "--bench", "--out", g],
                   capture_output=True, text=True, check=True)
    with open(g, "r", encoding="utf-8") as fh:
        gam = json.load(fh)

    return {
        "seed": seed,
        "a1_queries": att["queries"],
        "a1_covered": att["covered"],
        "a1_mismatch": att["mismatch"],
        "gamma_p5": gam["gamma_p5"],
        "step_cost_ratio": gam["step_cost_ratio"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=os.path.join(ROOT, "reports", "G4B-c7"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    rows = [one(s, args.out) for s in SEEDS]
    queries = sorted(r["a1_queries"] for r in rows)
    gammas = sorted(r["gamma_p5"] for r in rows)
    ratios = sorted(r["step_cost_ratio"] for r in rows)

    doc = {
        "experiment": "c7-diversity",
        "seeds": SEEDS,
        "point": {"n": 512, "m": 256, "w": 8, "c": 8, "r_bar": 2,
                  "psi": "table"},
        "rows": rows,
        "summary": {
            "a1_queries_min": queries[0],
            "a1_queries_max": queries[-1],
            "a1_queries_median": queries[len(queries) // 2],
            "a1_covered_all": all(r["a1_covered"] == 16 for r in rows),
            "a1_mismatch_total": sum(r["a1_mismatch"] for r in rows),
            "gamma_p5_min": gammas[0],
            "gamma_p5_max": gammas[-1],
            "gamma_p5_spread": round(gammas[-1] - gammas[0], 4),
            "step_cost_ratio_min": ratios[0],
            "step_cost_ratio_max": ratios[-1],
        },
    }
    # The falsifiable statement: diversity must move the attacker's cost.
    s = doc["summary"]
    doc["verdict"] = {
        "hypothesis": "per-instance diversity raises attacker cost",
        "supported": s["a1_queries_max"] > s["a1_queries_min"],
        "reason": ("attack cost varies across instances"
                   if s["a1_queries_max"] > s["a1_queries_min"]
                   else "attack cost is flat across all 16 instances: every "
                        "instance is recovered with the same number of queries, "
                        "so diversity changed the encodings but not the cost"),
        "gamma_spread": s["gamma_p5_spread"],
        "cost_spread": round(s["step_cost_ratio_max"] - s["step_cost_ratio_min"], 3),
    }
    with open(os.path.join(args.out, "diversity.json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("seeds: %d | A1 queries %s..%s (covered all: %s)"
          % (len(rows), s["a1_queries_min"], s["a1_queries_max"],
             s["a1_covered_all"]))
    print("gamma p5 %.4f..%.4f (spread %.4f)" % (gammas[0], gammas[-1],
                                                 s["gamma_p5_spread"]))
    print("verdict: %s / %s" % (doc["verdict"]["supported"],
                                doc["verdict"]["reason"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
