#!/usr/bin/env python3
"""G1 (model layer) verdict: is there a parameter point that satisfies both the
coverage/non-affine conditions and the performance budget?

Conditions (plan M2-10 / doc §10 stage 1):
  * Gamma 5% quantile >= 0.5 for every instruction type;
  * D is non-affine on pi_A(K) for every instruction type;
  * step-cost ratio <= 3 against the plain VM;
  * the point is not enumerable within the registered query budget, i.e. it
    needs w >= 48 (or C2, which does not exist yet at this stage).

The last condition is deliberately explicit: a cheap table point that an
attacker enumerates in 2^w queries is not a pass, and the report must not let
cost alone select it.
"""

import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--grid", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.grid, "r", encoding="utf-8") as fh:
        grid = json.load(fh)

    reasons = []
    coverage_ok = []
    perf_ok = []
    security_ok = []
    both = []

    for p in grid["points"]:
        # A point must describe real work: zero instructions would satisfy
        # "coverage" and "non-affine" vacuously, and a zero baseline would make
        # the ratio meaningless.
        if p.get("instructions", 0) <= 0 or p.get("bench_plain_ns", 0) <= 0:
            reasons.append("invalid point %s: instructions=%r bench_plain_ns=%r"
                           % (p.get("point"), p.get("instructions"),
                              p.get("bench_plain_ns")))
            continue
        cov = p["gamma_p5"] >= 0.5
        nonaff = p["affine_nonaffine"] == p["instructions"]
        perf = p["step_cost_ratio"] <= 3.0
        # Enumerability is derived here, never trusted from the sweep: a w-bit
        # table, or any point below 48 bits, is enumerable inside the budget.
        sec = not (p["psi"] == "table" or p["w"] < 48)
        if p.get("enumerable_below_48") is not None and \
                bool(p["enumerable_below_48"]) != (not sec):
            reasons.append("point %s disagrees with the sweep about "
                           "enumerability (grid=%r derived=%r)"
                           % (p["point"], p["enumerable_below_48"], not sec))
        if cov and nonaff:
            coverage_ok.append(p["point"])
        if perf:
            perf_ok.append(p["point"])
        if sec:
            security_ok.append(p["point"])
        if cov and nonaff and perf and sec:
            both.append(p["point"])

    if not coverage_ok:
        reasons.append("no point satisfies Gamma p5 >= 0.5 and non-affine D")
    if not perf_ok:
        reasons.append("no point satisfies step_cost_ratio <= 3")
    if not security_ok:
        reasons.append("no point has w >= 48 (all are enumerable or table-based)")
    if not both:
        reasons.append("no point satisfies coverage, non-affine, performance "
                       "and non-enumerability together")

    verdict = {
        "gate": "G1-model",
        "pass": not reasons,
        "reason": "ok" if not reasons else "; ".join(reasons),
        "points": len(grid["points"]),
        "coverage_ok": len(coverage_ok),
        "perf_ok": len(perf_ok),
        "security_ok": len(security_ok),
        "all_conditions": both,
        "best_ratio": min(p["step_cost_ratio"] for p in grid["points"])
        if grid["points"] else None,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(verdict, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
