#!/usr/bin/env python3
"""G0v2 verdict: does any thin point have a cost floor at or below the cap?

Stop rule `g0v2_cost_floor_above_cap` fires only if EVERY point's floor exceeds
3.0 x baseline. The floor used is the measured sum of isolated components, which
is optimistic (a fused kernel can only be cheaper than the sum of its parts plus
loop overhead), so a pass here is necessary-not-sufficient: it licenses the C2
build, it does not certify the emitted kernel.
"""

import argparse
import json
import sys


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--floor", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.floor, "r", encoding="utf-8") as fh:
        doc = json.load(fh)

    cap = doc.get("cap_ratio", 3.0)
    pts = doc["points"]
    best = min(pts, key=lambda p: p["floor_ns"])
    feasible = [p["point"] for p in pts if p["ratio"] <= cap]

    reasons = []
    if not feasible:
        reasons.append("g0v2_cost_floor_above_cap: every thin point has "
                       "floor_ns > %.1f ns (best %.2f ns, %.2fx)"
                       % (cap * doc["baseline_ns"], best["floor_ns"],
                          best["ratio"]))

    verdict = {
        "gate": "G0v2",
        "pass": not reasons,
        "reason": "ok" if not reasons else "; ".join(reasons),
        "points": len(pts),
        "feasible_points": feasible,
        "best_point": best["point"],
        "best_floor_ns": round(best["floor_ns"], 3),
        "best_ratio": round(best["ratio"], 3),
        "cap_ratio": cap,
        "method": "sum of isolated component timings (optimistic lower bound)",
        "caveat": "a pass licenses the C2 build; it does not certify the final "
                  "kernel, which must still meet the cap when fused",
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(verdict, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
