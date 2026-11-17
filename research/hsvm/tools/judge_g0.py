#!/usr/bin/env python3
"""G0 gate: did stage 0 falsify the linear layer?

Pass conditions (plan M1-7, doc §10 stage 0):
  * A1 recovered every slot with zero mismatches;
  * A2 recovered every slot with zero mismatches;
  * both attacks finished in under a minute of wall time.

The numbers must come from the attack JSONs, never from the command line.

    judge_g0.py --a1 reports/G0/a1.json --a2 reports/G0/a2.json \
                --out reports/G0/verdict.json
"""

import argparse
import json
import sys

MAX_SECONDS = 60.0


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--a1", required=True)
    ap.add_argument("--a2", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    a1 = load(args.a1)
    a2 = load(args.a2)

    reasons = []
    for name, doc in (("a1", a1), ("a2", a2)):
        if doc.get("covered") != doc.get("slots"):
            reasons.append("%s did not cover every slot (%s/%s)"
                           % (name, doc.get("covered"), doc.get("slots")))
        if doc.get("mismatch") != 0:
            reasons.append("%s reported %s mismatches"
                           % (name, doc.get("mismatch")))
        if doc.get("elapsed_s", 1e9) > MAX_SECONDS:
            reasons.append("%s took %.1fs, above the %.0fs bar"
                           % (name, doc.get("elapsed_s"), MAX_SECONDS))

    # Cross-run recovery must agree: one table, not one fitted trajectory.
    if a1.get("cross_run_common") != a1.get("slots"):
        reasons.append("a1 cross-run comparison did not cover every slot")
    if a1.get("cross_run_mismatch") != 0:
        reasons.append("a1 recovered different tables from two runs")

    verdict = {
        "gate": "G0",
        "pass": not reasons,
        "reason": "ok" if not reasons else "; ".join(reasons),
        "a1_elapsed_s": a1.get("elapsed_s"),
        "a2_elapsed_s": a2.get("elapsed_s"),
        "slots": a1.get("slots"),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(verdict, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
