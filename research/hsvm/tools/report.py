#!/usr/bin/env python3
"""Report validation and statistics for HSV gate evidence (stdlib only).

Rules this enforces (plan §7.3):
  * a report is bound to git_commit / params_hash / protocol_sha256 / seeds;
  * every metric must be traceable to a raw log file that exists;
  * success-rate style metrics require a nonzero query count;
  * a censored run may not claim a positive success rate;
  * declaring fewer queries than the registered budget REQUIRES censored=true.

Commands:
    report.py validate reports/G0/run.json
    report.py stats --values 1,2,3,4
    report.py wilson --successes 0 --trials 16
"""

import argparse
import json
import math
import os
import re
import sys

REQUIRED_FIELDS = [
    "run_id",
    "gate",
    "created_at",
    "git_commit",
    "params_hash",
    "protocol_sha256",
    "attacker_model",
    "seeds",
    "metrics",
    "queries_used",
    "censored",
    "raw_log",
    "evidence",
]

GATE_RE = re.compile(r"^(G[0-5][AB]?(v2)?|S[0-5][AB]?)$")
TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
PARAMS_RE = re.compile(r"^[0-9a-f]{16}$|^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

# Metric names that assert something about an attack outcome. These need a
# query budget behind them, otherwise the number is not evidence.
RATE_RE = re.compile(r"(success|recover|recovery|extract|break)_?(rate|ed)?",
                     re.IGNORECASE)


def is_number(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def validate_report(path):
    problems = []

    def need(cond, msg):
        if not cond:
            problems.append(msg)

    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return ["cannot read report: %s" % exc]

    if not isinstance(doc, dict):
        return ["report must be a JSON object"]

    for key in REQUIRED_FIELDS:
        need(key in doc, "missing field: %s" % key)
    if problems:
        return problems

    need(isinstance(doc["run_id"], str) and doc["run_id"],
         "run_id must be a non-empty string")
    need(isinstance(doc["gate"], str) and GATE_RE.match(doc["gate"]) is not None,
         "gate must look like G0..G5 (doc games, optional v2 suffix) or S0..S5/S4A/S4B (stage evidence)")
    need(isinstance(doc["created_at"], str) and
         TIME_RE.match(doc["created_at"]) is not None,
         "created_at must be YYYY-MM-DDTHH:MM:SSZ")
    need(isinstance(doc["git_commit"], str) and
         COMMIT_RE.match(doc["git_commit"]) is not None,
         "git_commit must be a hex SHA (7-64 chars)")
    need(isinstance(doc["params_hash"], str) and
         PARAMS_RE.match(doc["params_hash"]) is not None,
         "params_hash must be 16 or 64 lowercase hex chars")
    need(isinstance(doc["protocol_sha256"], str) and
         SHA_RE.match(doc["protocol_sha256"]) is not None,
         "protocol_sha256 must be 64 lowercase hex chars")
    need(doc["attacker_model"] in ("A1", "A2", "A3"),
         "attacker_model must be A1, A2 or A3")

    seeds = doc["seeds"]
    need(isinstance(seeds, list) and seeds, "seeds must be a non-empty list")
    if isinstance(seeds, list):
        need(all(isinstance(s, int) and not isinstance(s, bool) and s != 0
                 for s in seeds),
             "seeds must all be nonzero integers")
        need(len(set(seeds)) == len(seeds), "seeds must be unique")

    queries = doc["queries_used"]
    need(isinstance(queries, int) and not isinstance(queries, bool) and
         queries >= 0, "queries_used must be a non-negative integer")

    censored = doc["censored"]
    need(isinstance(censored, bool), "censored must be a boolean")

    metrics = doc["metrics"]
    need(isinstance(metrics, dict) and metrics, "metrics must be a non-empty object")
    if isinstance(metrics, dict):
        for name, value in metrics.items():
            need(isinstance(name, str) and name,
                 "metric names must be non-empty strings")
            need(is_number(value) and math.isfinite(float(value)),
                 "metric '%s' must be a finite number" % name)

    evidence = doc["evidence"]
    need(isinstance(evidence, list) and evidence,
         "evidence must be a non-empty list")
    if isinstance(evidence, list):
        need(all(isinstance(e, str) and e for e in evidence),
             "evidence entries must be non-empty strings")

    # Raw log must exist, relative to the report's directory.
    raw = doc["raw_log"]
    if isinstance(raw, str) and raw:
        base = os.path.dirname(os.path.abspath(path))
        candidates = [raw] if os.path.isabs(raw) else [os.path.join(base, raw),
                                                       raw]
        need(any(os.path.isfile(c) for c in candidates),
             "raw_log does not exist: %s" % raw)
    else:
        need(False, "raw_log must be a non-empty path")

    # Attack-outcome metrics need queries behind them.
    if isinstance(metrics, dict):
        rate_metrics = [n for n in metrics if RATE_RE.search(n)]
        if rate_metrics and isinstance(queries, int) and queries == 0:
            need(False,
                 "metric(s) %s assert an attack outcome but queries_used == 0"
                 % ", ".join(sorted(rate_metrics)))
        if censored:
            for name in rate_metrics:
                value = metrics.get(name)
                if (isinstance(value, (int, float)) and
                        not isinstance(value, bool) and value > 0):
                    need(False,
                         "censored run may not report '%s' > 0: report only "
                         "'no success within the used budget'" % name)

    # Budget consistency: censored is exactly "budget not exhausted".
    budget = doc.get("budget")
    if budget is not None:
        need(isinstance(budget, int) and not isinstance(budget, bool) and
             budget > 0, "budget must be a positive integer when present")
        if isinstance(budget, int) and isinstance(queries, int):
            need(queries <= budget, "queries_used must not exceed budget")
            if queries < budget:
                need(censored,
                     "queries_used (%d) < budget (%d): censored must be true"
                     % (queries, budget))

    return problems


def percentile(sorted_vals, pct):
    """Linear interpolation, same convention as numpy's default."""
    if not sorted_vals:
        raise ValueError("no values")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_vals[lo])
    frac = pos - lo
    return float(sorted_vals[lo]) * (1 - frac) + float(sorted_vals[hi]) * frac


def stats(values):
    vals = sorted(float(v) for v in values)
    n = len(vals)
    return {
        "n": n,
        "min": vals[0],
        "p5": percentile(vals, 5),
        "median": percentile(vals, 50),
        "mean": sum(vals) / n,
        "max": vals[-1],
    }


def wilson(successes, trials, z=1.96):
    if trials <= 0:
        raise ValueError("trials must be positive")
    p = successes / trials
    denom = 1.0 + z * z / trials
    center = (p + z * z / (2.0 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4.0 * trials * trials)) / denom
    return max(0.0, center - half), min(1.0, center + half)


def cmd_validate(args):
    problems = validate_report(args.report)
    if problems:
        for p in problems:
            print("ERROR: %s" % p, file=sys.stderr)
        return 1
    print("report: ok (%s)" % args.report)
    return 0


def cmd_stats(args):
    vals = [float(x) for x in args.values.split(",") if x.strip()]
    out = stats(vals)
    print(json.dumps(out, sort_keys=True))
    return 0


def cmd_wilson(args):
    lo, hi = wilson(args.successes, args.trials, args.z)
    print(json.dumps({"p": args.successes / args.trials, "lo": lo, "hi": hi,
                      "n": args.trials, "z": args.z}, sort_keys=True))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate")
    v.add_argument("report")
    v.set_defaults(func=cmd_validate)

    s = sub.add_parser("stats")
    s.add_argument("--values", required=True,
                   help="comma-separated numbers")
    s.set_defaults(func=cmd_stats)

    w = sub.add_parser("wilson")
    w.add_argument("--successes", type=int, required=True)
    w.add_argument("--trials", type=int, required=True)
    w.add_argument("--z", type=float, default=1.96)
    w.set_defaults(func=cmd_wilson)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
