#!/usr/bin/env python3
"""Attack A1: recover H*v(i) from an x-only trace (stage 0).

The doc's V0.1 machine had F(s,i) = s XOR v(i). Any observer of the projection
x = H s therefore sees x_{t+1} XOR x_t = H v(i_t), regardless of the hidden
state. This script recovers that table per instruction slot and checks it
against the ground truth emitted by hsvm_run.

Outputs one flat JSON object (all values scalars) so it can be folded directly
into a gate report.

    a1_trace_diff.py --trace t.jsonl --truth truth.json --out a1.json
"""

import argparse
import json
import sys
import time


def load_jsonl(path):
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--trace2", default=None,
                    help="optional second trace with a different initial "
                         "state; the recovered table must be identical")
    ap.add_argument("--truth", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--recovered", default=None,
                    help="optional path for the recovered pc -> Hv table")
    args = ap.parse_args()

    started = time.time()
    trace = load_jsonl(args.trace)
    with open(args.truth, "r", encoding="utf-8") as fh:
        truth = json.load(fh)

    by_pc = {}
    inconsistent = 0
    for rec in trace:
        before = int(rec["x_before"], 16)
        after = int(rec["x_after"], 16)
        delta = before ^ after
        pc = rec["pc"]
        if pc in by_pc and by_pc[pc] != delta:
            inconsistent += 1
        by_pc[pc] = delta

    hv_truth = [int(h, 16) for h in truth["hv"]]
    mismatch = 0
    covered = 0
    for pc, delta in by_pc.items():
        if pc >= len(hv_truth):
            mismatch += 1
            continue
        if delta == hv_truth[pc]:
            covered += 1
        else:
            mismatch += 1

    # The same table must fall out of a run that started from a different
    # hidden state; otherwise "recovery" would just be curve fitting.
    cross_run_common = 0
    cross_run_mismatch = 0
    if args.trace2:
        by_pc2 = {}
        for rec in load_jsonl(args.trace2):
            by_pc2[rec["pc"]] = int(rec["x_before"], 16) ^ int(rec["x_after"], 16)
        for pc, delta in by_pc.items():
            if pc in by_pc2:
                cross_run_common += 1
                if by_pc2[pc] != delta:
                    cross_run_mismatch += 1

    elapsed = time.time() - started
    result = {
        "slots": len(hv_truth),
        "recovered_slots": len(by_pc),
        "covered": covered,
        "mismatch": mismatch,
        "inconsistent_slots": inconsistent,
        "cross_run_common": cross_run_common,
        "cross_run_mismatch": cross_run_mismatch,
        "queries": len(trace) + (len(load_jsonl(args.trace2)) if args.trace2 else 0),
        "elapsed_s": round(elapsed, 6),
        "coverage": round(covered / len(hv_truth), 6) if hv_truth else 0.0,
    }

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)

    if args.recovered:
        with open(args.recovered, "w", encoding="utf-8") as fh:
            json.dump({str(pc): "%0*x" % (truth["n"] // 4, v)
                       for pc, v in sorted(by_pc.items())}, fh, indent=2)

    print("a1: slots=%d covered=%d mismatch=%d inconsistent=%d queries=%d "
          "cross_run_mismatch=%d elapsed=%.4fs"
          % (result["slots"], result["covered"], result["mismatch"],
             result["inconsistent_slots"], result["queries"],
             result["cross_run_mismatch"], result["elapsed_s"]))
    ok = (mismatch == 0 and covered == len(hv_truth))
    if args.trace2:
        ok = ok and cross_run_common == len(hv_truth) and cross_run_mismatch == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
