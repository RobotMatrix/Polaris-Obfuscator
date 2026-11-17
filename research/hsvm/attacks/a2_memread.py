#!/usr/bin/env python3
"""Attack A2: recover v(i) by reading the state buffer (stage 0).

A2 may read the VM's state memory. In the linear ablation two adjacent steps
differ by exactly the slot mask, so one XOR per step yields the whole v table
without any cryptanalysis. The dump is the hsvm_run state history; the trace
supplies the pc sequence.

    a2_memread.py --state states.bin --trace t.jsonl --truth truth.json \
                  --nbits 512 --out a2.json
"""

import argparse
import json
import sys
import time


def load_jsonl(path):
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def read_states(path, nbits):
    rec = (nbits + 7) // 8
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) % rec != 0:
        raise SystemExit("a2: state dump size %d is not a multiple of %d"
                         % (len(blob), rec))
    return [int.from_bytes(blob[i * rec:(i + 1) * rec], "little")
            for i in range(len(blob) // rec)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state", required=True)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--nbits", type=int, default=512)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    started = time.time()
    states = read_states(args.state, args.nbits)
    trace = load_jsonl(args.trace)
    with open(args.truth, "r", encoding="utf-8") as fh:
        truth = json.load(fh)

    if len(states) < len(trace) + 1:
        raise SystemExit("a2: state dump has %d records, trace has %d steps"
                         % (len(states), len(trace)))

    v_truth = [int(x, 16) for x in truth["v"]]
    recovered = {}
    mismatch = 0
    for i, rec in enumerate(trace):
        pc = rec["pc"]
        delta = states[i] ^ states[i + 1]
        recovered[pc] = delta

    covered = 0
    for pc, delta in recovered.items():
        if pc < len(v_truth) and delta == v_truth[pc]:
            covered += 1
        else:
            mismatch += 1

    elapsed = time.time() - started
    result = {
        "slots": len(v_truth),
        "recovered_slots": len(recovered),
        "covered": covered,
        "mismatch": mismatch,
        "queries": len(trace),
        "elapsed_s": round(elapsed, 6),
        "coverage": round(covered / len(v_truth), 6) if v_truth else 0.0,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)

    print("a2: slots=%d covered=%d mismatch=%d queries=%d elapsed=%.4fs"
          % (result["slots"], result["covered"], result["mismatch"],
             result["queries"], result["elapsed_s"]))
    return 0 if mismatch == 0 and covered == len(v_truth) else 1


if __name__ == "__main__":
    sys.exit(main())
