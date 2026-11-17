#!/bin/bash
# Stage 0 / gate G0: build, run the linear ablation, attack it, judge it.
# Every artifact lands in reports/G0/ and is reproducible from SEED.
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=build
OUT=reports/G0
SEED=${SEED:-12345}
N=${N:-512}
M=${M:-256}

mkdir -p "$OUT"

cmake -S . -B "$BUILD" >/dev/null
cmake --build "$BUILD" -j"$(sysctl -n hw.ncpu 2>/dev/null || echo 4)" >/dev/null

./"$BUILD"/hsvm_run --program allops --mode linear --n "$N" --m "$M" \
  --seed "$SEED" --trace "$OUT/trace.jsonl" --truth "$OUT/truth.json" \
  --dump-state "$OUT/states.bin" | tee "$OUT/run_summary.json"

# Second run from a different hidden initial state: the attack must recover the
# same table, otherwise it is fitting one trajectory rather than the machine.
./"$BUILD"/hsvm_run --program allops --mode linear --n "$N" --m "$M" \
  --seed "$SEED" --init 0xDEADBEEF --trace "$OUT/trace2.jsonl" \
  > "$OUT/run_summary2.json"

PARAMS_HASH=$(python3 -c "import json;print(json.load(open('$OUT/run_summary.json'))['params_hash'])")
QUERIES=$(python3 -c "print(len(open('$OUT/trace.jsonl').read().splitlines()))")

python3 attacks/a1_trace_diff.py --trace "$OUT/trace.jsonl" \
  --trace2 "$OUT/trace2.jsonl" --truth "$OUT/truth.json" --out "$OUT/a1.json" \
  --recovered "$OUT/a1_recovered.json"

python3 attacks/a2_memread.py --state "$OUT/states.bin" --trace "$OUT/trace.jsonl" \
  --truth "$OUT/truth.json" --nbits "$N" --out "$OUT/a2.json"

python3 tools/make_report.py --gate G0 --run-id "g0-linear-$SEED" \
  --out "$OUT/run.json" --metrics "a1=$OUT/a1.json" --metrics "a2=$OUT/a2.json" \
  --raw-log trace.jsonl --queries "$QUERIES" --censored=false \
  --params-hash "$PARAMS_HASH" \
  --evidence attacks/a1_trace_diff.py --evidence attacks/a2_memread.py \
  --evidence reports/G0/truth.json

python3 tools/judge_g0.py --a1 "$OUT/a1.json" --a2 "$OUT/a2.json" \
  --out "$OUT/verdict.json"
