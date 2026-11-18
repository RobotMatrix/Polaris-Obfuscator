# rnd/ — per-execution randomisation experiment

Harness and analysis for `demos/wbaes/reports/RANDOMISATION.md`. Everything here
operates on a **copy** of the runtime in a work directory; `demos/wbaes/wbaes_hybrid.h`
is input only.

| file | what it does |
|---|---|
| `patch_header.py` | regenerates the randomised header from the shipped one: per-call xorshift, `hy_dummy_access()`, and `hy_mc_round` rewritten so the 16 lane decodes run in a per-call Fisher-Yates order. Two `#define`s select the level: `HY_RND_K` (dummy reads per round) and `HY_RND_SHUFFLE`. |
| `harness_rnd.cpp` | `trace_harness/harness.cpp` plus per-block seeding, `_seeds.bin` / `_ct.bin` output, and a timed pass with the recorder off. |
| `rnd_traces.py` | drives the above: writes the randomised header, applies the five `HY_TRACE` hooks by importing `build_traces.py`'s own hook table, compiles with `src/build/bin/clang++`, runs it. |
| `measure.py` | ciphertext identity across levels, and the dummy statistics (how often a boundary table has two candidates, how often the first-in-order is the dummy, how often sorting by address still is). |
| `curve.py` | the traces-to-converge curve, `--mode naive` (the shipped attack) or `--mode filter` (plus the multiplicity filter). |
| `realign.py` | the residual path: sort by address, single-hit filter, and block-boundary relabelling against the recovered `Zl`/`Zr`. |

`curve.py` and `realign.py` import `collision_pairs`, `solve_half`, `reslib` and
`wblib` unmodified; no threshold, cap or candidate test is relaxed.

## Run order

```bash
for spec in "0 0 k0_s0" "0 1 k0_s1" "4 1 k4_s1" "16 1 k16_s1" "64 1 k64_s1"; do
  set -- $spec
  python3 demos/wbaes/attacks/rnd/rnd_traces.py --k $1 --shuffle $2 --n 4096 \
      --work /tmp/wbaes-rnd2/$3
done
python3 demos/wbaes/attacks/rnd/measure.py --work /tmp/wbaes-rnd2
for lv in k0_s0 k0_s1 k4_s1 k16_s1 k64_s1; do for m in naive filter; do
  python3 demos/wbaes/attacks/rnd/curve.py \
      --traces /tmp/wbaes-rnd2/$lv/rnd_${lv}_traces.bin --mode $m
done; done
python3 demos/wbaes/attacks/rnd/realign.py \
    --traces /tmp/wbaes-rnd2/k16_s1/rnd_k16_s1_traces.bin \
    --truth  /tmp/wbaes-rnd2/k0_s0/rnd_k0_s0_traces.bin
```

Each work directory holds a 70 MB unmasked table and ~80 MB of traces at n=4096.
