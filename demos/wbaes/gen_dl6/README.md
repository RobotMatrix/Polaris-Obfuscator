# gen_dl6 — the rk0-in-Z variant (an experiment, not a generation)

dl6 moves round key 0 out of round 0's S-box input and into the output-side
relabelling: round 0's lane tables compute `MC·S(pt)`, and a 12 KiB layer between
round 0's boundary and round 1 puts the key back, so the round output the rest of the
network sees is bit-identical to dl5's. The point was to test whether that hides `rk0`
from `attacks/residual/hs_attack.py`'s gauge-invariant test.

**It does, and it does not help: the variant is worse.** The layer must contain
`S ∘ σ_rk0` (merged with `S^-1 ∘ σ_d` into one table per byte), so `rk0` — and `rk1`,
which inverts the AES-128 key schedule — fall out by table inspection in 0.01 ms,
against 3.33 s of algebra for the shipped dl5 design on the same host.
Full numbers, the correctness proof and the verdict: **`../reports/RK0-IN-Z.md`**.

Nothing here is shipped: `../gen_hybrid.cpp`, `../wbaes_hybrid.h`, `../wbaes_vm.*` and
the exported binaries are untouched, so the dl5 / nl / f4 generations build exactly as
before. `HY_TOTAL` grows by 12,288 B only inside this variant's table.

## Build and run

The generator takes the key on the command line; no key is stored in this directory.

```sh
clang++ -std=c++17 -O2 -I. -I.. -o /tmp/gen_dl6 gen_dl6.cpp
mkdir -p /tmp/wbaes-dl6/work && cd /tmp/wbaes-dl6/work
/tmp/gen_dl6 dl6_table.bin --key <32 hex> --pagesize 16384 --ncpu 10 --cls 128
```

It writes `dl6_table.bin` (70,103,104 B, masked), `hy_in.h` (the round-0 input
bijection) and `hy_seal.h` (the mask seed), and exits 0 only if the table path matches
a straight AES reference on the test vector and on eight random plaintexts, in both
directions, and no round key appears in the table as a byte run.

## Checks

```sh
python3 verify_dl6.py --table dl6_table.bin --work . --key <32 hex> --n 6
python3 dl6_traces.py --table dl6_table.bin --work . --n 64      # ct, traces, bench
python3 rk0_in_z_attack.py --table dl6_table.bin --work . --ct <32 hex> --key <32 hex>
```

`verify_dl6.py` re-derives the round function from the table bytes (plus the layer) and
compares against `openssl enc -aes-128-ecb`. `dl6_traces.py` builds the trace harness
with the dl5-era five hooks (the committed harness hooks three, which is enough for F4
but drops the 32-bit lane loads an 8-bit-generation artifact uses), runs 64 real
traces, and times the round walk. `rk0_in_z_attack.py` is the attack the move hands
over: a shape scan of the layer plus the two key reads.

## Generator diff (dl5 → dl6)

1. `sp.rk_pre = nullptr` for round 0 (was `key`).
2. `fill_rkz()` writes 12 tables per column (`Pi[0]`, `U`, `T`, kinds 168..191);
   `hy_rkz_apply()` applies them between `hy_rec_undo(round 0)` and
   `hy_mc_round(round 1)`.
3. The key comes from `--key`; the self-check compares against `ref_encrypt`.
4. `HY_TOTAL` gains `HY_RKZ_BYTES`; every dl5 offset is unchanged.

Decryption is the dl5 code unchanged: the layer's output is dl5's round-0 output, so
the decrypt chain (which inverts round 0 through `IMC` and `S^-1` rather than through
the layer) still ends on `pt ^ rk0` and the tail pair table removes the key.
