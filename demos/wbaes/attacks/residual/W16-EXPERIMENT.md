# 16-bit column combining: built, AES-compatible, and it buys no key secrecy

> **Verdict: the combine really is 16 bits wide, and the work factor did not move.**
> AES's MixColumns is GF(2)-linear, so pairing the four lanes *and* the four output
> rows gives a 16-bit partial sum per half and the two halves meet in one XOR of two
> 16-bit words (measured: every 2^16-index pair table is a bijection onto the 2^16
> 16-bit values, and a 16-bit value spans the whole alphabet — there is no 8-bit sum
> anywhere on the data path). But the per-build encoding that has to ride on that
> value is forced to be **affine**, because a nonlinear 16-bit encoding cannot be
> undone by any 2^16-index table (proved in §1 and measured as 119 contradicting
> outputs over 4096 sampled pairs). An affine encoding makes the pair table **exactly
> XOR-separable**: 1,048,576/1,048,576 entries reproduced by one row plus one column.
> One axis of that table is still one key byte, so the key falls out at
> **4,096 affine-consistency tests, 0.08 s of algebra, 16/16 bytes**, and the
> ciphertext follows.
>
> 4,096 is a quarter of the shipped artifact's 16,384: a 16-bit value spans two
> MixColumns rows (half the positions), and the second row pair is redundant — the
> first already pins the key byte (the other half).
> The construction is a 20 %/17 % per-block speed-up and costs nothing in volume; as a
> key barrier it is a small step backwards.
>
> **Shipped (2026-11-18), as a performance generation.** This construction is now the
> repository's only shape: `gen_hybrid.cpp` and `wbaes_hybrid.h` carry F4 as code (the
> patch file is gone), the four eight-bit families were removed, the key was rotated to
> `3acb79e7…`, and `wbaes_f4_clean` / `wbaes_f4_max` are exported. The measurement
> below stands as measured; the current gate table, timings and attack costs for the
> shipped build are in `README.md` §5.29, and the strength position is stated there and
> in `WB-DESIGN-V2.md` §16: AES-compatible, 20 % faster, **weaker** against key
> extraction than dl5/nl, because the pair table is exactly XOR-separable.

All numbers below are from this machine (macOS arm64, clang-16 16.0.6 at
`src/build/bin/clang++`, Python 3.12.5, stdlib only). The variant was built and
measured entirely under `/tmp/wbaes-w16/`; the artifact of record is
`/tmp/wbaes-w16/work/hy_table.bin`, 70,090,816 B, mask seed `0x27ed5bea`,
seal `0xa8f5737c`. Everything in §2–§6 comes from one `runall.sh` pass over that one
table, so the timings and the counts belong to the same bytes.

---

## 1. The construction, exactly, and the arithmetic that had to be checked first

Per (direction, round, column), with `u_k = S(in_k ^ rk_k)` the four lane values:

```
pair the rows too:      Y01 = ( sum_k MC[0][k] u_k , sum_k MC[1][k] u_k )     16 bits
                        Y23 = ( sum_k MC[2][k] u_k , sum_k MC[3][k] u_k )     16 bits
split the lanes:        Y01 = WL01 ^ WR01,   WL01 from lanes 0,1,  WR01 from lanes 2,3
store each half:        T_L[a][b] = E01( WL01(a,b) )     2^16 entries x 2 B
                        T_R[c][d] = E01( WR01(c,d) )     2^16 entries x 2 B
combine:                x01 = T_L ^ T_R                   <-- 16-bit XOR, 16-bit values
finish:                 out_r = P_out[ byte_r(E01^-1(x01)) ^ rk_after[r] ]   4 x 2^16 x 1 B
```

Column slot (798,720 B, the shipped `HY_COL`, unchanged):

| region | bytes | contents |
|---|---|---|
| `[0, 524288)` | 4 × 131,072 | the four pair tables: rows 0,1 / lanes 0,1 · rows 0,1 / lanes 2,3 · rows 2,3 / lanes 0,1 · rows 2,3 / lanes 2,3 |
| `[524288, 528384)` | 4,096 | unused (the shipped alignment gap) |
| `[528384, 536576)` | 8,192 | the 32-bit recoding, untouched (12 forward + 12 inverse S-boxes + 12 constants) |
| `[536576, 798720)` | 4 × 65,536 | the four decode tables, 2^16 index, 1 B out |

Lookups per column: 4 pair + 4 decode + 12 recoding = **20**, against the shipped 28.

### Why the value encoding can only be affine

The runtime needs one table `D` with `D(E0(u) ^ E1(v)) = u ^ v` for all `u, v` on
16 bits. Absorb the constants, so `E0(0) = E1(0) = 0` and `T = M(· ^ E1(0))`; then
`T(E0(u)) = u` forces `T = E0^-1`, and setting `u = 0` gives `T(E1(v)) = v`, so
`T = E1^-1` and `E0 = E1 =: E`; substituting back, `E(u) ^ E(v) = E(u ^ v)`. So `E` is
GF(2)-linear (affine with the constant). **A nonlinear 16-bit encoding cannot be
undone by any 2^16-index table, at any table size.**

Measured (`w16_probe.py` step 0, before the table was generated):

```
merge table D(E0(u)^E1(v)) = u^v, 4096 sampled pairs:
  E0, E1 random 16-bit bijections : 119 collisions demanding two different outputs
  E0 = E1 affine 16-bit map       : 0 collisions
```

The encoding still carries 256 bits of per-build entropy (a random invertible 16×16
GF(2) matrix plus a 16-bit constant, fresh per slot), so builds differ. It is
transparent, not secret — and §3 shows what "transparent" costs.

### Why the width is not the old failure

The four previous generations died because the *sum* was 8 bits: a 2^16-entry table of
8-bit values whose rows are permutations has to exist, and `reslib.Decomp` eats it.
Here the sum is 16 bits, and it is measured, not asserted:

```
16 pair tables x 65536 entries, distinct 16-bit values per table: min 65536 max 65536
decode index == pair_left ^ pair_right: 1024/1024 (from the address traces, §4)
```

So the shape the previous generation's diagnosis demanded was built. §3 is why it did
not help.

## 2. W1: the artifact is AES, and every gate that is not about secrecy still holds

| item | value |
|---|---|
| `gen_hybrid` (patched, §8) | rc 0; `spn-mds: PASS`, `table-check PASS`, `seal-check PASS` |
| artifact | 70,090,816 B (identical to the shipped table size), mask seed `0x27ed5bea`, seal `0xa8f5737c` |
| `AES-128(6bc1bee2…172a, 4f065a03…4c66)` | **`7672415a6313c58518fc95c9cb6922b8`** ✓ |
| demo | `vector-match: PASS`, `roundtrip: PASS` |
| schedule | nine rounds, both directions, one shape (`F4`) |

The generator's own checks are the evidence for "the ciphertext is unchanged": it
compares the table path against a straight AES reference on the test vector and on 8
random plaintexts, in both directions, and returns 8 (encrypt) or 9 (decrypt) on a
mismatch. Both controls were exercised, §6.

## 3. W2: the work factor is 4,096 tests, i.e. 2^8 per key byte

`w16_probe.py` reads the artifact the way any attacker would — unmask, invert the
per-table scatter with the public tag and env, read the pair tables — and then:

```
== 3. the dl4/BGE step, in 16-bit values ==
   col 0: T[a][b] == X[a]^Y[b] on 65536/65536  65536/65536  65536/65536  65536/65536
   … all four columns …
   total 1048576/1048576: one row plus one column of 256 values reproduces every 2^16 table exactly

== 5. the gauge-invariant key test on a 16-bit axis ==
      0    0  0x4f  ['0x4f']   256  unique        2    0  0x5f  ['0x5f']   256  unique
      1    0  0x16  ['0x16']   256  unique        3    0  0x66  ['0x66']   256  unique
      … all 16 (lane, column) pairs, one candidate each …
   16 axes, 4096 tests, 0.08s

== 6. result ==
   recovered key: 4f065a03ee16cf8c31b15fd8f0344c66
   reproduces the shipped ciphertext: YES
   work factor: 4096 affine-consistency tests (16 lane axes x 256 guesses)
```

Why 4,096 and not 16,384: the shipped design tests one MixColumns *row* at a time, 64
(col, lane, row) positions; F4's 16-bit value covers two rows, and the rows-2,3 tables
are redundant once rows 0,1 have pinned the byte, so 16 positions replace 64. The test
itself is `reslib.linear_image_ok` with a 16-bit codomain:
`val[enc] = A · S(P0^-1(enc) ^ g) ^ c` for an unknown GF(2)-linear `A: 8 → 16` of rank
8. Nothing about `E` or about the MixColumns coefficients is needed — both are linear
and fold into `A`. Model check from the same run: at the true key byte the axis fits
with `256/256` consistent differences.

Cost accounting: 4,096 table entries (8 KiB) are actually read. The 70 MB unmask is
15.7 s in Python and the 144-table decomposition scan another 12.3 s; the attack's own
algebra is the 0.08 s above.

### The shortcut the last generation would have taken: it exists, and it is slower

Four things were tried on the *same* artifact, because "no 8-bit projection exists"
would be a false claim:

1. **`Decomp` generalised to 16-bit values** (`res16.Decomp16`). It needs, per row
   `a`, `f_a = Q[a][·]` to be a permutation of the value alphabet, so that
   `lam_a = f_a ∘ f_0^-1` is defined. With 8-bit values a row of 256 entries can be
   such a permutation; with 16-bit values the alphabet has 65,536 members and a row has
   256. Measured on all four columns: rows are injective `256/256`, but **0/255 rows
   share row 0's value set (maximum overlap 0)**, so `LAM` does not exist. If it did,
   the gauge would be `|GL(16,2)| · 2^16 = 2^270.2` — worth having, and unavailable.
2. **`Decomp` on the 8-bit projections of the pair tables.** All 32 projections were
   tried: **0/32 decompose in this build** (an earlier build of the same construction
   had 1/32). The reason is arithmetic: a projection is `P(L0(a) ^ L1(b))` with `L0`,
   `L1` the 8×8 blocks of `E^-1`, so it decomposes only when *both* are invertible
   (≈ 8 % per table). Where it does, the decomposition's labels are an affine image of
   the S-box output — in the earlier build, taking that route returned `0x06` for
   (column 3, lane 1) at 256 guesses: the same byte, the same cost, plus a
   decomposition.
3. **The 2^16-index decode tables.** These are the 8-bit-valued, 2^16-index tables the
   last generation died on, and they do occur here. Over all 144 encrypt slots:
   **38/144 have permutation rows, 6/144 decompose.** When one does, `Decomp` returns
   `E^-1` up to the 2^70.2 gauge — the public linear map — and no key byte, because
   these tables sit *after* the MixColumns sum: their axis carries the whole column,
   not one lane.
4. **Byte-axis key tests.** Splitting each 16-bit axis into its two bytes doubles the
   number of positions: 32 axes × 256 guesses = 8,192 tests. It also needs a
   rank-tolerant test: `reslib.linear_image_ok` demands an *invertible* linear image,
   and a byte of a 16-bit word is a singular function of the lane value in most slots —
   measured **9/32 unique with the shipped test, 32/32 with the rank allowance removed**.
   A script that keeps the shipped test on the projection therefore under-reports, not
   under-recovers: the tolerances are a property of the projection, not a barrier.

**Conclusion for W2: 2^8 tests per key byte, 4,096 for the whole key, no search over
the 16-bit encoding, no traces, no group recovery. The 2^16 width did not enter the
work factor at all — and the test count halved.**

## 4. W3: the shipped attacks, and the trace-side measurement

`run_shipped.py` runs each committed script against the F4 artifact with two pieces of
plumbing only: `wblib.FAM_NAMES[4]` (the scripts print the schedule through that dict
and die on a `KeyError` before any algebra) and, optionally, the boundary tag constant
(208 instead of 144). Every offset in `wblib` holds unchanged, because `HY_TOTAL`,
`HY_COL`, `SCHED_OFF` and `BDY_OFF` are the shipped values.

| script | outcome | why |
|---|---|---|
| `hs_attack.py` | `round 0 is not F1/T32; this script's tag choice assumes it` | stops at its own family guard. The decomposition it would have run is measured in §3 items 1–2: it does not exist for F4's tables. |
| `zk_attack.py` | `SystemExit: 70090816 bytes, expected 70107200` | asserts the zk layout length |
| `bge_attack.py` | ran: 16/16 rows `row is a bijection: no`, `incomplete (0/16 bytes)` | reads the *shipped* lane offsets (`HY_LANE_OFF`, 1024 B stride), which in F4 are slices of a 2^16 pair table. A statement about its offsets. |
| `consistency_attack.py` | ran its full math: 4–10 collision pairs per half, `0 candidate` in 8/8 halves | its signature is built for an **8-bit** pair sum. Measured on F4: `u` is *not* a function of the 8-bit sum (6–13 conflicts per column, against 0 on dl5). A 16-bit generalisation would need ~2^16 guesses per half (8 halves) — more than the 4,096 static tests, so it was not implemented. |
| `dca_attack.py` | `lane slot (col 0, k 0) not in trace` | experiment A looks for the shipped lane-table address |

None of these five nulls is a defeat, and none of them is evidence about the
construction. The evidence about the address side is `w16_traces.py`, which reads the
same 64 traces the harness produced (1,160 accesses/block) and asks the E4c question
directly, with F4's offsets and tags:

```
round-0 pair tables: index == P0(pt_a)|P0(pt_b)<<8 : 512/512   (64 distinct per table)
round-0 decode tables: index == pair_left ^ pair_right : 1024/1024
                       distinct index values: 63–64 out of 64 traces
```

So every 8-bit-indexed table left in the round is the recoding S-box, whose index is a
nonlinear function of the *whole* column, and both 2^16-indexed families are reached
through 2-byte indices: the pair tables by P0 of the plaintext (public), the decode
tables by the 16-bit sum. A single-byte correlation has nothing to correlate with, at
any number of traces. An attacker with the artifact has no reason to use traces
anyway — §3 is cheaper.

## 5. W4: volume and per-block cost

| | shipped shape (`bench_base`, this machine) | F4 (`bench_w16`) |
|---|---|---|
| table bytes | 70,090,816 | 70,090,816 (unchanged `HY_COL`) |
| slot used | 798,720 of 798,720 | 794,624 of 798,720 (4 KiB slack per slot) |
| lookups / column | 28 | 20 |
| encrypt, best of 3 runs × 3000 blocks | 16.68 µs | **13.36 µs** (−20 %) |
| decrypt, best of 3 runs × 3000 blocks | 16.57 µs | **13.79 µs** (−17 %) |

Three interleaved runs each, same machine, same VM configuration, same harness:
`16.95 / 16.68 / 16.81` against `13.36 / 13.37 / 13.38` (encrypt), `16.59 / 16.57 /
16.61` against `13.87 / 13.79 / 13.84` (decrypt). Unlike the wide fusion, this one is
a real win, and it is the only real win: the 4 KiB lane tables' cache residency is
traded for two 256 KiB random reads per column, but there are half as many of them.

The 70,090,816 B is a choice, not a requirement: the slot was left at the shipped
stride so that the schedule block, the VM's 288 offsets and every reader offset stay
valid. Packing the slots would save 72 × 4,096 = 294,912 B (0.42 %) and buy nothing.

## 6. W5: every gate that is not about key secrecy

| gate | command | result |
|---|---|---|
| ciphertext identity | `./wbaes_w16_clean` | `7672415a6313c58518fc95c9cb6922b8` PASS, roundtrip PASS |
| VM is live and its offsets are the ones used | `-DWBAES_VM_SCHEDTEST` | intact `7672415a…` → byte 48 flipped → `f172250d2934bae301c91b7b4893c1ff` → restored `7672415a…` |
| DFA double pass | `-DWBAES_DFA_SELFTEST` | `c40a5ae8d24187a3ef202cae5e548d6c`, roundtrip `a0d06670d5f225ec…`, `vector-match: FAIL` (junk, as specified) |
| VM offset program | `tests/test_vm_offsets` | `vm-offsets: PASS` (288-offset plan, shipped/foreign layouts, forced families, short and null table) |
| generator self-checks | `gen_hybrid` | rc 0, `spn-mds: PASS`, `table-check PASS`, `seal-check PASS` |
| **generator return 8 is live** | break the *encrypt* decode tables | **rc 8** |
| **generator return 9 is live** | break only the *decrypt* decode tables | **rc 9** |
| family dimension | `gen_hybrid --fam 1` | `rc 2`, `this build has one shape (--fam 4); 0..3 cannot express a 16-bit combine` |

The VM bytecode was not touched: `wbaes_vm.cpp`, `wbaes_vm.h` and the ISA are the
shipped files. F4 is a *nonzero* family byte, so the bytecode takes its lane-stride
branch, and the schedule block's lane stride word is set to 131,072 — the size of one
pair table. That is how four tables per column come out of the same 16 offsets per
(direction, round) the VM already computes, with no new opcode and no new word.

## 7. What was given up, and what this does not buy

1. **The family dimension.** One shape only. `--fam 0..3` is refused rather than
   silently mis-built, so the "four forced families agree on the ciphertext" gate
   cannot be expressed for this generation. This is forced: the other four layouts put
   their partial sums in 8-bit tables at the same strides.
2. **dl5's per-lane nonlinear bijections.** They were the one thing that made the
   dl4-style rank-1 fit fail (0.80 % of off-axis entries). An affine 16-bit encoding
   cannot replace them, and a nonlinear one cannot be combined — §1. F4's pair tables
   fit at **100 %**, which is *worse* for us than dl5's 0.80 %.
3. **Nothing at all in ciphertext, seals, mask, DFA, VM or the decryption path.** All
   of it is the shipped code.
4. **Key secrecy.** Not improved; slightly reduced (4,096 tests against 16,384). The
   table layer still hides state, not keys.

## 8. Scope, and how to reproduce

* Shipped since 2026-11-18: F4 **is** the repository's shape. `gen_hybrid.cpp` and
  `wbaes_hybrid.h` carry it as code, `attacks/residual/w16/F4.patch` was deleted (a
  patch that no longer applies to anything is worse than no patch), and the key was
  rotated. The reproduction below is the historical recipe for the measurement run;
  for the shipped build use `README.md` §5.29, which builds from the tree without any
  patching step.
* The scripts are `attacks/residual/res16.py` (F4 readers, `Decomp16`, the 16-bit key
  test), `w16_probe.py` (W2: preconditions, fit, decompositions, key, cost) and
  `w16_traces.py` (W3: the address-side measurement). `run_shipped.py` is the driver
  used for §4's table and is not committed — its two changes are described there.
* Counts that depend on the build's random matrices (how many decode tables decompose)
  differ between builds; everything that decides the verdict (4,096 tests, 16/16 bytes,
  the 100 % fit, the unchanged ciphertext) does not.

```sh
# HISTORICAL RECIPE (the measurement run). The tree no longer needs steps 1's patch:
# F4 is the shipped shape, and `git archive HEAD demos/wbaes` now contains it.
mkdir -p /tmp/w16 && cd /tmp/w16
git -C $REPO archive HEAD demos/wbaes | tar x
cd demos/wbaes

# 2. table + binaries
CL=$REPO/src/build/bin/clang++
$CL -O2 -std=c++17 -I. gen_hybrid.cpp -o gen_hybrid && ./gen_hybrid hy_table.bin
$CL -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. \
    -mllvm -passes=hsvm -c wbaes_vm.cpp -o wbaes_vm.o
$CL -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. \
    demo_wbaes.cpp wbaes_vm.o hy_tab.S -o wbaes_w16_clean
$CL -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. \
    bench_wbaes.cpp wbaes_vm.o hy_tab.S -o bench_w16
$CL -O2 -std=c++17 -DWBAES_HAVE_VM -I. tests/test_vm_offsets.cpp wbaes_vm.o \
    -o test_vm_offsets

# 3. W1, W4, W5
./wbaes_w16_clean && ./bench_w16 3000 && ./test_vm_offsets

# 4. W2
cd attacks/residual && python3 w16_probe.py --table /tmp/w16/demos/wbaes/hy_table.bin \
    --work /tmp/w16/demos/wbaes
#    --table takes the *masked* segment bytes; an already-unmasked copy is re-XORed
#    by load_variant and gives 0/16. On an exported Mach-O use --binary instead:
python3 w16_probe.py --binary /path/to/wbaes_f4_max

# 5. W3 (traces need the patched header, so build them from this tree)
python3 ../trace_harness/build_traces.py \
    --binary /tmp/w16/demos/wbaes/wbaes_w16_clean --repo /tmp/w16 --work /tmp/w16/tr --n 64
python3 w16_traces.py --table /tmp/w16/demos/wbaes/hy_table.bin \
    --work /tmp/w16/demos/wbaes --traces /tmp/w16/tr/dl4_traces.bin
```

## 9. Verdict, in four lines

1. 16-bit column combining is expressible, AES-compatible, 20 %/17 % faster per block
   and costs no table volume — the engineering is real and it works.
2. It is not a key barrier: the encoding it needs is forced to be affine, the pair
   table becomes exactly XOR-separable, and one axis of it is still one key byte.
3. The measured work factor is 4,096 cheap tests for the whole key (2^8 per byte,
   down from 16,384), i.e. script-level. It is shipped anyway, as a performance
   generation, with that stated here and in README §5.29.
4. Shipped as the performance rewrite it is (2026-11-18), with the strength still
   booked where it was: DFA, seals, VM — not the table layer. README §5.29.
