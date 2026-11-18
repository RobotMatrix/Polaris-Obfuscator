# Wide-table nonlinear fusion: built, measured, and it does not raise the bound

> **Verdict: two 2^16-index pair tables per column do not hide `rk0`.** The reason is
> not the pair table — it is the table where the two halves *meet*. A correct AES
> white-box has to add two 8-bit partial sums per output byte, so some 2^16-entry table
> with 8-bit values has to exist, and every row of such a table is a permutation of 256
> values. That is the object the hidden-shift decomposition needs, and it recovers the
> per-byte encodings up to the same `|GL(8,2)| · 2^8 = 2^70.2` gauge. Once the encodings
> are known, one axis of a 2^16 pair table is still *one key byte*: 256 guesses, one
> 256-entry affine-consistency test each.
>
> Measured on a faithful model of the round-0 layer: **16/16 key bytes, 1 candidate each,
> 16 table decompositions, 16,384 affine-consistency tests** — the same work factor
> `hs_attack.py` needs on the shipped artifact (32 decompositions, the same 16,384 tests).
> The model's 1.3–1.5 s wall time is *not* comparable to the shipped script's 19.7 s: the
> model holds its tables in memory and pays no unmask and no scattered reads. The honest
> claim is "the fusion buys nothing", not "it is faster". Volume −0.41 %, per-block cost
> unchanged.
>
> The four committed residual scripts and `zk_attack.py` all die on the variant, but only
> because they read the shipped offsets: `wblib.py`'s `SCHED_OFF` is 70,090,816 and the
> fused artifact is 69,800,512 B. Nothing in their *mathematics* was blocked.
>
> So this generation was not shipped: the key was not rotated, no `wbaes_wf_*` binary was
> exported, and `gen_hybrid.cpp` / `wbaes_hybrid.*` / `hy_table.bin` in the repository are
> untouched. What ships is this measurement and `wf_probe.py`, which reproduces it.

All numbers below are from this machine (macOS arm64, clang-16 16.0.6 at
`src/build/bin/clang++`, Python 3.12.5, stdlib only). The variant was built and measured
entirely under `/tmp/wbaes-wf/`.

---

## 1. The spec as written cannot be built

The brief asks for, per column, two tables

```
T[a][b] = Z32( MC(row,*) . (S(a^k0), S(b^k1)) )        bytes 0,1 and bytes 2,3
```

with `Z32` a 4-round 32-bit nonlinear bijection, and the two 32-bit outputs combined into
the column. The combination is where it breaks. For the runtime to produce output byte
`r` from the two words it needs

```
out_r = byte_r( Z32^-1(W_left) ) ^ byte_r( Z32'^-1(W_right) )
```

and to do that with a table, `byte_r( Z32^-1(W) )` must be a function of `byte_r(W)`
alone. It is not, once `Z32` mixes: measured on the model, holding `W[0]` fixed across
4096 random words gives **256 distinct `W[0]` values and 3827 of them carry two different
pre-image bytes**. So no merge table indexed by two output bytes exists.

The only runtime that can combine the two words is one that applies `Z32^-1` in *code* —
and `Z32`'s S-boxes and constants are in the blob, so `Z32^-1` is public, and applying it
hands the attacker `u` and `v` verbatim with no encoding in between. That is strictly
worse than the shipped design, which at least keeps an 8-bit encoding in the way.

Measured by `wf_probe.py` step 0 (`python3 wf_probe.py`):

```
   byte 0 of Z32^-1(W) held against byte 0 of W over 4096 random words:
   256 distinct W[0] values, 3827 of them carry two different pre-image bytes
```

The well-defined shape is therefore the one built below: byte encodings inside the pair
tables, a 2^16 merge table that inverts them, and the 32-bit nonlinearity applied to the
*completed* column (the round recoding, now four rounds instead of three). That is the
shape this document measures.

## 2. What was built

A copy of `gen_hybrid.cpp` + `wbaes_hybrid.h` under `/tmp/wbaes-wf/work/`, with the four
per-lane shapes replaced by one wide shape. Per (direction, round, column), 786,432 B:

| region | bytes | contents |
|---|---|---|
| `[0, 262144)` | 2^16 × 4 | pair table for bytes 0,1: byte `r` = `E[0][r][ m[r][0].S(b0^k0) ^ m[r][1].S(b1^k1) ]` |
| `[262144, 524288)` | 2^16 × 4 | pair table for bytes 2,3, same shape with `E[1]` |
| `[524288, 786432)` | 4 × 2^16 | merge table per output row: `P[r][ E[0][r]^-1(x) ^ E[1][r]^-1(y) ^ rk_after[r] ]` |
| `[786432, 794688)` | 8,256 | the 32-bit recoding: 4 rounds × 4 bytes × (S, S^-1) + 16 constants |

`E` is a random per-build 8-bit bijection per (side, row); its inverse exists only inside
the merge table, and the generator burns both after the tables are written. There is no
8-bit-indexed lane table anywhere and no 256-entry table of any kind except the recoding
S-boxes. 144 column slots: 2 per column × 4 columns × 9 rounds × 2 directions.

Layout, from `wbaes_hybrid.h` in the variant: `HY_COL = 794,688`, `HY_ROUND =
3,178,752`, `HY_MC = 28,608,768`, `HY_PAIRS = 1,048,576`, `HY_TABLES = 69,795,840`,
`HY_TOTAL = 69,800,512`.

The VM is untouched: every family byte is 0, which is the branch that reads
`base + round*stride + col*col_stride + (k>=2 ? pair_stride : 0)`, and the generator writes
`pair_stride = 262144`. So the 288 offsets still come from `hsvm_entry` and the host still
reads them out of `hsvm_mem`.

### Artifact and correctness

| item | value |
|---|---|
| artifact | `/tmp/wbaes-wf/work/wf_table.bin`, 69,800,512 B |
| shipped for comparison | 70,090,816 B → **−290,304 B (−0.414 %)** |
| env | pagesize 16384 / ncpu 10 / cls 128 → `0x25c99707` |
| mask seed | `0x5d437f5a` (four-word XOR, as shipped) |
| seal | `0x10c216af` |
| `gen_hybrid` | rc 0 in 1.16 s, `table-check PASS`, `seal-check PASS`, `spn-mds: PASS` |
| `AES-128(6bc1bee2…172a, 4f065a03…4c66)` | `7672415a6313c58518fc95c9cb6922b8` ✓ |
| demo | `vector-match: PASS`, `roundtrip: PASS` |

The generator's own checks are the evidence for "the ciphertext is unchanged": it compares
the table path against a straight AES reference on the test vector and on 8 random
plaintexts, in both directions. Round 0's input bijection, the mask, the seals, the DFA
double pass, the pair maps and the decryption tail are the shipped code, untouched.

## 3. The five committed scripts, on the variant

Run as-is against the raw table / the built binary. None reaches its mathematics — all
five stop at the artifact loader, because `wblib.py` still holds the shipped geometry:

| script | outcome | why |
|---|---|---|
| `hs_attack.py --table … --work …` | `IndexError: index out of range` (`reslib.py:75`) | `wb.SCHED_OFF` = 70,090,816 > 69,800,512, so the schedule read leaves the file |
| `consistency_attack.py --binary …` | `TypeError: %x format: an integer is required, not NoneType` (`build_traces.py:99`) | the mask seed search reads the schedule block at the shipped offset and finds nothing |
| `bge_attack.py --table … --p0 … --seed …` | `IndexError: index out of range` (`bge_attack.py:139`) | same schedule offset |
| `dca_attack.py --binary …` | `TypeError: … not NoneType` (`dca_attack.py:292`) | same mask-seed path |
| `zk_attack.py --table … --work …` | `SystemExit: 69800512 bytes, expected 70107200` | it asserts the zk-layout length |

That is not the fusion defeating them; it is the fusion having a different `HY_TOTAL`.
Recording it as a pass would be the kind of self-deception `WB-DESIGN-V2.md` §13.5 was
written against.

## 4. The same two steps, re-pointed: `wf_probe.py`

`attacks/residual/wf_probe.py` builds the round-0 layer above (all four columns) and runs
`hs_attack.py`'s two steps against it, with the readers pointed at the wide tables:

1. `reslib.Decomp` on each of the 16 merge tables — each is `Z(D0[a] ^ D1[b])` by
   construction, rows are permutations, so this is unchanged and costs 0.14 s for 16;
2. the axis test: read the pair table at logical index `(a, 0)` or `(0, b)`, push each byte
   through the recovered inverse, and ask `reslib.key_candidates` for the key byte.

```
$ python3 wf_probe.py
== 1. build the round-0 layer (4 columns, 8 pair tables, 16 merge tables) ==
   built in 0.75s
   network == MC(row,:).S(pt^rk0) under the output bijection: 1024/1024 positions
== 2. step 1: LAM decomposition of the 16 merge tables ==
   16/16 decomposed, each Z a bijection in 16/16
   lane labels pinned up to |GL(8,2)| * 2^8 = 1369104324918194995200 = 2^70.2
   0.14s
== 3. step 2: gauge-invariant axis test on the 2^16 pair tables ==
   lane  col  true   candidates        verdict
      0    0  0x4f  ['0x4f']          HIT
      1    0  0x16  ['0x16']          HIT
      2    0  0x5f  ['0x5f']          HIT
      3    0  0x66  ['0x66']          HIT
      …  all 16 …
   16 byte positions, 0.32s
== 4. result ==
   recovered key: 4f065a03ee16cf8c31b15fd8f0344c66
   reproduces the shipped ciphertext: YES
   work factor: 16 merge decompositions + 64 x 256 affine-consistency
   tests on a 256-entry axis; no search over Z, no traces; 1.50s total
   width changed nothing: the axis of a 2^16 table is still one key byte.
```

Control, same machine, same published key:

```
$ python3 hs_attack.py                     # shipped wbaes_vm2_clean
   recovered key: 4f065a03ee16cf8c31b15fd8f0344c66
   work factor: 16384 affine-consistency tests, 32 group recoveries
   19.73s total (3.53s algebra)
```

So the work factor is the same: 16,384 affine-consistency tests either way, 16 group
recoveries instead of 32. The wall-clock gap (0.46 s of model algebra against 3.53 s for
`hs_attack.py`) is mostly bookkeeping — `hs_attack.py` pays for ~2.1 M scattered byte reads
through Python, `wf_probe.py` builds its tables as Python lists and pays nothing. Pointing
the fused artifact's readers at the real bytes would put it back in the same 2–4 s band.
**No better, no worse: the width did not enter the work factor at all.**

### Why the axis works at all

For lane `k`, row `r`, the pair table holds
`E[r][ m[r][2s].S(P0^-1(a) ^ k_2s) ^ m[r][2s+1].S(P0^-1(b) ^ k_2s+1) ]`. Fix `b = 0`: the
second term is a constant, so the 256 entries along `a` are `E(m[r][2s].S(P0^-1(a) ^ k_2s)
^ const)`. Peel `E` with the merge table's recovered inverse and what is left is an affine
image of `m . S(P0^-1(a) ^ g)` — exactly the object `reslib.linear_image_ok` tests, and it
fits for exactly one `g`. The same construction gives the other lane from `(0, b)`.

Widening the index from 8 bits to 16 does not change that: it changes how many entries the
attacker has to read (65,536 instead of 256) and costs him one Python list slice.

## 5. The families are gone, and that is not cosmetic

With one shape there is no lane dimension, so `F1/F2/F3` were retired rather than kept as
dead bytes. This is forced, not chosen: the HSV bytecode branches on the family byte
(`brz r4` → pair layout, else `k * lane_stride`), so a nonzero family byte now computes
offsets for a lane stride that no longer exists. Measured, `--fam 1`:

```
$ gen_hybrid hy_table.bin --fam 1        # rc 0, table-check PASS (generator-side)
$ ./demo_fam1
ciphertext: 824fff3a0ffc9fdc066c5edb09001a04     expected 7672415a6313c58518fc95c9cb6922b8
vector-match: FAIL
```

So the mixed schedule's shape diversity — the one property `--fam 0..3` existed to
demonstrate — cannot be expressed at all under fusion. That is a real loss, and it is the
second reason this generation was not shipped.

## 6. Gates that do hold on the variant

| gate | command | result |
|---|---|---|
| ciphertext identity | `./wbaes_wf_clean` | `7672415a6313c58518fc95c9cb6922b8` PASS, roundtrip PASS |
| VM is in the artifact and live | `-DWBAES_VM_SCHEDTEST` | intact `7672415a…` PASS; byte 48 flipped → `b347347a9dda3491a0098cdf3455ad10`; restoring returns `7672415a…` |
| DFA double pass | `-DWBAES_DFA_SELFTEST` | `deb49e302e45df13655c8c38e796f067`, roundtrip `6c3e3f5b7fcd20da…`, `vector-match: FAIL` (junk, as specified) |
| VM offset program | `tests/test_vm_offsets` | `vm-offsets: PASS` (288-offset plan, foreign layouts, short/null table) |
| generator self-checks | `gen_hybrid` | rc 0, `table-check PASS`, `seal-check PASS`, `spn-mds: PASS` |

## 7. Cost

| | shipped (`wbaes_vm2_clean`) | wide fusion |
|---|---|---|
| table bytes | 70,090,816 | 69,800,512 (−0.41 %) |
| table lookups / column | 4 lane + 8 decode + 4 boundary + 12 recoding = 28 | 2 pair + 4 merge + 16 recoding = 22 |
| `bench_wbaes 3000`, run 1 | 17.24 / 16.67 µs | 16.57 / 16.91 µs |
| run 2 | 20.23 / 17.20 µs | 17.71 / 17.30 µs |
| run 3 | 18.48 / 17.01 µs | 16.99 / 17.17 µs |

Best of the three runs: encrypt 17.24 → 16.57 µs (−3.9 %), decrypt 16.67 → 16.91 µs
(+1.4 %). The machine's run-to-run spread on the same binary is 17.24–20.23 µs, so the
honest statement is: **no measurable change**. Fewer, wider lookups trade the 4 KiB
lane-table cache residency for two 256 KiB random accesses per column, and it comes out
even.

## 8. What this implies

The failure mode is not "the key is on the wrong side of the lane" and it is not "the table
is too narrow". It is that **the sum is 8 bits wide**. AES's round output byte is
`XOR` of four `GF(2^8)` products; whatever the tables look like upstream, that XOR has to
happen somewhere, and in a table network it happens in a 2^16-entry, 8-bit-valued table
whose rows are permutations — which is exactly the object a hidden-shift decomposition
eats. Widening the *index* of the tables that produce the partial sums (this document)
does not change it; widening the *output* of those tables does not change it either,
because the merge table still has to invert one 8-bit encoding per side.

Two consequences worth writing down before the next attempt:

1. **Any AES white-box of this family is breakable in ~2^16 cheap tests per key byte by a
   table-read attacker.** Four generations of measurement now agree on this. The next
   structural step cannot be another rearrangement of AES's byte-slice tables; it has to be
   a construction whose combining operation is not 8-bit (space-hard ciphers, or a cipher
   with wider S-boxes) — or the honest acceptance that the table layer hides state, not
   keys, and that the remaining strength is DFA + seals + the VM.
2. **The gate should be stated as work factor, not as "these five scripts fail".** All five
   returned nothing on this variant and the construction is still broken in 0.46 s. A
   script that aborts on an offset is evidence about the offset.

## 9. Scope

* Not shipped: no key rotation, no `exported-binaries/wbaes-challenge/macos/wbaes_wf_*`, no
  change to `gen_hybrid.cpp`, `wbaes_hybrid.h`, `hy_table.bin` or `sha256.txt`. The variant
  lives only under `/tmp/wbaes-wf/`.
* `wf_probe.py` builds its tables in Python, so its 1.50 s is model construction +
  algebra, not a 70 MB unmask. The 0.46 s algebra figure is comparable to `hs_attack.py`'s
  3.53 s; the unmask is not (the shipped script pays it, the model does not).
* `wf_probe.py` attacks **round 0 only**. It recovers `rk0`, which *is* the AES-128 master
  key, so the rest of the schedule is a key-schedule evaluation, not an attack.
* Only the mixed schedule was measured on the built artifact; `--fam 1..3` cannot produce a
  correct artifact (section 5), so the usual "four forced families agree" check has no
  meaning here.
* The decryption path, `recoding_peel.py` and `cross_instance.py` were not re-run: the
  recoding gained a round but is structurally the same, and the decryption entry/tail are
  the shipped code.
