# zk experiment: moving `rk0` from the lane-table input into the output bijection

> **Verdict: the move buys nothing.** It is not a wash — it is strictly worse than the
> shipped `wbaes_nl_*` design. The correction layer it needs is
> `P0 · MC · S · sigma_rk0 · S^-1 · sigma_d · MC^-1 · P0^-1`, and the middle of that
> expression *is* the AES S-box composed with one byte of round key. `S` is public, so
> `rk0` falls out of a single 256-entry table by inspection: **16/16 bytes in 0.00 s
> (after the 70 MB unmask)**, against the 3.1 s the shipped design's hidden-shift
> algebra needs. The same tables also hand over `rk1`, and with it the whole key
> schedule.
>
> The four committed attacks do die on the variant — but only in the sense that they
> return the all-zero key: the gauge-invariant test now certifies *"there is no key on
> the input side"*, which is true and useless. The weakest test is no longer algebraic;
> it is a table-shape read.

All numbers below are from this machine (macOS arm64, clang-16 16.0.6, Python 3.12.5,
stdlib only). The variant was built and measured entirely under `/tmp/wbaes-zkey/`;
`gen_hybrid.cpp` and `wbaes_hybrid.*` in the repository were **not** modified.

---

## 1. What was built

Starting point: a copy of `demos/wbaes/gen_hybrid.cpp` + `wbaes_hybrid.h`, with the
published challenge vector (`key 46f6abe5…`, `pt 6bc1bee2…`, `ct 80aadc09…`). Two
changes, nothing else:

**(1) round 0's lane tables lose the key.** `sp.rk_pre = nullptr` instead of `key`, so
every family (F0/F1/F2/F3) computes `MC(row,:) . S(pt)` — the input side of the round
is now key-free, which is the point of the experiment.

**(2) a new 4×4-byte layer `Z_k` between the round-0 boundary and the 32-bit recoding.**
The boundary still emits `P0(x)` with `x = MC . S(pt) ^ rk1`; `Z_k` must turn that into
`P0(x')`, `x' = MC . S(pt ^ rk0) ^ rk1`. The exact map, and its factorisation into four
256-entry tables per byte plus two public linear steps:

```
Z_k = P0 . MC . S . sigma_rk0 . S^-1 . sigma_d . MC^-1 . P0^-1        d = MC^-1 . rk1

  T0[j][u] = P0^-1[j](u)                    (undo the round's output bijection)
  u        = MC^-1 . T0(.)                   (code, public IMC)
  T1[j][w] = S^-1( w ^ d[j] )                (d folded in -> recovers pt[j])
  T2[j][x] = S( x ^ rk0[src(j)] )            src(j) = hy_sr_src(j + 4*col)
  u        = MC . T2(.)                       (code, public MC)
  T3[j][v] = P0[j]( v ^ rk1[j] )              (re-apply the output bijection)
```

16 tables per column (4 KB), 4 columns, appended **after** the schedule block at
`HY_ZK_OFF = HY_TABLES + HY_SCHED_BYTES`, so *every shipped offset is untouched* —
lane tables, 64K pair-decode tables, recoding, 64K boundary tables all stay where
`wblib.py` and the committed attacks expect them. New tag ids 168..183.

Two details that mattered while building it, both honest hazards of the construction:

* the key byte must be indexed by the **ShiftRows source** (`hy_sr_src(dst)`), not by
  `dst`, because the lane's byte is `S(state[src] ^ rk0[src])`;
* the `rk1` column constant must be removed **before** `S^-1`, i.e. as `d = MC^-1 . rk1`
  after the inverse linear step — `MC^-1(x ^ rk1) = MC^-1 x ^ MC^-1 rk1`.

### Artifact and correctness

| item | value |
|---|---|
| artifact | `/tmp/wbaes-zkey/zk/work/zk_table.bin`, 70,107,200 B |
| layout | 70,090,816 shipped + 16,384 new (+0.023 %) |
| env | pagesize 16384 / ncpu 10 / cls 128 → `0x25c99707` |
| mask seed | `0x024260bf` |
| schedule enc | F1 F2 F3 F0 F1 F2 F0 F3 F1 |
| schedule dec | F0 F1 F2 F0 F3 F1 F2 F0 F3 |
| `--fam 0/1/2/3` and mixed | `table-check PASS`, rc=0 for all five |
| `AES-128(6bc1bee2…, 46f6abe5…)` | `80aadc09777696c9d492a7e53b3b15b0` ✓ |
| trace-enabled runtime (harness) | `ct:80aadc09…` ✓, 1528 accesses/block |

The generator's own checks are the evidence for "the ciphertext is unchanged": it
compares the table path against a straight AES reference on the test vector *and* on 8
random plaintexts, in both directions, for the mixed schedule and for each of the four
forced families.

## 2. The four committed attacks, on the variant

| attack | needs | result on the variant | cost |
|---|---|---|---|
| `hs_attack.py` | unmasked tables | **16/16 bytes, all `0x00`** — decoy; `AES(pt, 0…0) = cf2ea38a…` ≠ shipped | 3.07 s algebra / 19.0 s total |
| `consistency_attack.py` | 64 real address traces | **16/16 bytes, all `0x00`** — decoy; 8/8 halves unique | 0.02 s |
| `bge_attack.py` | unmasked tables | **0/16**, step 1 unchanged (see below) | 15.6 s |
| `dca_attack.py` | traces / model | **0/16** in both experiments | 1.6 s |

### (a) `hs_attack.py` — the gauge-invariant test still "succeeds", on nothing

```
$ python3 hs_attack.py --table …/zk_table.bin --work …/zk --key 46f6abe5…
   candidates over all 64 (col,lane,row) byte positions: min 1 median 1 max 1
   the four MC rows agree on the candidate set for 16/16 (column, lane) pairs
   recovered key: 00000000000000000000000000000000
   reproduces the shipped ciphertext: NO
```

Every byte position has exactly one candidate and that candidate is `0x00`, because the
lane table now reads `val = m . S(pt)` and the affine-consistency test is asked whether
`m . S(P0^-1(enc) ^ g)` is an affine image of it — which is true exactly for `g = 0`
(the same "wrong g never fits" fact the shipped attack relies on, just with the key
removed). So the test did not get weaker, it got *content-free*: its 2^70.2 gauge is
still there, and the key it used to discriminate is no longer inside the object it
measures. **This is the honest answer to "does the gauge test still recover 16/16": it
returns 16/16 bytes, and they are all zero.**

### (b) `consistency_attack.py` — the boundary index stopped leaking, and says so

64 traces from the trace-enabled variant runtime (`ct:80aadc09…`, so the traces are
evidence):

```
   col 0: u is a function of the left pair sum (conflicts 8), equals it on 0/64 …
   col 0 half 0:     6 collision pairs -> 1 candidate 2-byte key(s)  ['0x00x0']
   …
   recovered key: 00000000000000000000000000000000
   64 traces: 8/8 halves with exactly 1 candidate; 32 traces: 3/8
```

On the shipped artifact the same script reports **conflicts 0** ("u is a function of the
keyed pair sum, 0 conflicts") and recovers the real key from 64 traces. Here the
conflict count is 5–10 of 64: the index is still a clean function of a pair sum, just of
the *key-free* one, so the MITM's unique survivor is `(0,0)`. The index leak is closed;
what replaced it is a table-shape leak (section 3).

### (c) `bge_attack.py` — unchanged

```
   Off those, 992/122400 = 0.0081 reproduce, against 1/256 = 0.0039 …
   -> Q is not D0[a]^D1[b] … step 3 has no lane inverse to work with
   all four MC rows agree on the candidate set: True
   incomplete (0/16 bytes)
```

Shipped artifact for comparison: `974/122400 = 0.0080`, also 0/16. The pair-decode
tables were not touched, so this attack is bit-for-bit in the same place — blocked by
`Z`, exactly as before. (The variant's round-0 lane tables carry no key at all now, so
even if step 1 had succeeded there would be nothing to peel.)

### (d) `dca_attack.py` — unchanged

```
   slots whose index is bit-exactly P0(pt) on every trace: 16/16
     tag F1 (kind 144) half 0: candidates per column [0,0,0,0] -> 0/16 key bytes
   incomplete: 0/16 bytes
```

Identical to the shipped artifact (0/16, same per-tag candidate counts). Addresses were
never the problem here, and moving the key to the output side did not create one — see
§3 step 2b: the new keyed S-box lookups have `index == pt[src]` on 1024/1024 traced
accesses.

## 3. The new weakest test: read the shape off the new tables

`attacks/residual/zk_attack.py` (new). It needs the unmasked table only — no traces, no
group decomposition, no search:

```
$ python3 zk_attack.py --table …/zk_table.bin --work …/zk --traces …/zk_traces.bin
== 1. the shipped gauge-invariant test (hs_attack's step 2) ==
   64 byte positions: candidates min 1 median 1 max 1, 3.08s
   distinct candidate values over all positions: [0]
   the test's answer: 00000000000000000000000000000000
== 2. the test the variant hands over: shape of the Z_k tables ==
   (col,byte) positions with a single rk0 candidate: 16/16
   (col,byte) positions with a single rk1 candidate: 16/16
   S^-1(T2[x]) ^ x is constant for all 256 x in 16/16 tables (0.00s)
   rk0 = 46f6abe52990556a6713141f65fed9a5
   rk1 = fcc3ada8d553f8c2b240ecddd7be3578
   key schedule of rk0 gives rk1 = fcc3ada8d553f8c2b240ecddd7be3578 -> MATCH
== 2b. and the addresses of that layer are key-free ==
   keyed S-box lookups traced: 1024; recovered index == pt[src] on 1024 of them
== 3. verify ==
   AES-128(6bc1bee2…, rk0) = 80aadc09777696c9d492a7e53b3b15b0
   reproduces the shipped ciphertext: YES      equals the published key: YES
   cost: 2 x 256 table lookups per key byte; 18.55 s total, 15.45 s of it the 70 MB unmask
```

Two table reads per byte, both one-liners:

```
T2[x] = S(x ^ rk0[src])      ->  rk0[src] = S^-1(T2[x]) ^ x        (constant for all x)
T3[x] = P0(x ^ rk1[dst])     ->  rk1[dst] = x ^ P0^-1(T3[x])       (P0^-1 is T0, right there)
```

Neither is an accident of how I wrote the generator: **both are forced.** To move `rk0`
past the S-box you must materialise `S ∘ sigma_rk0` (or `S^-1 ∘ sigma_d`) as a
256-entry table, and the AES S-box is a public permutation, so that table is a
fingerprint of the key byte with 256 possible alignments. The same argument covers the
`rk1` side: the layer needs `P0^-1` to get back into the S domain, and `P0^-1` plus
`P0 ∘ sigma_rk1` is a two-line solve for `rk1`. Recovering `rk1` is as good as `rk0`
here, because the key schedule inverts: `rk1` gives the master key in the clear.

### The other implementation, and why it is worse

The only alternative is to keep `S` unkeyed in the table and XOR the key byte in code
between `T1` and `T2` (with a random byte folded into `T1` so the constant in the
binary is not the key). That does not help either, and it is strictly worse: the value
being XORed is the *index of the `T2` lookup*, and because `T1`'s output is
`S^-1(P0^-1(y) ^ d) = pt[src]`, that index is `pt[src] ^ rk0[src]` — one address trace,
0.00 s, one equation per byte. The variant I did build is the *stronger* of the two
placements (key in table values, address key-free, verified on 1024/1024 traced
lookups) and it still falls to a shape read. So the choice is: key on an address
(traces), or key in a known-shape table (algebra). There is no third option inside a
byte-slice chain.

## 4. Cost

| | shipped | variant |
|---|---|---|
| table bytes | 70,090,816 | 70,107,200 (+16,384) |
| table lookups / block | 1464 | 1528 (+64) |
| encrypt | 8.61 µs/block | 8.76 µs/block (+1.7 %) |

Measured with one benchmark source compiled against each header, 4000 blocks, best of
five, after a warm-up that pays the unmask. The added layer costs one extra 256-entry
lookup per byte of round 0 (16 × 4) and four GF multiplies per column.

## 5. What this implies

Key-dependent output encodings cannot close this hole in this design, and the reason is
structural rather than a matter of care. The move exists because `rk0` currently sits
where the round's *input* is, and the gauge-invariant affine test is invariant precisely
in the output-side label; to escape that test the key has to be pushed through the
S-box, and pushing it through the S-box means some 256-entry table in the artifact must
compute `S(x ^ k)` or `S^-1(x ^ k)` up to a compensation that is itself forced (the
neighbouring stage is `MC`, which is public and linear, so nothing can be absorbed
there). A public S-box with a hidden input translation is a 256-way fingerprint, which
is why the variant is broken in 0.00 s where the shipped design cost 3.1 s of real
algebra. The mirror-image placement does not help either: an XOR that is *not* composed
into an S-box has to be applied to a value in code, and then it is a table index, and an
index is a byte in an address trace — one trace, 16 equations, no masking survives it,
because the masked value *is* the address. The design does have one placement that has
never leaked: the decryption tail already puts `rk0` inside a 16-bit pair table
(`outv[a] = Di[0][a] ^ key`), where the XOR is absorbed by the translation gauge that
the pair table cannot reveal — i.e. the XOR is hidden by 16 bits of table index, not by
an 8-bit encoding. That is the whole lesson: what has ever resisted here is *width*, not
sideness. The only way to move `rk0` into the linear-layer output without publishing it
is to put it inside a table whose index is at least 16 bits wide and whose output is the
full 32-bit column word, so that no table of known shape exists anywhere in the chain
and the key is protected by the same `|GL(8,2)| · 2^8 = 2^70.2` hidden-shift gauge the
pair-decode tables already provide — i.e. wide-table nonlinear fusion (2^16 entries ×
32-bit output, no per-lane XOR followed by an output bijection), not a key-dependent
per-lane encoding. Conversely: any design that keeps the key in a byte-slice table, on
either side, will keep falling to a 256-comparison fingerprint or a single trace.

## 6. Scope, and what was not done

* No Mach-O was built for the variant: the committed attacks were given a raw-artifact
  path (`--table/--work` for `hs_attack.py`, `--table/--p0/--seed` for
  `bge_attack.py`, `--p0` for `dca_attack.py`, `load_variant()` in `reslib.py`). Their
  analysis code is untouched; only the artifact loader is new.
* `consistency_attack.py` was run on 64 traces only (the shipped artifact's curve shows
  64 is already enough: 8/8 halves unique). The 4096-trace curve was not repeated.
* `recoding_peel.py` and `cross_instance.py` were not re-run: neither touches round 0's
  key placement, and the recoding is unchanged by the variant.
* The variant's `T2`/`T3` tables were *not* additionally masked (e.g. `T2[x] =
  gamma(S(x ^ k))` with `gamma` absorbed into the recoding). That is not implementable
  without changing the round function: the stage after `S` is `MC`, so `gamma` cannot be
  cancelled by a neighbouring per-byte table — the AES function forces the table to be
  `S ∘ sigma_k` exactly. That is the point of §5, and it is also why no variant of this
  construction can be "hardened" by adding output encodings.
