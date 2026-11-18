# dl6 — round key 0 folded into the output side (rk0-in-Z): built, measured, **red**

> **Verdict: the change is correct, and it is strictly worse.** Moving `rk0` from
> round 0's S-box input to the output-side relabelling does make `hs_attack.py` stop
> seeing the key — the unchanged script now returns 16/16 bytes of `00` — but the key
> only moved to a place where reading it is **cheaper**: the layer the move needs
> contains `S ∘ σ_rk0` (or a one-byte-spaced composite of it) as a 256-entry table, so
> `rk0` (and `rk1`, which inverts the key schedule) fall out by table inspection in
> **0.01 ms**, against the **3.33 s** of algebra the shipped dl5 design costs on this
> host. That is a factor of ~3×10^5 the wrong way. dl6 is therefore **not** shipped;
> `gen_hybrid.cpp`, `wbaes_hybrid.h` and every exported binary are untouched, and the
> dl5 / nl / f4 generations still build exactly as before.
>
> The four committed attacks do go quiet on the variant (bge 0/16, dca 0/16 in both
> experiments, consistency and hs return all-zero keys), but that is not protection:
> it is the same "there is no key on the input side" answer, which is true and
> useless. §5 shows why no placement inside this round function can do better.

All numbers below are from this machine (macOS arm64, Apple clang 17.0.0, Python
3.12.5, stdlib only), from commands listed in §8. This experiment's key and
ciphertext are recorded **here and nowhere else** in the tree (the generator takes
the key on the command line; there is no key header for dl6):

```
master key  cd241e042dacdcc4899d8339260a0ec5
plaintext   6bc1bee22e409f96e93d7e117393172a
ciphertext  8190951ad006be2872ca95e886b993a5      (openssl enc -aes-128-ecb)
```

None of `3acb79e7…`, `46f6abe5…`, `4f065a03…` is reused.

---

## 1. What dl6 is

dl5's round 0 computes, per output byte `dst = row + 4·col`,

```
y0[dst] = XOR_k MC[row][k] · S( pt[sr_src(k+4col)] ^ rk0[sr_src(k+4col)] ) ^ rk1[dst]
```

so `rk0` sits where the round's *input* is. `hs_attack.py` measures exactly that: it
decomposes the 32 pair-decode tables `Q = Z(D0 ^ D1)` up to the hidden-shift gauge
(|GL(8,2)|·2^8 = 2^70.2, printed by the script), reads each lane word back through
`D = E^-1`, and asks the gauge-invariant question "is this value an affine image of
`m·S(pt ^ g)`?". Only `g = rk0[src]` answers yes.

dl6 removes `rk0` from the S-box input and puts it into the output-side relabelling.
Round 0's lane tables now compute `MC·S(pt)`; a 4-byte layer between round 0's
boundary and round 1 puts the key back, per column:

```
y0  = MC·S(pt) ^ rk1                 # what round 0 now produces (key-free)
w   = IMC(y0) = S(pt) ^ d,  d = IMC(rk1)
z   = U(w)                           U[j][v] = S( S^-1(v ^ d[dst]) ^ rk0[src(dst)] )
y0' = MC(z) ^ rk1                    # = MC·S(pt ^ rk0) ^ rk1  — dl5's value, bit-exact
out = P[0](dst)( y0' )               T[j][z'] = P[0][dst]( z' ^ rk1[dst] )
```

`P[0]` is round 0's own output bijection (random, and it exists only inside the
boundary table), so the layer also carries its inverse `Pi[0]` as a table — that is
the difference from the `/tmp` experiment in `attacks/residual/ZK-EXPERIMENT.md`,
which reused `P0` and therefore had to sit in a different domain.

Why this is the only correct placement: `S(pt ^ rk0)` is not a linear function of
`S(pt)`, so the key cannot be moved past the S-box by any linear map. Anything that
computes the keyed round output from the key-free one must contain, somewhere, a
256-entry table that applies `S` to a translated byte (or `S^-1`, or the two composed
with one byte of spacing). dl6 merges the two stages into `U` — one table per byte —
which is the cheapest and least readable form of that map that still works, and the
measurement in §4 says what it costs an attacker: 2^16 candidate `(d, k)` pairs per
byte instead of 2^8, i.e. **0.88 ms instead of 0.01 ms**.

**r0 stays 16 bytes wide?** No: the round output the rest of the network sees is
bit-identical to dl5's, so rounds 1–9, the schedule block, the recoding, the mask and
the seals are unchanged. Table size grows by exactly the layer: 12,288 B.

### Decryption needed no inverse — and why

The task asked for "the key absorbed into Z (and its inverse for decryption)". No
`Z^-1` table is materialised, because the decrypt chain never passes through the
layer: it inverts round 1 (`IMC(x ^ rk1)`) and then round 0's S-box
(`S^-1`) analytically, landing on `pt ^ rk0` and removing the key in the tail pair
table (`outv[a] = Di[0][a] ^ key`), exactly as dl5 does. dl6's layer output *is*
dl5's round-0 output, so the whole decrypt path — 9 `dec_mc` rounds, 9 pair maps, the
tail — is byte-for-byte the dl5 code (verified by the generator's roundtrip checks,
§3). The consequence is worth stating in the other direction too: **dl6 leaves `rk0`
in a 16-bit pair table on the decryption side**, which is the one placement
`ZK-EXPERIMENT.md` §5 says has never leaked. The encryption side is where the move
costs.

## 2. Generator diff (dl5 `gen_hybrid.cpp` → `gen_dl6/gen_dl6.cpp`)

Four changes, nothing else. The dl5 generator and header were taken verbatim from
`702ec6dcb` (`demos/wbaes/gen_hybrid.cpp`, `wbaes_hybrid.h` at that commit) so the
comparison is against the dl5 shape, not against the current F4 one.

1. **Round 0 loses the key**: `sp.rk_pre = (r == 0) ? key : nullptr;` → `sp.rk_pre = nullptr;`.
2. **The layer**: new `fill_rkz()` writes, per column, 4 `Pi[0]` tables, 4 `U`
   tables, 4 `T` tables (tags 168..171 / 184..187 / 188..191, byte-indexed scatter
   `hy_store8t`); `hy_rkz_apply()` in the header reads them. The driver applies it
   between `hy_rec_undo(round 0)` and `hy_mc_round(round 1)`:
   `if (r == 1) hy_rkz_apply(tab.data(), s, env);` — the same place `wbaes_hybrid.inc`
   would have to call it.
3. **The key comes from the command line** (`--key <32 hex>`), and the self-check
   compares the table path against `ref_encrypt` instead of a baked `test_ct`, because
   dl6 has no key header (deliberately: no key material in the tree).
4. **Layout**: `HY_TOTAL_DL5 = HY_TABLES + HY_SCHED_BYTES` stays; the layer is
   appended at `HY_RKZ_OFF = HY_TOTAL_DL5`, `HY_RKZ_COL = 12·256`,
   `HY_RKZ_BYTES = 4·HY_RKZ_COL`; `HY_TOTAL = HY_RKZ_OFF + HY_RKZ_BYTES`. Every dl5
   offset (`Q_OFF`, `SPN_OFF`, `BDY_OFF`, `COL`, `HY_ROUND`, decrypt base/strides,
   schedule block) is unchanged, which is what lets the committed readers
   (`wblib.py`, `reslib.py`, the attacks) work on it without modification.

Files added, all under `demos/wbaes/gen_dl6/`:

| file | what |
|---|---|
| `wbaes_hybrid_dl6.h` | dl5 header + layer constants, `hy_aes_mc/imc`, `hy_rkz_apply` |
| `gen_dl6.cpp` | dl5 generator + the four changes above |
| `verify_dl6.py` | independent reader (wblib + the layer) vs `openssl` |
| `dl6_traces.py` | builds the 5-hook trace harness and the bench against one table |
| `dl6_harness.cpp`, `dl6_bench.cpp` | traced / timed copy of the round walk |
| `rk0_in_z_attack.py` | the attack the move hands over (shape scan + key reads) |

`gen_hybrid.cpp`, `wbaes_hybrid.h`, `wbaes_hybrid.inc`, `wbaes_vm.*` and the exported
binaries were not modified (`git status` in §8).

## 3. Correctness

| check | result |
|---|---|
| generator self-check: `ref_encrypt` vs `ref_decrypt` on the test vector | PASS (prints `8190951a…`) |
| table path vs AES reference, test vector | `table path == AES reference on the test vector: PASS` |
| table encrypt + decrypt roundtrip, test vector | `encrypt+decrypt roundtrip on the test vector: PASS` |
| 8 random plaintexts, both directions, table vs reference | PASS (generator returns 0 only if all match) |
| round key search in the finished table (`table_has_key`, rk0..rk10 as 16-byte runs) | no hit (generator returns 0) |
| **independent** reader (`verify_dl6.py`: table bytes + `hy_in.h`, no generator code) vs `openssl` | **7/7 vectors match** |
| trace-enabled harness ciphertext | `ct:8190951ad006be2872ca95e886b993a5` (the openssl value, so the traces are evidence) |

`verify_dl6.py` output (first lines):

```
table /tmp/wbaes-dl6/work/dl6_table.bin (70103104 B), mask seed 0x7f716422, schedule ['F1','F2','F3','F0','F1','F2','F0','F3','F1']
  pt 6bc1bee22e409f96e93d7e117393172a -> table 8190951ad006be2872ca95e886b993a5  openssl 8190951ad006be2872ca95e886b993a5  OK
  ...
7/7 vectors match openssl AES-128-ECB
```

The intermediate state was checked against the AES formula while building it, which
is how the one real bug in the layer was found (`hy_mds` is the *recoding's*
circulant `(1,4,3,7)`, not AES MixColumns): with the fix, the layer maps

```
round-0 output, decoded   58090759e5cf3a98727ac965fd3f2efd   (key-free: MC·S(pt) ^ rk1)
after the layer, decoded  210f80a0116ac5897d92026b94fba47f   (keyed:    MC·S(pt^rk0) ^ rk1)
```

which is the keyed value computed independently from the key. The debug prints were
removed before the final build; this paragraph is the record of that check.

## 4. Attacks, unchanged, on dl6

Artifact: `/tmp/wbaes-dl6/work/dl6_table.bin`, 70,103,104 B, mask seed `0x7f716422`,
schedule enc `F1 F2 F3 F0 F1 F2 F0 F3 F1`. Unmask is 15.5–16.4 s of the totals below
(Python; the C unmask is 0.19 s, `DATA-LAYER.md`).

| attack | needs | result on dl6 | wall time | diagnostic |
|---|---|---|---|---|
| `hs_attack.py` (gate) | unmasked tables | **16/16 bytes, all `0x00`** — decoy, `AES(pt, 0…0) = cf2ea38a…` ≠ `8190951a…` | 19.6 s total, **3.14 s algebra** (vs **3.33 s** on nl, same host, cached unmask) | 64 byte positions: candidates min 1 median 1 max 1, and the unique value is `0` everywhere; the gauge-forced (dl4) test gets 0 candidates |
| `consistency_attack.py` | 64 real traces | **16/16 bytes, all `0x00`** — decoy | 0.02 s | index still a function of the *key-free* pair sum (conflicts 6–9/64, equals it on 0–3/64); 8/8 halves unique, all `(0,0)` |
| `bge_attack.py` | unmasked tables | **0/16** | 17.8 s | `0.0081` of off-axis entries fit (random 0.0039) — same as shipped; pair tables untouched |
| `dca_attack.py` | traces | **0/16** in both experiments | 2.3 s | A: lane index is bit-exactly `P0(pt)` on 16/16 slots × 64/64 traces, true byte ranks 10–202/256; B: 0 4-byte candidates per column for all six tag guesses |
| `w16_extract.py` | — | **not applicable** | — | it reads F4's 2^16 pair tables and 16-bit decode tables; dl6 is the F1/F2/F3/F0 shape, so the tables it reads do not exist here |
| **`rk0_in_z_attack.py`** (new) | unmasked tables | **16/16 bytes, `cd241e04…`, ciphertext reproduced** | **0.01 ms** of table reads + 16.1 s unmask | 16 `P.sigma` tables (`T[x] = P[0](x ^ rk1)`) and 16 merged `U` tables found; 16 tables (the `Pi[0]` ones) have no keyed shape; 0 naked `S.sigma` tables |

`hs_attack.py`'s own conclusion lines on dl6:

```
   candidates over all 64 (col,lane,row) byte positions: min 1 median 1 max 1
   the four MC rows agree on the candidate set for 16/16 (column, lane) pairs
   recovered key: 00000000000000000000000000000000
   reproduces that ciphertext: NO
   work factor: 16384 affine-consistency tests (64 byte positions x 256 guesses), 32 group recoveries
   no search over Z, no search over D0/D1, no traces; 19.64s total (3.42s algebra)
```

and the new attack, in full:

```
== 2. shape scan of the layer: 48 tables of 256 entries ==
   S.sigma_k  tables:  0/48  (rk0 byte direct)
   P.sigma_k  tables: 16/48  (a round-key byte direct)
   merged U   tables: 16/48  ((d, k) pair, 2^16 to find)
   tables with no keyed shape: 16/48
   classification cost: 0.01s (12288 table reads + 12x256..65536 tests each)
== 3. the cheap door: rk1 from the P.sigma tables, then invert the schedule ==
   rk1 = ab8fb8f3862364370fbee70e29b4e9cb  (16/16 bytes, 2 table reads each)
   key schedule of the inverted rk1 -> rk1 again: MATCH
   master key = cd241e042dacdcc4899d8339260a0ec5   [0.0000s]
== 4. the merged door: rk0 from U alone (the merge costs the attacker 2^16) ==
   (d, k) pairs found for 16/16 bytes in 0.9 ms
   rk0 from U = cd241e042dacdcc4899d8339260a0ec5
   agrees with the P.sigma door: YES
   every d the U scan found is IMC(rk1): YES
   AES-128(6bc1bee2..., rk1 -> schedule key) = 8190951ad006be2872ca95e886b993a5  MATCH
   AES-128(6bc1bee2..., U (2^16/byte) key) = 8190951ad006be2872ca95e886b993a5  MATCH
```

Two doors, both open:

* `rk1` from the `T` tables: `T[x] = P[0](x ^ rk1)` and the neighbouring `Pi[0]`
  table gives `x ^ Pi[0](T[x]) = rk1` — one constant test per byte, 2 table reads,
  **0.01 ms** for 16 bytes. AES-128's key schedule is a bijection, so `rk1` inverts
  to the master key (`invert_key_schedule`, checked against the forward schedule).
* `rk0` from `U` alone: for each byte, the one `d` that makes
  `S^-1(U[x]) ^ S^-1(x ^ d)` constant yields that constant as `rk0[sr_src(dst)]` —
  2^16 candidate pairs per byte worst case, measured **0.88 ms** for 16 bytes with
  early exit. The `d` values found are exactly `IMC(rk1)`, so the two doors agree.

Both are pure table reads: no traces, no group decomposition, no search over `Z`, no
unmasking beyond what any table-reading attack already pays.

## 5. What made the key visible

The layer is forced, and that is the whole result.

Round 0 must produce `MC·S(pt ^ rk0) ^ rk1` while its lane tables only compute
`MC·S(pt) ^ rk1`. `S` is a public permutation and `pt ↦ pt ^ rk0` does not commute
with it, so the correction is a **nonlinear** map on the column:

```
correction = MC · S · sigma_rk0 · S^-1 · IMC
```

Every factor of that expression is either public (`MC`, `IMC`, `S`, `S^-1`) or one
byte of key. Any implementation with a per-byte table therefore has to publish `S`
applied to a translated byte, or a composite whose inner spacing is one byte — which
is what `U` is. There is no third structure to hide behind: the stage before `S` is
`pt` (one byte, from the table index) and the stage after `MC` is the recoding, which
is downstream of the linear layer and cannot absorb a per-byte map that must be
applied *before* `MC`.

Merging `S^-1·σ_d` and `S·σ_rk0` into one table (`U`) is the strongest form of this
placement available, and it only buys 2^8 → 2^16 per byte: **0.88 ms instead of
0.01 ms**, i.e. nothing. And the layer's *other* end has to re-apply `P[0]` with `rk1`
folded in (`T`), which hands over `rk1` — and `rk1` is the master key. The only way to
avoid `T`'s leak is to fold `rk1` into round 1's input decoding instead, which puts
`rk1` back on an input side where the very same gauge-invariant test that fails on
dl6's round 0 would succeed on round 1 (the test only needs the round's input
bijection, and it would be `P[0]`, which ships in `hy_in.h`). So the choice is:

* key on an input side → 3.3 s of hidden-shift algebra (`hs_attack.py`, dl5, measured here);
* key on an output side → 0.01 ms of table shape (`rk0_in_z_attack.py`, dl6, measured here).

This is the same conclusion `attacks/residual/ZK-EXPERIMENT.md` reached on a `/tmp`
copy of the 8-bit families; dl6 reproduces it in-tree, on the T32 shape, with a
rotated key, and adds the measurement of the merged-`U` variant and of the `rk1`
door. Nothing in the repo's earlier claims changes.

## 6. Cost and size

| | dl5 (`gen_hybrid.cpp` @ 702ec6dcb) | dl6 | delta |
|---|---|---|---|
| table bytes | 70,090,816 | 70,103,104 | +12,288 (**+0.0175 %**) |
| build time (`time ./gen…`) | 1.00 s | 1.05 s | +0.05 s |
| table lookups / block | 1,464 (`FINGERPRINT.md`) | 1,512 (harness count) | +48 (12 per column) |
| encrypt, same bench, min of 5×50,000 | **9.22 µs** | **9.38 µs** | +0.16 µs (**+1.7 %**) |
| bench without the layer, same table | — | 9.31 µs | layer = ~0.07 µs |
| decrypt | unchanged code path | unchanged code path | 0 |

The two non-layer rows are the honest bounds: the layer's 48 lookups cost 0.07–0.16 µs
on this host, which is at the edge of run-to-run spread (±0.1 µs over 5×50,000). For
reference, the repo's documented `nl` figure is **16.9 µs/block** for the shipped
runtime binary (masking, per-block seal sample, DFA double pass); this host's dl5
build measures 9.22 µs with the same harness, so the transferable number is the
**+1.7 %** ratio, not the absolute one.

**VM offset plan: it still works, and it is untouched.** The HSV program computes 288
offsets (`2 dirs × 9 rounds × 16 bytes`) from `base[dir] + round·round_stride +
col·col_stride + lane_stride(fam, i&3)`, all read out of the schedule block with
`Tld`. dl6 moves no region, and the layer sits *after* the schedule block, so every
word the program reads (`[32..60)`) and every offset it produces are the dl5 values;
`tests/test_vm_offsets` reads only the shipped F4 layout, which no file outside
`gen_dl6/` touches, so it is unaffected (it was not re-run for this report). To
run dl6 through the VM path one would extend the plan by 48 words (4 columns × 12
tables, `HY_RKZ_OFF + col·3072 + slot·256`) and add one fixed-base read stage — two
new layout words and a short loop, no change to the existing 288. **Not implemented**,
because dl6 is not shipping; the numbers above come from a C++ walk of the same
header functions the VM-driven reader calls, not from the VM.

## 7. Verdict

* **Correctness: green.** dl6 is AES-128, bit-exact, both directions, verified
  three ways (generator vs reference, independent Python reader vs openssl on 7
  vectors, trace harness ciphertext). Same plaintext/ciphertext format, same offsets,
  same mask/seal discipline, key not present as bytes anywhere in the table.
* **The gate (`hs_attack.py`): red for the variant, and it says so.** It returns
  16/16 bytes of zero and fails its own ciphertext check. Read as a key-recovery
  attack it is **not** successful on dl6; read as evidence of protection it is
  worthless, because the key moved to a cheaper place.
* **Key recovery on dl6: 0.01 ms** (rk1 door) / **0.88 ms** (U door), after the same
  one-off unmask every table-reading attack pays, versus **3.33 s** of algebra on dl5
  on this host. No "harder" claim is made anywhere: the measured direction is easier
  by ~5 orders of magnitude.
* **Recommendation: do not ship dl6, and do not treat "the four committed attacks
  return zeros" as progress.** What the four scripts test is the input side; moving
  the key to the output side satisfies them by removing the object they measure. The
  only direction that survives both tests in this repo's data is width and depth
  (wide-table nonlinear fusion, `W16-EXPERIMENT.md` §7 / `ZK-EXPERIMENT.md` §5), and
  that still has to be measured, not assumed.

Hazards found while building it, worth recording:

* the layer's input domain is round 0's **output** bijection `P[0]`, which is random
  and not published anywhere — the first attempt used `P0` (the *input* bijection from
  `hy_in.h`) and produced a wrong ciphertext. A fourth table family (`Pi[0]`) is what
  makes the layer correct, and it is also why the layer costs 12 KB rather than 8 KB;
* `hy_mds`/`hy_mds_inv` in the header are the recoding's circulant `(1,4,3,7)`, **not**
  AES MixColumns; using them in the layer silently breaks the ciphertext (caught by the
  round-0 intermediate check, §3);
* the dl5-shaped artifacts need the **32-bit** load helpers hooked in the trace
  harness. `attacks/trace_harness/build_traces.py` at HEAD hooks only the three
  byte/16-bit helpers (F4 needs no 32-bit lane loads), so on a T32 artifact `dca_attack`
  dies with "lane slot not in trace". `gen_dl6/dl6_traces.py` carries the dl5-era
  five-hook list; this is a harness gap for any future 8-bit-generation artifact, not a
  dl6 issue.

## 8. Reproduce

```sh
cd demos/wbaes/gen_dl6
clang++ -std=c++17 -O2 -I. -I.. -o /tmp/gen_dl6 gen_dl6.cpp
mkdir -p /tmp/wbaes-dl6/work && cd /tmp/wbaes-dl6/work
/tmp/gen_dl6 dl6_table.bin --key cd241e042dacdcc4899d8339260a0ec5 \
    --pagesize 16384 --ncpu 10 --cls 128                     # rc 0, 1.05 s
python3 <repo>/demos/wbaes/gen_dl6/verify_dl6.py --table dl6_table.bin --work . \
    --key cd241e042dacdcc4899d8339260a0ec5 --n 6              # 7/7 vs openssl
python3 <repo>/demos/wbaes/gen_dl6/dl6_traces.py --table dl6_table.bin --work . --n 64
                                                              # ct + 64 traces + bench
cd <repo>/demos/wbaes/attacks/residual
python3 hs_attack.py --table /tmp/wbaes-dl6/work/dl6_table.bin --work /tmp/wbaes-dl6/work \
    --ct 8190951ad006be2872ca95e886b993a5 --key cd241e042dacdcc4899d8339260a0ec5
python3 consistency_attack.py --traces /tmp/wbaes-dl6/work/build/dl6_traces.bin \
    --key cd241e042dacdcc4899d8339260a0ec5 --skip-curve
cd .. && python3 bge_attack.py --table /tmp/wbaes-dl6/work/dl6_table.bin \
    --p0 /tmp/wbaes-dl6/work/build/p0.bin --seed 0x7f716422
python3 dca_attack.py --traces /tmp/wbaes-dl6/work/build/dl6_traces.bin \
    --p0 /tmp/wbaes-dl6/work/build/p0.bin --seed 0x7f716422
cd ../gen_dl6 && python3 rk0_in_z_attack.py --table /tmp/wbaes-dl6/work/dl6_table.bin \
    --work /tmp/wbaes-dl6/work --ct 8190951ad006be2872ca95e886b993a5 \
    --key cd241e042dacdcc4899d8339260a0ec5
```

The dl5 baseline in §6 was built the same way from `702ec6dcb` (generator + header +
`wbaes_key.h`) and benched with the same `dl6_bench.cpp` minus the `hy_rkz_apply` call.

## 9. What this does not prove

* Only the F1/F2/F3/F0 (dl5) shape was measured. `w16_extract.py` does not apply, and
  nothing here says anything about the F4 generation's numbers.
* The VM path was not built for dl6 (§6); the per-block numbers are from a direct C++
  walk of the header's round functions, not from the HSV-driven reader.
* No remote/black-box cost is given: every attack above reads table bytes after a
  one-off unmask. dl6 does not change that threat model, and the 0.01 ms figure is
  *after* unmasking.
* The `Pi[0]`/`U`/`T` tables were not further masked (e.g. `U` composed with a random
  per-byte bijection). That is not implementable: `U`'s output feeds the public `MC`,
  so nothing can absorb a relabelling there, and a relabelling on `U`'s *input* is
  cancelled by the `IMC` that precedes it only if it is affine — in which case `U` is
  separable again and the 2^8-style test returns.
