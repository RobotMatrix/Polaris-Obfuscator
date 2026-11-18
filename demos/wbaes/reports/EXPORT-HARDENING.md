# Export hardening: what the artifact used to tell you, and what it still does

Target: `demos/wbaes` built as `wbaes_vm2_clean` (key `4f065a03ee16cf8c31b15fd8f0344c66`,
table 70,090,816 B). Hardened with `tools/harden_export.py`, seed
`polaris-export-2026-11-18`.

Everything below is measured on this host (arm64, 10 CPUs, `pagesize=16384`,
`hw.cachelinesize=128`) by the committed scripts. Nothing is estimated.

> **Scope note (2026-11-18).** Step 1 (the table scrub) has no target in the F4
> generation that is shipped now: its column front is four 2^16-entry pair tables
> of 16-bit values, not 256-entry S-box rows, so `tools/hy_scrub.cpp` writes the
> table back byte-for-byte and reports `tables_reenencoded: 0`. Steps 2 and 3
> (known-answer replacement, Mach-O rename) are unaffected. The numbers below are
> the dl5/vm2 run and stay valid for that artifact; they say nothing about F4,
> whose key falls at 4,096 affine-consistency tests (README §5.29). **§9 is the
> F4 run, measured separately on 2026-11-18.**

---

## 0. Verdict first

* **The naming tells are gone and the score for them is 0.** M1 goes **155 → 0**.
  `nm` shows sixteen seeded names and libc imports; the two custom sections are
  `__DATA,__dmgo6ml7n3` and `__DATA,__xqqjb37njx`; two builds share **no** symbol
  and **no** section name; the NIST plaintext and ciphertext appear **0** times;
  the strings that used to say `plaintext :` / `vector-match` are gone.
* **The ciphertext is bit-identical** to the unhardened build for the NIST vector
  and for the build's random self-check vector, the roundtrip passes, and the HSV
  bytecode still drives the lane addresses through the renamed section.
* **Cost: 0 bytes, 0 ops per block.** The table rewrite is 27.5 MB of blob
  changed once at export time (0.74 s); per-block timing is unchanged inside the
  noise; the file gets **411 KB smaller** because the symbol table is gone.
* **Nothing structural was hidden, and the report says so.** The tables are still
  AES-shaped, `hs_attack.py` still recovers the key from the hardened table in
  **20.0 s**, and an affine pre-composition of a 256-entry table is provably
  invisible to anyone who has the table. Hardening removes the *name tag*, not the
  *algebra*.

---

## 1. The tells that existed

Measured on the shipped artifact with `tools/m1_detect.py`.

| tell | where | before | after |
|---|---|---|---|
| `_hsvm_entry`, `_hsvm_bytecode`, `_hsvm_table`, `_hsvm_table_len`, `_hsvm_mem` | symbol table | present | gone (16 seeded names, no locals) |
| `_kHyTab` | symbol table | present | gone |
| `__ZN5WBAES4initEv`, `_ZN5WBAES8enc_core...`, `_ZN9wbaes_keyL7test_ptE`, `_ZN9wbaes_keyL7test_ctE`, 11 more | symbol table | 15 matches | 0 |
| `__DATA,__hytab` (the 70 MB table), `__DATA,__hsvm` (the bytecode) | section list | 2 self-describing names | 2 names from the seed, purpose-free |
| `plaintext : `, `\nciphertext: `, `vector-match: %s\n`, `\nroundtrip : `, `roundtrip   : %s\n` | `__cstring` | 5 | 0 |
| NIST plaintext `6bc1bee2…172a` (byte string) | `__const` (`test_pt`) | 1 | 0 |
| NIST ciphertext `7672415a…22b8` (byte string) | `__const` (`test_ct`) | 1 | 0 |
| `hy_seal` / `wbaes` in the string table | symbol table | 1 + 4 | 0 |
| AES S-box / inverse-S-box byte string (256 B and 16-byte prefix) | anywhere | **0 already** | 0 |
| 256-byte windows that are 4-uniform permutations (S-box rows) | table blob, unmasked | **0 already** | 0 |

The last two were already clean and the report does not claim credit for them:
the generator composes every lane table with a random bijection on the input and
another on the output, which is enough to destroy the byte-level S-box
signature. §3 is about what that means for requirement 2.

Build metadata (`/Users/`, `/tmp/`, `Polaris`, `clang version`, `sub,bcf`,
`backend-obfu`, `gen_hybrid`) was already absent from this artifact — the build
paths never reach `__TEXT` because there is no `__FILE__`, no assert and no
`-g`. The scan is in M1 anyway so a regression would show.

## 2. M1: the score, per signal

`python3 demos/wbaes/tools/m1_detect.py --bin <artifact> --seal demos/wbaes`

| signal | weight | before | after | delta |
|---|---|---|---|---|
| S1 symbol-name tells (`nm`) | 6/hit, cap 60 | 15 hits → **60** | 0 → **0** | −60 |
| S2 section-name tells (`otool -l`) | 15/name | 2 (`__hytab`, `__hsvm`) → **30** | 0 → **0** | −30 |
| S3 string tells (`__cstring`) | 3/hit, cap 30 | 5 → **15** | 0 → **0** | −15 |
| S4 S-box byte string | 40 if any | 0 → **0** | 0 → **0** | 0 |
| S5 NIST vector bytes | 40 if any | 2 → **40** | 0 → **0** | −40 |
| S6 256-entry S-box-class tables | 40 if any | 0 → **0** | 0 → **0** | **0** |
| S7 build metadata | 10/hit, cap 30 | 1 → **10** | 0 → **0** | −10 |
| **total** | | **155** | **0** | **−155** |

S6 is the one that does not move, and §3 explains why that is a property of the
design rather than a gap in the hardening.

Classifier definition (in `tools/m1scan.c`): a 256-byte window counts if it is a
permutation of 0..255 **and** every one of its 255 non-zero derivatives peaks at
exactly 4. That is "an S-box row up to invertible maps on both sides", i.e.
exactly the class that the AES S-box and its affine images live in. It finds
1,999 permutation windows in this build's blob (2,002 in a second build — the count
moves with the table's random bijections) and **0** of them 4-uniform, in both builds.

## 3. The table scrub: what it did, what it bought, what it could not

`tools/hy_scrub.cpp` rewrites, per build and per table, `T'(x) = A(T(x))` with `A`
an invertible affine map on GF(2)^8 (a random invertible 8x8 GF(2) matrix, plus
a random constant), and re-indexes the 64K decode table that consumes the values so that
`Q'(A(u), A(v)) = Q(u, v)`. Both changes are absorbed by the existing reader:
the affine is applied to the value, the re-index is a permutation of the 64K
table's own entries. **Cost: 0 bytes, 0 ops per block.**

| family | tables re-encoded | shape | what they hold |
|---|---|---|---|
| F2 (`T8`) | **256** (4 rounds × 4 columns × 16 tables) | 256 × 1 B | one `(k,row)` coefficient table |
| F1 (`T32`) | **80** (5 rounds × 4 columns × 4) | 256 × 4 B | one lane table, four output rows |
| F3 (`T32K`) | **64** (4 rounds × 4 columns × 4) | 256 × 4 B | same, column constant folded in |
| F0 (`PAIR`) | 0 — skipped | 64K × 4 B | 16-bit-indexed pair tables, not a 256-entry row |
| decode tables | **416** re-indexed (27,262,976 B) | 64K × 1 B | `Q = Z(D0[a] ^ D1[b])` |

Bytes rewritten: 27,475,968 B (39 % of the blob), 0.74 s. Two builds from different seeds rewrite different values: 39 % of the
sampled bytes differ (the affine touches 400 tables, the re-index 26.5 MB of
decode tables).

**What it bought: nothing measurable.** That is the honest result, and it is
worth stating precisely because it is easy to claim otherwise:

* every 256-byte table in this artifact is `bijection ∘ linear ∘ S-box ∘ random
  permutation`. Peak differential uniformity of such a table is **10–12**, not 4,
  measured both in the stored (scatter-permuted) domain and after undoing the
  per-tag scatter — in both builds. There is no 4-uniform row to disguise, so the
  affine has nothing to disguise.
* even if there were: for an affine `A`, `A(x) ^ A(x^a) = M·a` is constant, so
  **differential uniformity is invariant under affine re-encoding**. `--affine-only`
  and the full transform produce the same classifier count. An attacker holding
  the table computes `A = MC(S(x)) ∘ T⁻¹` in 256 lookups, so the affine is not a
  secret either.
* what it does buy is *cheap*: two builds no longer share table rows, so the
  "align two versions by matching a row" trick is gone, and it costs nothing.

**The index permutation I tried and rejected.** `T'(x) = A(T(π(x)))` with a
non-affine `π` *would* clear the 4-uniform signature (it is the only build-time
transform that can). It is not free: the reader picks exactly one position per
logical index (`hy_scatter8`), so permuting the index changes the function.
Measured: 13 of 18 rounds produced different output, `hy_selftest` named each one.
Absorbing `π` needs a matching change in `hy_mc_round` — i.e. in
`wbaes_hybrid.inc`, which this export pass does not own. `hy_scrub` refuses
`--index-perm` and says why.

## 4. M2: the function is unchanged

| check | value |
|---|---|
| key | `4f065a03ee16cf8c31b15fd8f0344c66` |
| NIST plaintext | `6bc1bee22e409f96e93d7e117393172a` |
| ciphertext, unhardened | `7672415a6313c58518fc95c9cb6922b8` |
| ciphertext, hardened (probe build) | `7672415a6313c58518fc95c9cb6922b8` |
| random self-check vector (build seed) | pt `1489dfa2a9b8393d3974bb63c8595ecc` |
| its ciphertext, hardened binary | `2f7a794dbad2853be2b61e5224060296` |
| the same, computed by real AES-128 outside the artifact | `2f7a794dbad2853be2b61e5224060296` |
| roundtrip | `check: ok` (the KAT compares `decrypt(ct)` with `pt`) |
| VM negative test (`tools/vm_negative_test.cpp`) | intact `2f7a794d…` → damaged `dccb4669…` → restored `2f7a794d…`, **PASS** |

The hardened binary prints `check: ok` and nothing else. The self-check no longer
stores a known-answer vector: the plaintext is derived from a 32-bit build seed at
run time, and only `FNV-1a-64(ct)` is compared, against a hash that
`harden_export.py` computed from real AES at export time. Bytes are printed only
when the check fails.

The VM negative test is the one that matters for requirement 1: it damages a
schedule byte the C++ never reads, and the ciphertext moves only because the
lowered bytecode recomputed the 288 offsets out of the **renamed** section. So the
rename did not disconnect `@hsvm_table` from the pass's output.

## 5. M3: cost

| | unhardened | hardened |
|---|---|---|
| file size | 70,707,168 B | **70,296,208 B** (−410,960 B, −0.58 %) |
| of which table section | 70,090,816 B | 70,090,816 B (unchanged) |
| encrypt | 17.18 µs/block | 17.15 µs/block |
| decrypt | 16.79 µs/block | 16.66 µs/block |
| process start (init + unmask + full seal + 2 blocks) | 210.8 ms | 204.2 ms |
| export pass (70 MB in, 70 MB out) | — | 0.74 s |

Timing: `bench_wbaes 3000`, best of 3 runs, same table on the same host; the
difference is inside the run-to-run spread (17.15–18.26 µs across runs), which is
what "zero per-block cost" looks like when the transform is definitionally
outside the loop. The 411 KB is metadata: `LC_SYMTAB` shrinks to 16 names and the
ad-hoc signature re-sign uses a smaller code directory (548,256 → 137,328 B).
No code or data byte moved.

## 6. M4: the attacks did not regress, they just lost their entry point

| attack | unhardened binary | hardened binary | hardened **table** |
|---|---|---|---|
| `bge_attack.py` | incomplete (0/16) | `no __hytab section` (loader) | incomplete (0/16), 17.0 s — same as before |
| `residual/hs_attack.py` | key recovered, 23.8 s | `no __hytab section` (loader) | **key recovered, 20.0 s**, `reproduces the shipped ciphertext: YES` |
| `residual/zk_attack.py` | n/a | n/a | n/a — it only accepts the zk *variant* table (70,107,200 B) |

`bge_attack.py` and `hs_attack.py` both already support a raw-artifact path
(`--table` + `--p0` / `--table` + `--work`, via `attacks/residual/reslib.py`'s
`load_variant`), and that is how the third column was produced. No loader change
was needed: the table file that `harden_export.py` writes next to `hy_in.h` /
`hy_seal.h` is exactly what those flags expect.

So the rename costs an attacker one step (find the 70 MB section by size, take the
four seed words out of `__const`, unmask) and nothing else. Anyone who gets that
far is back to the 20-second key recovery.

## 7. What remains, and cannot be removed by this kind of tool

Being explicit, because "hardened" is easy to over-read:

1. **The algebra.** The 32 pair-decode tables are still exactly
   `Q[a][b] = Z(D0[a] ^ D1[b])`: `hs_attack` explains **2,097,152 / 2,097,152**
   entries, recovers `Z` as a bijection in 32/32 tables, and pulls the round-0 key
   byte by byte with a single candidate per byte, in 3.1 s of algebra. No
   renaming, byte permutation or affine re-encoding touches that structure,
   because it is what makes the network compute AES.
2. **Block size and round count.** 16-byte state, 9 table rounds + a final
   whitening pair: visible in the schedule block (9 family bytes), in the loops,
   in the 69 MB of per-round column slots, and in the fact that any 16-byte
   permutation network with an S-box has that shape. Even with every name
   scrubbed, the artifact is obviously "a 16-byte block cipher with 10 rounds".
3. **The MixColumns matrix.** `(1,4,3,7)` and its inverse `(11,11,9,8)` live in
   `hy_mds` / `hy_mds_inv` / `hy_mulc` in `wbaes_hybrid.h` — code, not tables, and
   inlined into the recoding loops as xtime chains. Nothing in this pass touches
   code, and a byte scan does not see it. This is a *code-shape* tell.
4. **The key shards.** `wbaes_key.h`'s four 4-byte shards plus their FNV checks
   are in the baked build as plain `volatile const` blocks; `hs_attack` does not
   even need them, but they are there. Out of scope here (they are the design's
   own split-secret mechanism, and the file is generated by `rotate_key.py`).
5. **70 MB of tables.** The size itself says "white-box", and no naming choice
   changes it.
6. **Chosen plaintext.** Anyone who can run the binary can collect input/output
   pairs; that plus the block size identifies AES-128 in minutes regardless of
   what the artifact is called.

What hardening *does* remove is the part that let an attacker skip all of the
above: the artifact no longer says which algorithm it is, which section is the
table, or which 32 bytes are the known answer. That is worth about five minutes
of an attacker's time and a search query — not more, and this report does not
claim more.

## 8. Reproduction

```bash
cd demos/wbaes
# 1. table (needs the generator; produces hy_table.bin, hy_in.h, hy_seal.h)
clang++ -O2 -std=c++17 -I. gen_hybrid.cpp -o /tmp/gen_hybrid && /tmp/gen_hybrid hy_table.bin
# 2. hardened build + all the checks of this report
python3 tools/harden_export.py --src . --out /tmp/wbaes-hard \
        --seed polaris-export-2026-11-18 --probe --bench --vmtest --m1
# 3. score it
python3 tools/m1_detect.py --bin /tmp/wbaes-hard/wbaes_hard --seal .
# 4. the attacks, against the table rather than the Mach-O
python3 attacks/residual/hs_attack.py --table /tmp/wbaes-hard/hy_table.bin --work /tmp/wbaes-hard
```

The driver refuses to continue if any of its anchors in `demo_wbaes.cpp` are
missing, if the unmask check fails (wrong env or seed), or if the hardened binary
does not print `check: ok`.

One reproducibility caveat: `gen_hybrid` draws from `/dev/urandom`, so `hy_table.bin`
is a different table on every generation. The stable identity is the key and the
ciphertext (`4f06…` → `7672415a…`), not the table bytes. Everything in §2, §5 and
§6 was measured on the table this report names; M1 does not depend on which one
you build.

**Given up on:** hashing the table bytes inside the artifact (it is already
sealed with FNV; a stronger digest changes nothing), renaming the segments
themselves (`__TEXT`/`__DATA` must keep their names for `ld`/`dyld`), removing
the `hw.*` sysctl name strings (they name the platform, not the program),
obfuscating the MDS in code (needs `wbaes_hybrid.h`, owned elsewhere, and code
obfuscation is the CFF/BCF reports' subject), and any attempt to make the tables
stop being AES (that would change the ciphertext, which is the one thing this
task must not do).

---

## 9. The F4 generation (measured 2026-11-18, the shape that actually ships)

Everything in §1–§8 above was measured on the dl5/vm2 artifact and stays labelled
as such. This section is the same pass re-run on the F4 sources, and it replaces
no earlier number.

Target: `demos/wbaes` current tree (key `3acb79e72c06bebbbdcda86dc62f009b`, KAT
`6bc1bee2…172a` → `2c0b8f87b6aa8d4a8c7b12d8d2227c8d`, table 70,090,816 B,
sha256 `d5c57b33…91e269`).

```bash
cd demos/wbaes
python3 tools/harden_export.py --src . --out /tmp/wbaes-f4-hard \
        --seed polaris-f4-export-2026-11-18 --probe --vmtest --m1
# 4.89 s wall, exit 0
```

### 9.1 What each step did to this generation

| step | result on F4 | why |
|---|---|---|
| table scrub (`hy_scrub`) | **nothing**: `tables_reenencoded: 0`, `bytes_changed: 0` | the F4 column front is four 2^16×16-bit pair tables; there is no 256-entry S-box-shaped lane table to pre-compose. `hy_table.bin` out is byte-identical to `hy_table.bin` in (both `d5c57b33…`), so the seal constants did not move either |
| self-check vector (`hy_kat.h`) | NIST plaintext/ciphertext and the five printf strings gone; seed `0x4428bb0b`, plaintext derived at run time, `FNV-1a-64(ct) = 0xaec4da0d308d2fdd` | the hash was computed from real AES-128 at export time |
| Mach-O scrub | 2 sections renamed (`__hytab` → `__rpw3sxyhfp`, `__hsvm` → `__r77nbreolp`), 16 symbols renamed from the seed, locals dropped, ad-hoc re-sign | post-link, so `@hsvm_*` was already resolved to addresses |

`nm -a` on the result: 16 defined symbols, none matching
`aes|wbaes|hsvm|hytab|sbox|mixcol|rcon|test_pt|test_ct`. The VM is still there and
still wired: `_hsvm_entry` (0x100003284) → `_mrtisyvda7`, `_hsvm_table` →
`_r2wqkkzdie`, `_hsvm_bytecode` → `_nqs7izwuif`, and the lowered entry is 206
instructions with **0** indirect branches.

### 9.2 M1: 100 → 0

| artifact | S1 | S2 | S3 | S4 | S5 | S6 | S7 | total |
|---|---|---|---|---|---|---|---|---|
| `wbaes_f4_clean` (debug build, in `exported-binaries/…/macos/`) | 60 | 30 | 15 | 0 | 40 | 0 | 10 | **155** |
| `wbaes_f4_max` (shipped, in `redteam-2026-11/`) | 60 | 30 | 0 | 0 | 0 | 0 | 10 | **100** |
| `wbaes_f4_hard` (this run) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **0** |

`wbaes_f4_max` already had no debug strings and no stored vector, which is why its
baseline is 100 and not 155; the whole of what is left for this pass to remove is
the 15 symbol tells, the 2 section names and the `hy_seal` metadata string. S6 is
0 in all three (1,744 permutation windows in the table, none 4-uniform) — the F4
pair tables are not S-box rows, so §3's point holds a fortiori.

### 9.3 The function is unchanged, checked five ways

| check | value |
|---|---|
| NIST ciphertext, hardened probe (`=6bc1bee2…172a`) | `2c0b8f87b6aa8d4a8c7b12d8d2227c8d` |
| the same plaintext, `openssl enc -aes-128-ecb -K 3acb…` | `2c0b8f87b6aa8d4a8c7b12d8d2227c8d` |
| the same plaintext, unhardened `wbaes_f4_max` | `2c0b8f87b6aa8d4a8c7b12d8d2227c8d` |
| build-seed vector `3a1d7226…8e9c`, hardened probe | `836855128d9a7afb5ea8dfd0ef09282b` |
| the same vector computed by AES-128 outside the artifact (openssl) | `836855128d9a7afb5ea8dfd0ef09282b` |
| roundtrip | `check: ok` (the KAT compares `decrypt(ct)` with `pt`) |
| VM negative test | intact `83685512…` → damaged `5aabe85a…` → restored `83685512…`, **PASS** |
| `tools/hy_selftest` (orig vs hardened table) | 18/18 rounds identical, `all rounds identical` |

### 9.4 Cost: the attacker's, not the runtime's

File size 70,707,184 → **70,296,208 B** (−410,976 B, −0.58 %), all of it metadata
(`LC_SYMTAB` + the smaller code directory). No code or data byte moved — the
table section is still 70,090,816 B and byte-identical.

`attacks/residual/w16_extract.py`, same host, same table, cold = no unmasked-table
cache, warm = `--cache` hit:

| | `wbaes_f4_max` | `wbaes_f4_hard` |
|---|---|---|
| extractor as committed | key `3acb79e7…`, **15.62 s** cold / 0.23 s warm | **fails**: `no __hytab section`, **0.04 s** |
| with `find_section` picking the 70 MB section by size | n/a | key `3acb79e7…`, **15.27 s** cold / 0.23 s warm |

Decomposition on the same runs (`wb.find_section` timed separately):

| phase | unhardened | hardened |
|---|---|---|
| read binary + find the 16×256 input bijection in `__const` | 0.022 s | 0.022 s |
| locate the mask seed (16-byte windows of `__const`, schedule checksum) | 0.073 s (51 candidates) | 0.024 s (13 candidates) |
| unmask 70 MB in Python | 15.045 s | 15.456 s |
| the 8,192 affine-consistency tests + voting | 0.19 s | 0.20 s |

So: **the rename buys one loader exception, worth 0.04 s of machine time and one
line of Python; the seed search is not the cost either (0.07 s vs 0.02 s, both
noise against a 15 s unmask); and the algebra is 0.2 s of a 15.5 s run.** The
de-symbolised artifact is not more expensive to break, it is only more expensive
to *start* breaking. Note also that the extractor found the same mask seed in both
binaries — the seed lives in `__const`, which this pass does not touch, because
renaming it would mean touching code.

### 9.5 What this generation does not get from the pass

§7 applies unchanged. In addition, for F4 specifically:

1. the table scrub is a no-op, so the "two builds share no table rows" benefit
   claimed in §3 for F1/F2/F3 does not exist here — two F4 builds from the same
   `hy_table.bin` embed the same table;
2. the 2^16 pair tables are exactly XOR-separable (README §5.29), and nothing in
   a metadata pass changes that;
3. the artifact still prints `check: ok`, so it still tells you it passed its own
   test — it just no longer tells you the answer.
