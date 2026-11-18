# CFF / BCF: what control-flow obfuscation actually buys on the white-box binary

Target: `exported-binaries/wbaes-challenge/macos/wbaes_nl_clean`
(key `46f6abe52990556a6713141f65fed9a5`, ciphertext
`80aadc09777696c9d492a7e53b3b15b0`, table 70,090,816 B).
Four builds of the same program, same key, same table:

| variant | pass list | what it adds |
|---|---|---|
| **V0** | — | the shipped build (`-O2`, `hsvm` on the VM TU only) |
| **V1** | `-mllvm -passes=fla` | control-flow flattening (`Flattening.cpp`) |
| **V2** | `-mllvm -passes=bcf` | bogus control flow (`BogusControlFlow2.cpp`) |
| **V3** | `-mllvm -passes=bcf,fla` | both |

Everything below is measured, not estimated. Commands are in §9; the two scripts
this report adds are `attacks/cff/build_variants.sh` (builds the four) and
`attacks/cff/measure_cff.py` (all static numbers: it parses `otool -tv` /
`otool -l` and counts programmatically).

---

## 0. Verdict first

**Key-extraction resistance added by CFF/BCF in this build: none measurable.**

All three committed attacks return bit-identical results on all four variants
(and on two extra variants where the table loop itself is flattened):

| attack | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| `bge_attack.py` | 0/16 bytes, 15.93 s | 0/16, 15.89 s | 0/16, 15.35 s | 0/16, 15.25 s |
| `extract_key.py` | refuses at the size gate, 0.09 s | same, 0.12 s | same, 0.09 s | same, 0.09 s |
| `dca_attack.py` (real traces) | 0/16, 1.67 s | 0/16, 1.70 s | 0/16, 1.75 s | 0/16, 1.64 s |

The attacks fail for reasons that live **in the table bytes**, and the table
bytes are byte-identical across the four builds: `__DATA,__hytab` is
70,090,816 B with sha256 prefix `4fbce0f65ce20d6d` and `__TEXT,__const`
(4,208 B, `8c25137d21577891`) in every one of them. CFF/BCF move code; they do
not touch data, and every one of the three attacks is a data attack
(`bge` reads `__hytab`, `dca` reads table access addresses, `extract_key`
reads `__hytab` geometry).

What they *do* buy: **+2.9 % / +3.3 % / +13.5 % `__text` bytes**, +8.6 % / +9.7 % /
+43.8 % basic blocks, and a `WBAES::encrypt` that grows from 67 instructions /
7 blocks to 296 / 49 (×4.4 / ×7.0) in V3. They buy reading time for a human
who starts at `main`, and nothing at all for the tables.

Runtime cost, with the shipped annotation scope: **0 %, i.e. below noise**
(within ±1.1 %, run-to-run spread of a single build is ±2.5 %). When the pass is
pointed at the actual table loop (§8), the cost becomes real: **+2.8 % / +1.9 %**
for `fla`, **+11.1 % / +11.2 %** for `bcf,fla` (encrypt / decrypt).

---

## 1. Why the passes hit so little: the annotation gate

`Pipeline.cpp` maps `-mllvm -passes=fla` → `Flattening` and `bcf` →
`BogusControlFlow2`, in a fixed order (`bcf` before `fla`). Both passes act
**only on functions whose annotation names them**:

```
Flattening.cpp:437          readAnnotate(f).find("flatten")  || policyHasPass("fla")
BogusControlFlow2.cpp:64    readAnnotate(F).find("boguscfg") || policyHasPass("bcf")
```

In `demo_wbaes.cpp` exactly four functions carry
`__attribute((__annotate__(("...boguscfg,flatten..."))))` — lines 1054, 1095,
1111, 1176: `WBAES::encrypt`, `WBAES::decrypt`, `WBAES::enc_core`,
`WBAES::dec_core`. The 9-round table walk (`hy_mc_round`, 937 instructions),
the VM entry (`hsvm_entry`, 172), the SPN steps (`hy_spn_*`) and
`hy_pair_map` are **not** annotated, so both passes skip them.

This is measured, not assumed: the mnemonic sequence of the un-annotated hot
functions is identical in all four builds (same instruction count, same block
count, same branch counts, same mnemonic hash):

| function | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| `hy_mc_round` | 937 ins / 28 blk, hash `35eebddf03fcf7d5` | identical | identical | identical |
| `hsvm_entry` | 172 ins / 27 blk, hash `dcdc2a34200a70aa` | identical | identical | identical |
| `hy_spn_inv` | 172 ins | identical | identical | identical |
| `hy_mulch` | 174 ins | identical | identical | identical |

(`measure_cff.py` prints `shape` per function: sha256 of the mnemonic sequence.
Relocated addresses/offsets differ between builds; the instruction schedule does
not. Annotated functions change hash, un-annotated ones do not.)

---

## 2. Static size and shape

`python3 demos/wbaes/attacks/cff/measure_cff.py --binary <variant>`

| metric | V0 | V1 (fla) | V2 (bcf) | V3 (both) |
|---|---|---|---|---|
| `__text` bytes | 12,552 | 12,916 (+2.9 %) | 12,972 (+3.3 %) | 14,248 (+13.5 %) |
| disassembled instructions | 3,138 | 3,229 | 3,243 | 3,562 |
| functions | 20 | 20 | 20 | 20 |
| basic blocks (`__text`) | 185 | 201 (+8.6 %) | 203 (+9.7 %) | 266 (+43.8 %) |
| conditional branches | 101 | 110 | 114 | 146 |
| unconditional branches | 23 | 29 | 29 | 51 |
| indirect branches (`br`/`blr`) | 1 | 1 | 1 | 1 |
| `ret` | 26 | 26 | 26 | 26 |
| `bl` | 216 | 217 | 236 | 236 |
| **file size** | 70,706,984 | 70,706,984 | 70,706,984 | 70,706,984 |

Two points worth stating precisely:

* **The file does not grow.** The 70 MB table dominates and `__hytab` starts at
  file offset 49,168 in all four builds; up to 2 KB of extra `__text` still fits
  the 16 KiB page. The shipped artifact is 70,707,000 B; the V0 rebuild is
  16 B smaller (layout, not code — V0's `__text` is the shipped one, see §3).
* **No indirect branch is added.** The single `br` lives in `hy_mulch` and is
  present in V0 too. The flattening dispatcher compiles to a **comparison
  chain**, not a jump table, because its state values are random 32-bit
  constants (`getUniqueNumber()`), which LLVM cannot lower to a table:
  `encrypt` in V3 has 28 `cmp` and 38 `movk` (the 32-bit state immediates) and
  a single back edge to the dispatcher. That is a shape a decompiler or a
  constant-folding pass removes mechanically — it is noise, not a barrier.

### Hot-path functions

| function | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| `WBAES::encrypt` ins / blocks | 67 / 7 | 122 / 16 | 125 / 14 | 296 / 49 |
| `WBAES::decrypt` ins / blocks | 48 / 3 | 84 / 10 | 65 / 8 | 147 / 24 |
| `hy_mc_round` (table loop) | 937 / 28 | 937 / 28 | 937 / 28 | 937 / 28 |
| `hsvm_entry` (VM) | 172 / 27 | 172 / 27 | 172 / 27 | 172 / 27 |

---

## 3. Where the VM entry and the table loop sit

Addresses are image addresses (`__text` starts at 0x1000006c0 = file offset 1,728):

| variant | `WBAES::encrypt` | `hy_mc_round` | `hsvm_entry` | `__hytab` |
|---|---|---|---|---|
| V0 | 0x100000860 | 0x100001930 | 0x100003518 | 0x10000c010 |
| V1 | 0x100000860 | 0x100001a9c | 0x100003684 | 0x10000c010 |
| V2 | 0x10000089c | 0x100001ad4 | 0x1000036bc | 0x10000c010 |
| V3 | 0x100000920 | 0x100001fd0 | 0x100003bb8 | 0x10000c010 |

V0's numbers are the shipped artifact's: running the same script on
`exported-binaries/wbaes-challenge/macos/wbaes_nl_clean` gives 12,552 bytes,
3,138 instructions, 185 blocks, 101/23/1 branches, 11 `__hytab` references —
identical to V0. The rebuild is a faithful baseline.

---

## 4. Cost of the three committed attacks

Commands:

```
python3 demos/wbaes/attacks/bge_attack.py --binary <variant> [--cache file]
python3 demos/wbaes/extract_key.py <variant>
python3 demos/wbaes/attacks/trace_harness/build_traces.py --binary <variant> --work DIR --n 64
python3 demos/wbaes/attacks/dca_attack.py --binary <variant> --traces DIR/dl4_traces.bin
```

| attack | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| BGE: key recovered? | no (0/16) | no (0/16) | no (0/16) | no (0/16) |
| BGE wall time (cold, incl. 70 MB unmask + seed search) | 15.93 s | 15.89 s | 15.35 s | 15.25 s |
| BGE step-1 fit (off-axis entries reproduced) | 976/122,400 = 0.80 % | 0.80 % | 0.80 % | 0.80 % |
| BGE mask seed found | 0x22e0f8cd | same | same | same |
| `extract_key.py` | refuses: "70,090,816-byte blob is dl4/dl5" | same | same | same |
| `extract_key.py` wall time | 0.09 s | 0.12 s | 0.09 s | 0.09 s |
| DCA (64 real traces, 1,464 accesses/block) | 0/16, 1.67 s | 0/16, 1.70 s | 0/16, 1.75 s | 0/16, 1.64 s |
| DCA experiment A: slots whose index is `P0(pt)` | 16/16 | 16/16 | 16/16 | 16/16 |
| DCA experiment B candidates per column | 0,0,0,0 | 0,0,0,0 | 0,0,0,0 | 0,0,0,0 |

The DCA traces were rebuilt from V0 and from V3 and are **byte-identical**
(`sha256 2be77776…2e2555`), because the harness reads the table, the round-0
bijection and the mask seed out of the binary and nothing else — all of which
are identical. The harness can be rebuilt for every variant; the result does not
change, which is itself the measurement: the address trace carries no
information that CFF/BCF could remove.

Wall-time differences (15.25–15.93 s, 1.64–1.75 s, 0.09–0.12 s) are noise and
are all dominated by the 70 MB unmask (≈15 s) — identical work in every case.

---

## 5. Runtime cost

`bench_wbaes 3000`, median of five runs, same table:

| variant | encrypt µs/block | decrypt µs/block | Δ enc | Δ dec |
|---|---|---|---|---|
| V0 | 23.42 | 23.11 | — | — |
| V1 (fla) | 23.22 | 23.10 | −0.9 % | −0.0 % |
| V2 (bcf) | 23.51 | 23.03 | +0.4 % | −0.3 % |
| V3 (both) | 23.16 | 23.05 | −1.1 % | −0.3 % |

Single-build run-to-run spread is ±2.5 % (V3 encrypt ranged 23.11–25.18 over five
runs), so every delta above is inside noise: **with the shipped annotation scope
the obfuscation is free.** It is free because it only rewrites the per-block
wrappers (`encrypt`/`decrypt` ≈ 300 extra instructions) around a hot path of
~1,464 table accesses and 288 VM calls per block; 300 instructions is ~0.5 % of
one block's work and cannot be resolved above the noise of a 23 µs measurement.

---

## 6. RE-cost proxy (explicitly a proxy)

`measure_cff.py` builds the call graph from `bl` edges (direct and via symbol
stubs), BFS from `main`, and reports the shortest static chain plus the total
instruction count of the distinct functions on it — i.e. how many lines of
disassembly a reader must account for before reaching a given anchor.

| anchor | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| chain to `&kHyTab` (4 functions on it) | 692 ins | 747 (+7.9 %) | 750 (+8.4 %) | 921 (+33 %) |
| chain to `hy_mc_round` (5 functions; the per-byte table loop) | 1,590 | 1,645 | 1,648 | 1,819 (+14 %) |
| chain to `hsvm_entry` (6 functions) | 855 | 910 | 913 | 1,084 |
| instructions that materialise an address inside `__hytab` | 11 | 11 | 11 | 11 |
| functions containing those references | 3 | 3 | 3 | 3 |

The 11 references are `adrp x26, 0x10000c000` + `ldr x0, [x26]` against a
16-byte pointer cell (`__ZL10hy_tab_ptr`) that sits immediately before the
section and holds `&kHyTab` after dyadic rebasing. **That count does not move**:
CFF/BCF add reads of the dispatcher state, never new ways to reach the table.

The mask seed is not a static constant at all: it is
`hy_env_mix(pagesize, ncpu, cachelinesize)` from three `sysctlbyname` calls, so
the model locates it with a data test (unmask the schedule block, check the
family bytes and the check byte — `wblib.find_mask_seed`), which no code
transformation can affect. Measured: the same seed `0x22e0f8cd` after 21
candidate 4-word XORs in every variant.

**This is a proxy, not a human study.** It measures work that scales with the
number of instructions a reader must walk, and it moves monotonically with what
a human would actually face at the entry points. It does not measure the cost of
giving up, of tooling, or of a decompiler collapsing the dispatcher in one pass —
and §1/§2 show that last one is cheap here.

---

## 7. What the numbers add up to

| | V0 → V3 |
|---|---|
| key-extraction resistance | 0 (three attacks, identical verdicts) |
| `__text` | +13.5 % |
| blocks in `__text` | +43.8 % |
| `encrypt` shape | ×4.4 instructions, ×7.0 blocks |
| indirect branches added | 0 |
| runtime (shipped scope) | 0 (inside ±1.1 %) |
| static chain to the table base | +33 % |
| references to `__hytab` | unchanged (11, in 3 functions) |

---

## 8. Extra: what if the pass were pointed at the table loop?

The obvious objection is "you measured the wrong functions". So the same
experiment was repeated with the CFF/BCF annotation widened to the real hot
function — a scratch copy of `wbaes_hybrid.h` under `/tmp` with
`__attribute((__annotate__(("boguscfg,flatten"))))` on `hy_mc_round`; no repo
source was modified. Same key, same table, same everything else.

| | V0 (none) | V1′ (fla on the loop) | V3′ (bcf+fla on the loop) |
|---|---|---|---|
| `__text` bytes | 12,552 | 14,360 (+14.4 %) | 21,388 (+70.4 %) |
| instructions | 3,138 | 3,590 | 5,347 |
| blocks | 185 | 234 | 451 |
| `hy_mc_round` ins / blocks | 937 / 28 | 1,298 / 61 | 2,716 / 212 (×2.9 / ×7.6) |
| chain to table base | 692 | 747 | 923 |
| chain to `hy_mc_round` | 1,590 | 2,006 | 3,600 |
| bench encrypt / decrypt µs | 23.42 / 23.11 | 24.08 / 23.55 (**+2.8 % / +1.9 %**) | 26.02 / 25.69 (**+11.1 % / +11.2 %**) |
| `bge_attack.py` | 0/16 | 0/16 (15.24 s) | 0/16 (15.40 s) |
| `dca_attack.py` | 0/16 | 0/16 (1.66 s) | 0/16 (1.66 s) |
| ciphertext | `80aadc09…` | `80aadc09…` | `80aadc09…` |

Even aimed at the correct function, the attacks do not move by one byte — and
this is the cleanest demonstration of why: the property that stops them is the
shape of the 64K pair-decode tables and the two-byte boundary index, which lives
in `__hytab`, and no control-flow pass rewrites `__hytab`.

What *does* move is the reader's cost: the loop becomes 2.9× (fla) or 7.6×
(bcf+fla) its original block count, and runtime goes up 11 % in the worst case.

---

## 9. Exact commands

```bash
REPO=/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator
CL=$REPO/src/build/bin/clang++
W=/tmp/wbaes-cff/src          # scratch copy of demos/wbaes (no repo writes)

# 0. scratch copy (sources may be edited concurrently)
mkdir -p $W && cd $REPO/demos/wbaes && \
  cp gen_hybrid.cpp wbaes_hybrid.h wbaes_hybrid.inc wbaes_vm.cpp wbaes_vm.h \
     demo_wbaes.cpp bench_wbaes.cpp hy_tab.S hy_table.bin wbaes_testvec.h \
     wbaes_key.h hy_seal.h hy_in.h hy_mask.h $W/

# 1. the four variants + a bench harness for each (deterministic: -obf-seed)
bash $REPO/demos/wbaes/attacks/cff/build_variants.sh $W /tmp/wbaes-cff/final
#   internally, per variant:
#   $CL -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. \
#       -mllvm -passes=hsvm -c wbaes_vm.cpp -o wbaes_vm.o           # VM TU, once
#   $CL -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM -I. \
#       demo_wbaes.cpp hy_tab.S wbaes_vm.o -mllvm -obf-seed=1234 \
#       -mllvm -passes=<none|fla|bcf|bcf,fla> -o vN

# 2. static shape
python3 $REPO/demos/wbaes/attacks/cff/measure_cff.py \
        --binary /tmp/wbaes-cff/final/v3_both --json /tmp/wbaes-cff/f.json

# 3. attacks
python3 $REPO/demos/wbaes/attacks/bge_attack.py --binary /tmp/wbaes-cff/final/v3_both
python3 $REPO/demos/wbaes/extract_key.py        /tmp/wbaes-cff/final/v3_both
python3 $REPO/demos/wbaes/attacks/trace_harness/build_traces.py \
        --binary /tmp/wbaes-cff/final/v3_both --work /tmp/wbaes-cff/tr3 --n 64
python3 $REPO/demos/wbaes/attacks/dca_attack.py \
        --binary /tmp/wbaes-cff/final/v3_both --traces /tmp/wbaes-cff/tr3/dl4_traces.bin

# 4. runtime (median of five)
/tmp/wbaes-cff/final/bench_v3_both 3000

# 5. data identity check (hytab + __const are the same in all four)
python3 - <<'EOF'
import subprocess, hashlib
def sect(b, seg, name):
    out = subprocess.run(['otool','-l',b],capture_output=True,text=True).stdout
    pend=cur=fd=None; sz=None
    for line in out.splitlines():
        s=line.strip()
        if s.startswith('sectname'): pend=s.split()[1]
        elif s.startswith('segname'): cur=(s.split()[1],pend)
        elif cur==(seg,name) and s.startswith('offset'): fd=int(s.split()[1])
        elif cur==(seg,name) and s.startswith('size'): sz=int(s.split()[1],0)
    return sz, hashlib.sha256(open(b,'rb').read()[fd:fd+sz]).hexdigest()[:16]
for v in ['v0_none','v1_fla','v2_bcf','v3_both']:
    print(v, sect('/tmp/wbaes-cff/final/'+v,'__DATA','__hytab'),
             sect('/tmp/wbaes-cff/final/'+v,'__TEXT','__const'))
EOF
```

**Build determinism.** The pass RNG is seeded from the clock unless
`-mllvm -obf-seed=N` is passed (`src/llvm/lib/Support/ObfuscationSeed.cpp`), and
`BogusControlFlow2` skips a block on a 20 % roll, so unpinned `bcf` builds vary.
Three unpinned V3 builds measured: `__text` 14,344 / 14,520 / 14,804 B, blocks
263 / 283 / 285, `encrypt` 305 / 329 / 329 instructions. All numbers in this
report come from the pinned (`-obf-seed=1234`) set.

---

## 10. Caveats and limits

1. **CFF protects the understanding of control flow, not the algebra of the
   tables.** Every attack that succeeds or fails here does so by reading
   `__hytab` (BGE, `extract_key`) or the addresses of its reads (DCA). Neither
   pass changes the data layout, the table base, the section offsets, the mask
   seed or the round-0 bijection — verified byte-for-byte in §0 and §6. So the
   white-box security of this binary is exactly what it was in V0.
2. **The pass scope, not the pass, is the reason the numbers are this small.**
   With the shipped annotations only four wrapper functions are transformed; the
   937-instruction table loop and the VM entry are untouched (§1). §8 shows the
   other regime: aimed at the loop, CFF costs 2.8 % runtime and 14 % text, BCF +
   CFF costs 11 % runtime and 70 % text — and still zero attack impact.
3. **No indirect branches are added.** The flattened switch is a compare chain
   over 32-bit state immediates; a decompiler or constant-propagation pass folds
   it. This is a property of this `Flattening` implementation (random 32-bit case
   labels), not of control-flow flattening in general.
4. **The RE-cost numbers are a static proxy.** "Instructions before the table
   base" counts the functions on the shortest call chain and their instruction
   counts. It is reproducible and directionally honest; it is not a human study
   and it does not price tooling that removes the dispatcher outright.
5. **Timings are wall-clock on one machine** (macOS arm64, 10 CPUs). Attack
   times are dominated by the 70 MB unmask and are stable to ±4 %; benchmark
   deltas below ±2.5 % are not resolvable.
6. **Scope of the claim**: this is a rebuild of `wbaes_nl_clean` from a scratch
   copy of `demos/wbaes` taken from the working tree during this measurement
   (HEAD then `f02cdf877`, with the table blob as shipped; HEAD has since moved).
   V0 reproduces the shipped artifact's `__text` shape exactly — same byte count,
   instruction count, block count, branch counts and `__hytab` reference count —
   so the comparison is apples to apples. It does not re-test the shipped
   `wbaes_nl_max` (8 passes), which adds `sub/mba/alias/indbr/indcall/gvenc` on
   top — those are data/instruction transforms and are out of scope here.
