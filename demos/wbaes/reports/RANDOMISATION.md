# Per-execution randomisation vs the consistency attack

**Question.** Does shuffling the 16 lane decodes per call and issuing K dummy table
reads per round raise the number of address traces the consistency attack
(`attacks/residual/consistency_attack.py`) needs to converge?

**Answer.** Not in any way that matters.

* Against the attack **as shipped**, K=4 and K=16 do not raise the cost — they
  destroy the attack outright, and *more* traces make it worse, not better: the
  attack needs every collision pair to agree, one dummy-corrupted trace poisons
  about `T/256` pairs, and the false-pair count grows linearly with `T`. At
  K=16 no trace count up to 4096 yields a key.
* Against an attacker who looks at **how many times** a table is hit in one block
  — a check that needs no key and no extra traces — K=4 costs **1.04x** and K=16
  costs **1.16x** in traces. The gain is `(1 - 1/112)^-K`, a constant factor
  linear in K, not an asymptotic wall.
* The residual path works completely. After bootstrapping the key from the
  unambiguous traces, the attacker rebuilds the unknown boundary bijections and
  re-labels the ambiguous ones; **4410/4410** re-labelled reads at K=16 were
  correct and the curve is then *identical* to K=0 (8/8 at 64 traces).
* The shuffle alone is worth **nothing** to this attack: the curve is identical
  with and without it, and it costs 0 extra accesses.

Measured on the shipped `wbaes_vm2_clean` artifact, 4096 traces per level,
`4f065a03…` recovered at every level where the attack converges at all.

---

## 1. What was implemented

Three levels, all in a copy of the runtime (a `/tmp` tree); nothing under
`demos/wbaes` was edited. `rnd/patch_header.py` regenerates the randomised header
from the shipped one, so the change is a script, not a hand-edited file.

| level | shuffle of the 16 lane decodes | dummy reads per round | dummy reads per block |
|---|---|---|---|
| K=0 | no | 0 | 0 |
| K=0+shuffle | yes | 0 | 0 |
| K=4 | yes | 4 | 36 |
| K=16 | yes | 16 | 144 |
| K=64 (extra probe) | yes | 64 | 576 |

**Per call, not per build.** `hy_mc_round` draws a Fisher-Yates permutation from
`hy_rnd_next()`, and the caller re-seeds at the top of every block from a counter
(`seed = base ^ (t+1)*0x9E3779B1 ^ 0xA5C31E87`). All 4096 blocks of every level
have a distinct seed, and the seed of each trace is written to
`<prefix>_seeds.bin`, so any recorded permutation can be replayed. A fixed
permutation would be pointless: one trace would reveal it and the attacker would
subtract it, which is exactly why the seed is per call and recorded rather than
derived once.

**Dummies.** Each one copies the `(offset, width)` of a real access of the same
column — sampled uniformly from that column's access sites, which is 28 sites for
F1/F3, 40 for F2 and 18 for F0 — and draws a **fresh** index inside that table.
Consequences, all measured below:

* a dummy is indistinguishable from a real access by width (it draws a 4-byte lane
  site or a 1-byte table site with the frequency its own column uses them, 10.5%
  wide overall) or by offset class (it reads a table the block really reads);
* re-using the *same* index would make the dummy a duplicate address and one
  `set()` would delete it, so the index is fresh;
* half the dummies are emitted before their row's boundary decode and half after,
  so a dummy precedes the real access it imitates about half the time. Emitting
  them all after the block would have made the shipped first-hit reader immune by
  construction — measured at 49.8% (K=4), 50.9% (K=16), 54.8% (K=64) wrong, so the
  placement is neutral, not rigged for or against the defence.

**Function identity.** The dummy value is read and discarded; the real reads, their
tags and their order within each phase are the shipped ones.

## 2. Function identity — the same cipher, 4096 blocks per level

| level | blocks compared to K=0 | equal | distinct seeds | accesses/block |
|---|---|---|---|---|
| K=0 | — (reference) | — | 4096 | 1464 |
| K=0+shuffle | 4096 | 4096 | 4096 | 1464 |
| K=4 | 4096 | 4096 | 4096 | 1500 |
| K=16 | 4096 | 4096 | 4096 | 1608 |
| K=64 | 4096 | 4096 | 4096 | 2040 |

That is 4096 blocks at each of four randomised levels, plus the challenge vector,
plus an independent check that the K=0 reference is the artifact and not itself:
`wblib.encrypt` over the artifact's own table reproduces 64/64 recorded K=0
ciphertexts, and `AES-128(6bc1bee2…2a)` over the artifact gives
`7672415a6313c58518fc95c9cb6922b8`. The harness prints
`ct:7672415a6313c58518fc95c9cb6922b8` for the challenge vector at every level.

## 3. Traces to converge — the curve

Cells are *halves with exactly one candidate* out of 8; `*` marks the cells where a
complete 16-byte key came out and reproduced the ciphertext. The attack takes the
first T traces in file order (the convention the shipped script uses), cap 2000
collision pairs, row 0, all four columns.

| level | mode | 32 | 64 | 128 | 256 | 512 | 1024 | 4096 |
|---|---|---|---|---|---|---|---|---|
| K=0 | as shipped | 3/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |
| K=0+shuffle | as shipped | 3/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |
| K=4 | as shipped | 3/8 | 7/8 | 6/8 | 1/8 | 1/8 | 0/8 | 0/8 |
| K=16 | as shipped | 4/8 | 6/8 | 3/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| K=64 | as shipped | 3/8 | 4/8 | 0/8 | 0/8 | 0/8 | 0/8 | 0/8 |
| K=0 | multiplicity filter | 3/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |
| K=4 | multiplicity filter | 3/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |
| K=16 | multiplicity filter | 5/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |
| K=64 | multiplicity filter | 3/8 | 7/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |

Two things to read off.

**The shipped attack is destroyed, not slowed.** At K=4 and K=16 the curve goes the
wrong way: 64 traces is its best cell and 4096 is its worst. It also fails *loudly*
— the failing halves return **zero** candidates, never a wrong one — because the
meet-in-the-middle requires the two signature halves to be equal on *every*
collision pair.

**The 32-trace cell is noise in every row, including K=0.** With 1–4 pairs the
MITM leaves 250+ candidates ("widest 252"), so the count is not a convergence
measure there. Across 8 disjoint windows of 32 traces the K=0 level itself gives
3, 1, 3, 3, 3, 1, 4, 2 out of 8. The convergence point is 64 traces, and it is
stable: across the same 8 windows at 64 traces every level with the filter gives
8/8 and the key.

### Why more traces make it worse — measured, not argued

A trace whose boundary read was replaced by a dummy contributes a random half-index.
A false collision pair enters the signature set and no `(k0,k1)` can satisfy all
pairs, so the half returns nothing. The false-pair count grows with T because a
corrupted trace collides with about `T/256` others. Measured per level, per half:

| traces | K=4: halves with ≥1 false pair | K=4: halves failing | K=16: halves with ≥1 false pair | K=16: halves failing |
|---|---|---|---|---|
| 64 | 1 | 1 | 2 | 2 |
| 128 | 2 | 2 | 5 | 5 |
| 256 | 7 | 7 | 8 | 8 |
| 512 | 7 | 7 | 8 | 8 |
| 1024 | 8 | 8 | 8 | 8 |

The two columns agree in all ten rows. This is the whole mechanism: the defence
does not add work to the attack, it removes the property the attack relies on, and
it removes more of it the longer the attacker collects.

## 4. What a smarter attacker does

Ambiguity, and what each counter recovers. 65536 `(trace, boundary table)` reads per
level:

| level | reads with 2 candidates | first-in-order takes the dummy | sorting by address still takes the dummy | clean traces, row-0 tables |
|---|---|---|---|---|
| K=4 | 2346 (3.58%) | 1168 (49.8%) | 1155 (49.2%) | 96.38% |
| K=16 | 8964 (13.68%) | 4559 (50.9%) | 4553 (50.8%) | 86.47% |
| K=64 | 29014 (44.27%) | 15892 (54.8%) | 15676 (54.0%) | 56.09% |

The first three columns cover all sixteen `(col,row)` boundary tables of round 0;
the yield is measured on the four row-0 tables, which are the ones the attack
reads. The two differ by 0.05 percentage points, i.e. by sample.

**Sorting addresses does not realign anything.** The real and the dummy read the
same 64K table, so the ordering rule "smallest address first" is a coin flip:
49.2% / 50.8% / 54.0% wrong. It is a fixed function of the two addresses and there
is no reason for the real one to sort first. No re-alignment by order, address or
offset class is recovered this way.

**Restricting to an offset class does not separate them either**, because the
dummy *is* in the same offset class by construction: it reads the same table, at
the same width, at an offset drawn from the same pool. Measured over all 4096
traces of each level, every block carries exactly K×9 extra reads and none of the
real ones are lost: K=4 gives 32.26 one-byte + 3.74 four-byte, K=16 gives 128.89 +
15.11, K=64 gives 515.83 + 60.17. The 4-byte share (10.5%) is the per-column site
mix the dummies copy — 4 of 28 sites in F1/F3, 2 of 18 in F0, none in F2 — so a
filter keyed on width keeps the dummy just as a filter keyed on offset does.

**The multiplicity filter is free and works.** A real block hits each 64K boundary
table exactly once, so "keep the traces where this table is hit once" removes
exactly the corrupted reads. It needs no key and no extra traces. It costs the
data it discards:

| level | yield | traces for 64 clean (K=0 needs 64) | cost factor | measured |
|---|---|---|---|---|
| K=4 | 96.38% | 67 | 1.04x | 64 filtered traces suffice (8/8 windows) |
| K=16 | 86.47% | 74 | 1.16x | 64 filtered traces suffice (8/8 windows) |
| K=64 | 56.09% | 114 | 1.78x | 64 not enough, 128 filtered suffice |

The model `(1 - 1/112)^K` for the yield is within measurement error of every row,
so the cost is linear in K: the defender must pay roughly one extra real access per
112 for every trace of cost he wants. K=16 buys 10 traces.

### The residual path: block-boundary realignment

Bootstrapping is cheap: the filter gives the key at 74 real traces, and the shipped
attack ran end to end (4096 traces, 8 halves) in 2.9 s. With the key, the attacker
computes `x = MC·S(pt^k)` for both pair sums of every trace, rebuilds the maps
`Zl`, `Zr` from the clean traces (`Z` is a fixed bijection, so `u = Z(x)` must agree
across traces with the same `x`), and then picks, in each ambiguous trace, the
candidate whose value equals `Z(x)`:

| level | ambiguous reads | resolved uniquely | picked correctly | unresolved | accuracy |
|---|---|---|---|---|---|
| K=4 | 1186 | 1183 | 1183 | 3 | 100% |
| K=16 | 4434 | 4410 | 4410 | 24 | 100% |
| K=64 | 14388 | 14306 | 14306 | 82 | 100% |

and the curve on the fully relabelled trace set:

| level | 32 | 64 | 128 | 256 | 512 | 1024 | 4096 |
|---|---|---|---|---|---|---|---|
| K=4 relabelled | 3/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |
| K=16 relabelled | 3/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 8/8 * |
| K=64 relabelled | 3/8 | 8/8 * | 8/8 * | 8/8 * | 8/8 * | 6/8 | 7/8 |

At K=4 and K=16 nothing is discarded after one bootstrap: the curve is the K=0
curve. At K=64 the relabel stops being perfect (82 of 14388 reads keep two
candidates that both match `Z(x)`, 0.57%), and the wrong labels it leaves behind
make the 1024 and 4096 cells fail. That is where the constant-factor picture starts to bend, and it is
also where the defender is already paying 2.8x per block.

## 5. What it costs the defender

Trace-enabled reference loop, `-O2`, arm64, table resident in cache, median of
4096 blocks x 4 reps, median of three runs of the same build. The recorder is off
in this pass, so the numbers are the cipher and not the logger.

| level | extra accesses/block | median µs/block | vs K=0 | ns per extra access |
|---|---|---|---|---|
| K=0 | 0 | 10.5 | 1.00 | — |
| K=0+shuffle | 0 | 11.4 | 1.09 | — |
| K=4 | 36 | 11.7 | 1.11 | 33 |
| K=16 | 144 | 14.8 | 1.41 | 24 |
| K=64 | 576 | 29.4 | 2.80 | 31 |

The shuffle is most of K=4's cost: 0.9 µs of the 1.2 µs, because the lane reads now
jump between four column slots 800 KB apart instead of walking one column. Each
dummy costs about 30 ns, the same as one real table read. Attack wall clock is flat
— 3.3 s for the full 7-point curve at K=0, K=4 and K=16 alike — because the MITM cost
depends on the pair cap, not on the level.

## 6. Verdict

1. **How many extra traces do K=4 and K=16 buy?** 3 and 10 (67 vs 64, 74 vs 64), and
   only against an attacker who does not count hits per table. Against the shipped
   attack they buy everything: it stops converging at any trace count, and collects
   *worse* results the longer it runs.
2. **Asymptotic or constant?** Constant, and a small one: the factor is
   `(1 - 1/112)^-K ≈ e^(K/112)`, linear in K. A round spreads its K dummies K/4
   per column, and a dummy in the right column hits the attacked table with
   probability 1/28 (28 access sites), so the hit rate is K/112 — which is exactly
   the 3.58% / 13.68% / 44.27% measured in section 4. There is no
   threshold and no wall: a factor of 2 needs K≈78, which the measured 30 ns per
   dummy prices at roughly 3x per block (extrapolated from the K=64 row, not
   measured), and which the relabel at K=64 already partly undoes.
3. **The residual path works.** Block-boundary realignment against the recovered
   `Zl`/`Zr` recovers the real access in 100% of the reads it resolves (4410/4410 at
   K=16) and restores the K=0 curve exactly. Randomisation at this budget is
   therefore a constant factor in traces *and* nothing at all in attack time.
4. **The shuffle alone is worth nothing** against this attack, because the attack
   indexes by address and never by position. It is worth something only against an
   attacker who assumes a fixed access order, which none of the scripts in
   `attacks/` do.

What this does not show: only the consistency attack on the dl5 artifact, only the
address-trace model (no value traces, no cache side channel), and timings with a
warm table. `dca_attack.py` and `bge_attack.py` consume the same trace format and
would need their own curve; the mechanism measured here (dummies dilute the
per-table hit count, a per-table multiplicity filter undoes it) applies to any
attack that reads one table per block.

## 7. Commands

Everything runs on a copy; `demos/wbaes/wbaes_hybrid.h` is read-only input.

```bash
# 1. randomised runtime + traces (4096 blocks per level)
for spec in "0 0 k0_s0" "0 1 k0_s1" "4 1 k4_s1" "16 1 k16_s1" "64 1 k64_s1"; do
  set -- $spec
  python3 demos/wbaes/attacks/rnd/rnd_traces.py --k $1 --shuffle $2 --n 4096 \
      --work /tmp/wbaes-rnd2/$3
done

# 2. identity, dummy statistics
python3 demos/wbaes/attacks/rnd/measure.py --work /tmp/wbaes-rnd2

# 3. the curve, shipped attack and filtered attack
for lv in k0_s0 k0_s1 k4_s1 k16_s1 k64_s1; do for m in naive filter; do
  python3 demos/wbaes/attacks/rnd/curve.py \
      --traces /tmp/wbaes-rnd2/$lv/rnd_${lv}_traces.bin --mode $m
done; done

# 4. smarter attacker
python3 demos/wbaes/attacks/rnd/realign.py \
    --traces /tmp/wbaes-rnd2/k16_s1/rnd_k16_s1_traces.bin \
    --truth  /tmp/wbaes-rnd2/k0_s0/rnd_k0_s0_traces.bin

# 5. stability of the 64-trace cell (8 disjoint windows)
for off in 0 100 200 300 400 500 600 700; do
  python3 demos/wbaes/attacks/rnd/curve.py \
      --traces /tmp/wbaes-rnd2/k16_s1/rnd_k16_s1_traces.bin --mode filter --offset $off
done
```

`rnd/harness_rnd.cpp` is a copy of `attacks/trace_harness/harness.cpp` with three
additions: per-block seeding, `_seeds.bin`/`_ct.bin` output, and a timed pass with
the recorder off. `rnd/rnd_traces.py` reuses `build_traces.py`'s own `HOOKS` table
by importing it, so the five hook sites are byte-identical to the shipped harness.

**What changed in the attack scripts: nothing.** `consistency_attack.py`,
`reslib.py` and `wblib.py` are imported unmodified; `curve.py` re-expresses their
section 3 as a per-level driver and `realign.py` adds the multiplicity filter and
the relabel as extra attacker capability. Both are strictly more powerful than the
shipped attack — no threshold, cap or candidate test was relaxed. The shipped
script run unchanged on the K=0 trace file reproduces the documented baseline:
`32 traces -> 3/8, 64 traces -> 8/8, key 4f065a03…, 2.9 s end to end`.
