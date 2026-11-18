#!/bin/sh
# Build every artifact the S4 report measures.  Run from the scratch dir:
#   sh /Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/demos/ios/reports/build_s4.sh
set -e
REPO=/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator
CL=$REPO/src/build/bin/clang++
S=$REPO/demos/ios/demo6_mir_noeh.cpp
S4=$REPO/demos/ios/demo6_merge4.cpp
WB="$REPO/demos/wbaes/demo_wbaes.cpp $REPO/demos/wbaes/tiny_aes.c"
OUT=${1:-$PWD}
SEED_A=${SEED_A:-12345}
SEED_B=${SEED_B:-777}
SEED_C=${SEED_C:-424242}

cd "$OUT"
rm -f *.tsv

# ---- demo6: one obfuscated function, so the merge has nothing to merge ----
$CL -O1 "$S" -mllvm -obf-seed=$SEED_A -o D_base 2>/dev/null
$CL -O1 "$S" -mllvm -obf-seed=$SEED_A -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=d_s1.tsv -o D_S1 2>/dev/null
$CL -O1 "$S" -mllvm -obf-seed=$SEED_A -mllvm -passes=merge \
    -mllvm -merge-then-split -mllvm -merge-scope-sidecar=d_m.tsv \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=d_s4.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=3 \
    -mllvm -split-chunk-max=7 -o D_S4 2>/dev/null
$CL -O1 "$S" -mllvm -obf-seed=$SEED_B -mllvm -passes=merge \
    -mllvm -merge-then-split \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=d_s4_b.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=3 \
    -mllvm -split-chunk-max=7 -o D_S4b 2>/dev/null
$CL -O1 "$S" -mllvm -obf-seed=$SEED_C -mllvm -passes=merge \
    -mllvm -merge-then-split \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=d_s4_c.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=3 \
    -mllvm -split-chunk-max=7 -o D_S4c 2>/dev/null
# fixed granularity, same flags otherwise: the S1-shaped comparison
$CL -O1 "$S" -mllvm -obf-seed=$SEED_A -mllvm -passes=merge \
    -mllvm -merge-then-split \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=d_s4fix.tsv \
    -o D_S4fixed 2>/dev/null

# ---- demo6_merge4: four source functions in one merged body --------------
$CL -O1 "$S4" -mllvm -obf-seed=$SEED_A -o M_base 2>/dev/null
$CL -O1 "$S4" -mllvm -obf-seed=$SEED_A -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=m_s1.tsv -o M_S1 2>/dev/null
$CL -O1 "$S4" -mllvm -obf-seed=$SEED_A -mllvm -passes=merge \
    -mllvm -merge-then-split -mllvm -merge-scope-sidecar=m_m.tsv \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=m_s4.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=3 \
    -mllvm -split-chunk-max=7 -o M_S4 2>/dev/null
$CL -O1 "$S4" -mllvm -obf-seed=$SEED_B -mllvm -passes=merge \
    -mllvm -merge-then-split -mllvm -merge-scope-sidecar=m_m_b.tsv \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=m_s4_b.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=3 \
    -mllvm -split-chunk-max=7 -o M_S4b 2>/dev/null
$CL -O1 "$S4" -mllvm -obf-seed=$SEED_C -mllvm -passes=merge \
    -mllvm -merge-then-split -mllvm -merge-scope-sidecar=m_m_c.tsv \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=m_s4_c.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=3 \
    -mllvm -split-chunk-max=7 -o M_S4c 2>/dev/null
# merged body, fixed granularity: the attribution measurement needs every
# chunk of the merged interval, and the random rule happens to split fewer of
# its blocks (measured below)
$CL -O1 "$S4" -mllvm -obf-seed=$SEED_A -mllvm -passes=merge \
    -mllvm -merge-then-split -mllvm -merge-scope-sidecar=m_mfix.tsv \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=m_s4fix.tsv \
    -o M_S4fixed 2>/dev/null

# merged body without the split: what the merge alone gives an analyst
$CL -O1 "$S4" -mllvm -obf-seed=$SEED_A -mllvm -passes=merge \
    -mllvm -merge-then-split -mllvm -merge-scope-sidecar=m_monsplit.tsv \
    -o M_mergeonly 2>/dev/null

# ---- profile B on the merged build --------------------------------------
cp M_S4 M_S4_B1 && strip M_S4_B1
python3 $REPO/demos/wbaes/tools/macho_scrub.py --in M_S4_B1 --out M_S4_B2 \
    --seed s4-B --unwind neutralise >/dev/null

# ---- wbaes: static only (the demo SIGTRAPs on this host either way) ------
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla,merge \
    -mllvm -obf-seed=$SEED_A -o W_base 2>/dev/null
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla \
    -mllvm -obf-seed=$SEED_A -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=w_s1.tsv -o W_S1 2>/dev/null
# The two functions the MIR split touches (enc_core/dec_core) return int, and
# merge() only consumes void functions: S4's direct path is void-only, so the
# merged set here is the two void members (encrypt/decrypt).  Targeting
# enc_core/dec_core instead puts them through the legacy stub-wrapper path,
# which crashes (6/6 builds, see the report).
cat > wb_policy.json <<'EOF'
{ "passes": ["merge"], "targets_mangled": ["_ZNK5WBAES7encryptEPKhPh",
  "_ZNK5WBAES7decryptEPKhPh"] }
EOF
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla,merge \
    -mllvm -obf-seed=$SEED_A -mllvm -policy-file=wb_policy.json \
    -mllvm -merge-then-split -mllvm -merge-scope-sidecar=w_m.tsv \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=w_s4.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=5 \
    -mllvm -split-chunk-max=9 -o W_S4 2>/dev/null
cp W_S4 W_S4_B1 && strip W_S4_B1
python3 $REPO/demos/wbaes/tools/macho_scrub.py --in W_S4_B1 --out W_S4_B2 \
    --seed s4-Bw --unwind neutralise >/dev/null

echo "built; sizes:"
ls -l D_base D_S1 D_S4 D_S4b D_S4c M_base M_S1 M_S4 M_S4b M_S4c M_mergeonly \
      M_S4_B1 M_S4_B2 W_base W_S1 W_S4 W_S4_B2 | awk '{print $5, $9}'
