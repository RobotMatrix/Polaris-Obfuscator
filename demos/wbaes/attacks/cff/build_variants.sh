#!/bin/bash
# build_variants.sh — build the same white-box program four ways:
#   V0 none, V1 fla (CFF), V2 bcf (bogus CFG), V3 bcf+fla
# and a bench harness for each.
#
# The Polaris pipeline (src/llvm/lib/Transforms/Obfuscation/Pipeline.cpp) takes
# the pass list as `-mllvm -passes=<name,...>`; fla maps to Flattening, bcf to
# BogusControlFlow2. Both only touch functions whose annotation names them
# (readAnnotate), so the result depends on which functions the source marks.
#
#   usage: build_variants.sh <src-dir> <out-dir> [clang++]
#   <src-dir> must contain the wbaes sources + hy_table.bin (a scratch copy;
#   nothing here writes to the repo).
#
# The pass RNG is seeded from the clock unless -mllvm -obf-seed=N is given
# (src/llvm/lib/Support/ObfuscationSeed.cpp), and BogusControlFlow2 skips a
# block with probability 20% per roll, so bcf builds differ run to run without
# a pinned seed. OBF_SEED pins it; set OBF_SEED=0 to observe the raw spread.
set -euo pipefail

SRC=${1:?usage: build_variants.sh <src-dir> <out-dir> [clang++]}
OUT=${2:?usage: build_variants.sh <src-dir> <out-dir> [clang++]}
CXX=${3:-/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/src/build/bin/clang++}
OBF_SEED=${OBF_SEED-1234}
SEED_FLAG="-mllvm -obf-seed=$OBF_SEED"

mkdir -p "$OUT"
DEFS="-DWBAES_BAKED -DWBAES_NO_MIR -DWBAES_HAVE_VM"
FLAGS="-O2 -std=c++17 $DEFS -I."

# The VM translation unit always goes through the hsvm lowering pass and is
# compiled once; the variants differ only in the demo TU, exactly as the
# shipped build does it.
( cd "$SRC" && $CXX $FLAGS -mllvm -passes=hsvm -c wbaes_vm.cpp -o "$OUT/wbaes_vm.o" )

build_one() {  # name, pass-list
  local name=$1 passes=$2
  ( cd "$SRC"
    $CXX $FLAGS demo_wbaes.cpp hy_tab.S "$OUT/wbaes_vm.o" \
         $SEED_FLAG ${passes:+-mllvm -passes=$passes} -o "$OUT/$name"
    $CXX $FLAGS bench_wbaes.cpp hy_tab.S "$OUT/wbaes_vm.o" \
         $SEED_FLAG ${passes:+-mllvm -passes=$passes} -o "$OUT/bench_$name" )
  printf '%-10s %s\n' "$name" "$(stat -f%z "$OUT/$name") bytes"
}

build_one v0_none ""
build_one v1_fla  "fla"
build_one v2_bcf  "bcf"
build_one v3_both "bcf,fla"
