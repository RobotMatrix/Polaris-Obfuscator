#!/bin/bash
# 混淆矩阵验证: PLAIN (系统 clang) vs OBF (Polaris 10-pass)
# 验证项:
#   1) 行为等价: conformance 输出逐字节一致
#   2) 体积开销: 二进制大小对比
#   3) 性能开销: bench_core 各操作耗时对比
# 输出: build/matrix_result.txt (供报告生成)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
POLARIS_CLANG="${POLARIS_CLANG:-/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/src/build/bin/clang++}"
OUT="$ROOT/build/matrix"
mkdir -p "$OUT"
RESULT="$ROOT/build/matrix_result.txt"
: > "$RESULT"

# Polaris pass 集: arm64 用 9-pass (ccc 仅 x86; 见 README_FINAL 与 docs/06)
PASSES="alias,gvenc,indcall,indbr,mba,sub,bcf,fla,merge"

SRCS="$ROOT/src/crypto/sha2.c $ROOT/src/crypto/aes_wrap.c $ROOT/src/crypto/ed25519.c \
$ROOT/third_party/tiny_aes.c $ROOT/src/key_provider.cpp $ROOT/src/crypto_service.cpp \
$ROOT/src/license.cpp $ROOT/src/protocol.cpp $ROOT/src/server/authorization_server.cpp \
$ROOT/src/risk_model.cpp $ROOT/src/secure_sdk.cpp"

INC="-I $ROOT/include -I $ROOT/third_party -I $ROOT/src"
COMMON="-std=c++17 -O2 -DNDEBUG"
FRAMEWORKS=""
if [ "$(uname)" = "Darwin" ]; then FRAMEWORKS="-framework CoreFoundation -framework Security"; fi

echo "== 混淆矩阵 ==" | tee -a "$RESULT"
echo "plain-compiler: $(clang++ --version | head -1)" | tee -a "$RESULT"
echo "polaris-compiler: $($POLARIS_CLANG --version | head -1)" | tee -a "$RESULT"
echo "passes: $PASSES" | tee -a "$RESULT"

# ---- 1. PLAIN 构建 ----
echo "[1/5] PLAIN 构建..." | tee -a "$RESULT"
clang++ $COMMON $INC "$ROOT/tools/conformance.cpp" $SRCS -o "$OUT/conformance_plain" $FRAMEWORKS 2>"$OUT/plain_build.log" || {
    echo "FAIL: plain build" | tee -a "$RESULT"; exit 1; }
clang++ $COMMON $INC "$ROOT/tools/bench_core.cpp" $SRCS -o "$OUT/bench_plain" $FRAMEWORKS 2>>"$OUT/plain_build.log" || {
    echo "FAIL: plain bench build" | tee -a "$RESULT"; exit 1; }

# ---- 2. OBF 构建 (Polaris) ----
echo "[2/5] Polaris OBF 构建 ($PASSES)..." | tee -a "$RESULT"
$POLARIS_CLANG $COMMON $INC "$ROOT/tools/conformance.cpp" $SRCS \
    -mllvm -passes="$PASSES" -o "$OUT/conformance_obf" $FRAMEWORKS 2>"$OUT/obf_build.log" || {
    echo "FAIL: obf build (见 $OUT/obf_build.log)" | tee -a "$RESULT"; tail -5 "$OUT/obf_build.log" | tee -a "$RESULT"; exit 1; }
$POLARIS_CLANG $COMMON $INC "$ROOT/tools/bench_core.cpp" $SRCS \
    -mllvm -passes="$PASSES" -o "$OUT/bench_obf" $FRAMEWORKS 2>>"$OUT/obf_build.log" || {
    echo "FAIL: obf bench build" | tee -a "$RESULT"; exit 1; }

# ---- 3. 行为等价 ----
echo "[3/5] 行为等价性..." | tee -a "$RESULT"
"$OUT/conformance_plain" > "$OUT/out_plain.txt"; RC1=$?
"$OUT/conformance_obf"   > "$OUT/out_obf.txt";   RC2=$?
if [ $RC1 -eq 0 ] && [ $RC2 -eq 0 ] && cmp -s "$OUT/out_plain.txt" "$OUT/out_obf.txt"; then
    LINES=$(wc -l < "$OUT/out_plain.txt" | tr -d ' ')
    echo "PASS: 行为等价 ($LINES 行输出逐字节一致, 退出码均为 0)" | tee -a "$RESULT"
else
    echo "FAIL: 行为不一致 (rc: plain=$RC1 obf=$RC2)" | tee -a "$RESULT"
    diff "$OUT/out_plain.txt" "$OUT/out_obf.txt" | head -20 | tee -a "$RESULT"
    exit 1
fi

# ---- 4. 体积开销 ----
echo "[4/5] 体积开销..." | tee -a "$RESULT"
S1=$(stat -f%z "$OUT/conformance_plain")
S2=$(stat -f%z "$OUT/conformance_obf")
echo "size_plain_bytes $S1" | tee -a "$RESULT"
echo "size_obf_bytes $S2" | tee -a "$RESULT"
echo "size_overhead_x $(echo "scale=2; $S2 / $S1" | bc)" | tee -a "$RESULT"

# ---- 5. 性能开销 (各跑 3 次取中位) ----
echo "[5/5] 性能开销..." | tee -a "$RESULT"
run_bench() {
    local bin=$1 out=$2
    : > "$out"
    for i in 1 2 3; do "$bin" >> "$out" 2>/dev/null; done
}
run_bench "$OUT/bench_plain" "$OUT/bench_plain_raw.txt"
run_bench "$OUT/bench_obf" "$OUT/bench_obf_raw.txt"
python3 "$ROOT/scripts/bench_median.py" "$OUT/bench_plain_raw.txt" "$OUT/bench_obf_raw.txt" | tee -a "$RESULT"

echo "== 矩阵完成 ==" | tee -a "$RESULT"
exit 0
