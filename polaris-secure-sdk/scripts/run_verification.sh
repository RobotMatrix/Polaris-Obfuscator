#!/bin/bash
# 一键自动化验证: 构建 → 单元/攻击/集成测试 → 混淆矩阵 → 生成验证报告
# 用法: ./scripts/run_verification.sh [--skip-matrix]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SKIP_MATRIX=0
[ "${1:-}" = "--skip-matrix" ] && SKIP_MATRIX=1

echo "=============================================="
echo " polaris-secure-sdk 自动化验证"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
FAIL=0

echo "==> [1/4] CMake 构建 (Release)"
cmake -B build -DCMAKE_BUILD_TYPE=Release >/dev/null || exit 1
cmake --build build -j 2>&1 | grep -E " error " && FAIL=1
[ $FAIL -ne 0 ] && { echo "构建失败"; exit 1; }

echo "==> [2/4] 模型再生成 (确定性校验)"
python3 tools/gen_mlp_model.py >/dev/null 2>&1 || { echo "模型生成失败"; FAIL=1; }

echo "==> [3/4] ctest 全量 (单元 + 攻击模拟 + 集成)"
cd build
ctest > "$ROOT/build/ctest_result.txt" 2>&1
TESTRC=$?
cd "$ROOT"
if [ $TESTRC -ne 0 ]; then
    echo "ctest 存在失败项:"
    grep -E "FAILED|Failed" "$ROOT/build/ctest_result.txt" | head -10
    FAIL=1
else
    echo "ctest: 100% 通过"
fi
# 记录每个套件的 pass/fail 统计
: > "$ROOT/build/ctest_detail.txt"
for t in test_crypto_kat test_crypto_service test_license test_protocol_online test_risk_policy test_integration; do
    OUT=$(./build/$t 2>&1 | tail -1)
    echo "$t :: $OUT" >> "$ROOT/build/ctest_detail.txt"
done

echo "==> [4/4] 混淆矩阵 (PLAIN vs Polaris)"
MATRIX_OK=1
if [ $SKIP_MATRIX -eq 0 ]; then
    if ./scripts/obfuscation_matrix.sh > /dev/null 2>&1; then
        echo "混淆矩阵: 通过"
    else
        echo "混淆矩阵: 失败"
        FAIL=1
        MATRIX_OK=0
    fi
else
    echo "混淆矩阵: 跳过 (--skip-matrix)"
fi

echo "==> 生成验证报告"
python3 scripts/gen_report.py "$MATRIX_OK" > docs/07_验证报告.md || FAIL=1

if [ $FAIL -eq 0 ]; then
    echo "=============================================="
    echo " 全部验证通过 ✔  报告: docs/07_验证报告.md"
    echo "=============================================="
    exit 0
else
    echo "=============================================="
    echo " 验证存在失败项 ✘"
    echo "=============================================="
    exit 1
fi
