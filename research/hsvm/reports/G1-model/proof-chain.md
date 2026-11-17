# G1-模型层证明链（白盒代码验证）

四跳，每跳都能用命令复算；任何一跳不成立，G1 的结论就不成立。

## 跳 1：转移式与差分捷径一致

- 实现：`src/model.cpp` — `step()` 是 `F = s ⊕ v ⊕ Eψ`；`differential()` 走
  预计算的 `HE` 列（因为 δ∈ker H 时 s、v 项精确抵消）。
- 验证：`test_model` 的 `differential() agrees with H*(F(s^d)^F(s)) on 200 cases`
  —— 两条独立路径逐位相等。
- 失败暴露：若 HE 预计算或窗口投影写错，这 200 例立刻不一致，后面所有 Γ 数字作废。

## 跳 2：核方向与窗口投影

- `kernelBasis()`（`src/gf2.cpp`）给出 H·B_K=0；`kernelSample()` 用均匀 r 映射到核。
- `projectedKernelBasis()` 把核基投影到窗口 A_i，按最高位增量消元保证线性无关。
- 验证：`test_model` 的 `500 sampled directions lie in ker(H)`；
  `test_psi`/`test_gf2` 覆盖 rank/核基/满秩随机矩阵。
- 失败暴露：δ 出核会让 D 包含 s 项，Γ 会被高估。

## 跳 3：Γ 与非仿射的测量口径

- Γ：每指令 states×(dirs) 次独立采样，D≠0 计数；Wilson 区间随结果输出。
- 非仿射：在 π_A(K) 上做二阶差分检验；dim≤16 穷举（记录 `checked`），
  否则抽样 10000 次并标记 `exhaustive=false`。
- 验证：`test_model` 的 `gamma stays >= 0.9`、`random table psi yields a non-affine D`、
  `small pi_A(K) dimension is tested exhaustively`、`large pi_A(K) falls back to sampled`。
- 失败暴露：抽样被写成"证明"时 `exhaustive` 字段会暴露；Γ 的 trials 计数与
  states×dirs 不符会被测试抓住。

## 跳 4：成本口径

- `stepWords()` 是发射内核将来的形态（无分配、无虚调用、无每步除法）；
  `test_model` 的 `stepWords matches step() for every instruction` 保证两条路径等价。
- 基线：`Machine` 的 Plain 模式（同一 ISA、同一 512 位寄存器堆），关掉 trace 后
  计时，除以实际执行步数。
- 验证：`hsvm_gamma --bench` 输出 `bench_model_ns / bench_plain_ns / step_cost_ratio`，
  `run_g1_model.py` 只在网格上调用它，不手填任何数值。
- 失败暴露：若基准被换成更慢的实现来提高"通过率"，`bench_plain_ns` 会明显偏离
  4–5ns 的历史值；该字段随每个点存档，可被复核。

## 反向证据（防止门禁靠巧合失败/通过）

- `test_psi` 的 Walsh 检验：SPN S 盒最大线性偏差 ≤2^-3，否则"非线性"是空话。
- `test_psi` 的雪崩：单纯分块混合只有 ~25% 位变化，测试会失败；当前实现加入
  车道旋转后才达到 ~50%（这是被测试抓出来并修复的真实缺陷）。
- `test_machine` 用三个原生参考对 300 组随机输入做差分，保证 Plain 基线本身正确。

## 复现

```bash
cd research/hsvm
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j10
ctest --test-dir build --output-on-failure
python3 scripts/run_g1_model.py --out reports/G1-model
python3 tools/judge_g1_model.py --grid reports/G1-model/grid.json \
        --out reports/G1-model/verdict.json
```
