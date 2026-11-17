# G0 证明链（白盒代码验证）

每条结论都要求能沿代码/产物走完整条链路，而不是"看起来对"。下面 5 跳，
每跳给出文件:行、验证命令、以及本跳的失败会怎样暴露。

## 跳 1：ISA 定义唯一

- 真源：`src/llvm/include/llvm/Transforms/Obfuscation/HSVMOpcodes.def`
- 镜像：`research/hsvm/include/hsvm/isa.h`（生成，勿手改）
- 验证：`python3 research/hsvm/tools/sync_isa.py --check`
- 失败暴露：ctest `isa_sync` 直接红；若有人手改镜像而没改真源，字节码编号会在
  编译器与模型之间漂移，trace 的 `op` 字段将不可解释。

## 跳 2：线性转移实现

- `research/hsvm/src/machine.cpp:169` — `F(s,i) = s XOR v(i)`，无数据依赖、无算术。
- `machine.cpp:186` / `:306` — 每步记录 `x_after = H·s'`；`x_before` 在步首记录。
- `machine.cpp:313,318` — 状态转储：初始边界 + 每步之后，共 steps+1 条。
- 验证：`test_linear` 逐条断言 `x_after == x_before ⊕ H·v(pc)`，并断言掩码互异。
- 失败暴露：任何一步不是"单次异或"都会让该断言失败；掩码重复会让 A1 的
  per-slot 恢复产生歧义。

## 跳 3：产物格式

- `tools/hsvm_run.cpp:7-9` — 三种产物：trace JSONL、truth JSON、state 二进制。
- truth 里的 `v[]` 由 `Machine::vTable()` 导出，`hv[]` 由 `matVec(H, v)` 现算，
  与攻击侧独立重算，避免"用同一份错数据自证"。
- 验证：`run_g0.sh` 里 `params_hash`、`queries`、`slots` 全部由脚本从产物读取。
- 失败暴露：truth 与 trace 的 slot 数不一致时，A1 的 `mismatch` 非零。

## 跳 4：攻击只由观测重算

- `attacks/a1_trace_diff.py:57` — 只用 `x_before`/`x_after`，按 pc 分组，
  不读 `v[]`；`hv[]` 仅在最后比对。
- `attacks/a2_memread.py` — 只用状态相邻两步异或，不读 `v[]`。
- 跨运行对照：A1 在第二个初始状态（`--init 0xDEADBEEF`）下必须得到同一张表。
- 失败暴露：若攻击读了真值，或只拟合单条轨迹，`cross_run_mismatch` 会非零，
  `judge_g0` 判失败。当前实测为 0。

## 跳 5：判定只看 JSON

- `tools/judge_g0.py` — 只读 `a1.json`/`a2.json`；要求覆盖满、mismatch 为 0、
  墙钟 ≤60s、跨运行一致；输出 `verdict.json`。
- `tools/make_report.py` — 把指标绑定到 `git_commit`、`protocol_sha256`、
  `params_hash`、查询数，再交给 `report.py validate`。
- 失败暴露：手改 run.json 里的数字而不同步 `raw_log`/查询数会被校验器拒收。

## 反向证据（防止"门禁靠巧合通过"）

- `test_machine` 用三个原生参考函数对 300 组随机输入做差分，证明 Plain 模式的
  解释器语义正确；否则"线性消融失败"可能只是解释器写错。
- `test_linear` 的输入无关性断言：不同内存内容 → 相同 x 轨迹；这是线性层零保护的
  直接证据，而不是"攻击脚本恰好成功"。
- GF(2) 库有两组故意注入的变异测试（见 `reports/M0/verification.md`），保证
  rank/kernel/solve 不是空转。

## 复现命令

```bash
cd research/hsvm
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j10
ctest --test-dir build --output-on-failure
bash scripts/run_g0.sh
python3 tools/report.py validate reports/G0/run.json
```
