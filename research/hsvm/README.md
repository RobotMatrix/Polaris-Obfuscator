# research/hsvm — HSV 研究层

隐藏状态空间 VM（V1.3 方案）的模型层与攻击/度量层。设计见
`../../.hermes/plans/2026-11-17_1508-hsvm-polaris-implementation.md`。

**规则**

- 只用 C++17 + 标准库；不引入 Eigen/numpy 等依赖。这里跑的是"可信 oracle"，
  依赖越少越容易白盒审查。
- 任何"通过"结论必须有对应测试或攻击脚本；报告里不许手填数字。
- 模型层不 include LLVM 头文件。编译器 pass 是它的消费者，不是它的依赖。

## 构建与测试

```bash
cmake -S research/hsvm -B research/hsvm/build -DCMAKE_BUILD_TYPE=Release
cmake --build research/hsvm/build -j10
ctest --test-dir research/hsvm/build --output-on-failure
```

单个测试可直接跑，会逐条打印 PASS/FAIL：

```bash
./research/hsvm/build/test_gf2
```

## 目录

```
include/hsvm/   公共头（gf2.h 目前唯一）
src/            实现
tests/          ctest 用例（test_harness.h 提供 CHECK）
tools/          命令行工具（M1 起：hsvm_asm / hsvm_run / hsvm_gamma ...）
attacks/        攻击脚本（M1 起：a1_trace_diff.py / interp.py / bge.py ...）
reports/        每次运行的证据包（run.json + summary.md）
```

## 当前状态

- M0-1…M0-5：完成（骨架 / GF(2) / 参数 / 协议 / 报告）
- M1 阶段 0：完成，**G0 通过**（A1/A2 全表恢复，0.0001s）
- M2 阶段 1 模型层：完成，**G1-模型层失败**（Γ 与非仿射全过，成本 5.6–45× > 3×）
- M2 补充（ADR-006 方案 B）：ARX ψ 把不可枚举点从 22.1× 降到 10.9×，仍失败
- v2.0（ADR-008 草案）G0v2 成本下界：唯一可行点 2.53× 但实测内核 6.65×
  → **失败，C1/C2 路线终止（ADR-009），未实现 C2**
- 阶段 3 模块编码 + 全局正规化：完成实验，**负结果**（查询数=2^w，与模块数无关）
- 阶段 4 G3/G4 博弈：完成，G3 在 w≤16 全成功、G4 仅 w=8 满足 4 KiB
- 阶段 4A C6 证据层：完成（`c6.h/c6.cpp`，18 条断言，三平面 + 链式证据 + 状态机）
- 阶段 4B C7 多样性：完成实验，**负结果**（16 实例均 16 次查询被恢复，多样性不加成本）
- M3 起（LLVM pass、C2、阶段 3/4 博弈、Native VM）：未开始
- 证据：`reports/M0/`、`reports/M1/`、`reports/G0/`、`reports/G1-model/`、
  `reports/G1-model-addendum/`
- 决策：`DECISIONS.md`（ADR-006 判定与选项、ADR-007 方案 B 结果与建议）
