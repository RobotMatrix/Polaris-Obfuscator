# 阶段 5（VMP）收口报告

范围：`research/hsvm` 的 V-01…V-11 与 `src/llvm` 的 `-passes=hsvm`。
本节回答一个问题：**字节码经 Polaris 编译器产出的原生代码，与解释器是否语义一致**，
以及这件事**证明了什么、没证明什么**。

## 一、链路与证据

```
字节码 (8 字节/指令)
  └ lift        → MirOp         ctest mir         103 断言   无损解码
  └ lowerOp     → IrOp          ctest lower_regs   15 断言   寄存器类 + 变异检验
                                ctest lower_full   19 断言   全 16 opcode 三方比对
  └ emitC       → C 源码        ctest emit_c       18 断言   clang -O1，退出码 0/3/5
  └ HSVMLowering→ LLVM IR       ctest vmp_gate      6 用例   真实程序端到端
```

三方/四方一致性：
- 解释器 `Machine(Plain)` ↔ oracle `semStep`：`ctest diff`（13 断言），逐位比 regs/mem/pc/状态位
- 解释器 ↔ oracle ↔ lowering：`ctest lower_full`（19 断言），四个程序 × 两种初值
- 解释器/oracle ↔ 原生可执行文件：`ctest vmp_gate`

gate 输出（`scripts/verify_vmp_gate.sh`，退出 0）：
```
ok sum/zero        r0=0
ok sum/small       r0=6        循环 + 条件分支 + 累加
ok crc/zero        fault       地址越界，与解释器同一处
ok copy_xor/zero   fault
ok allops/fault    fault
ok refuse          unknown opcode 被拒绝，编译失败
```

## 二、这层证明了什么

1. **语义等价**：四个程序在"解释执行"和"编译成原生"两条路径上结局完全相同，
   包括故障停机点（越界/未对齐）与 ISA 外 opcode 的拒绝。
2. **fault 没有丢**：lowering 与 pass 都保留了解释器的越界/未对齐判定，
   没有退化成 UB——这是最容易假绿的地方。
3. **不支持的指令会红**：pass 遇到解释器没有的 opcode 直接 `report_fatal_error`，
   不近似、不静默。
4. **每一项都有可执行判据**：25 个 ctest + 1 个 gate 脚本，没有"人工确认"。

## 三、这层没有证明什么（同样重要）

1. **不构成安全主张。** 与 V1.3 文档 §10.1 一致：`R_plain ≤ 3` 未达成（最小 5.62，
   融合内核实测 6.65），§10.1 第 1 条已触发，C1/C2 路线终止。本报告只证明功能等价。
2. **没有性能数字。** 原因有两个，都不是"忘了测"：
   - 初始寄存器值是编译期常量，`-O1` 会把整段程序折叠掉，测出来的时间是"什么都不做"的时间；
   - `hsvm_entry` 目前是无参 `i32 ()`，没有运行时输入，无法构造"不可折叠"的负载。
   要做性能，需先把契约改成 `i32 (i32)` 并用 `volatile`/`argc` 喂入，再按 §5.5 的
   既有口径（4.2–4.34 ns 基线、cap 3.0）测——不能换尺子。
3. **只跑过 arm64 macOS**；`crc`/`copy_xor` 只覆盖故障路径，没有覆盖"正常跑完"。
4. **pass 侧没有步数预算**；`budget` 只是 oracle 侧的截断，不是语义的一部分。

## 四、复现

```bash
# research 层
cd research/hsvm && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j10
ctest --test-dir build --output-on-failure

# Polaris pass（改动 src/llvm 后必须重编）
cd src/build && ninja LLVMObfuscation && ninja clang
./research/hsvm/scripts/verify_vmp_gate.sh
```

## 五、后续若要继续（按性价比排序）

1. 契约改成 `i32 (i32)`，喂入运行时输入 → 才能测性能，也才让这个 pass 对真实 C 程序有用。
2. 覆盖 `crc`/`copy_xor` 的正常完成路径（目前两者都在故障处结束）。
3. 把 gate 扩成"随机程序生成 + 三方比对"，用性质测试替代固定用例。
