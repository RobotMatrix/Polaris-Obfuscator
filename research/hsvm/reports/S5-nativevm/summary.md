# 阶段 5（VMP）收口报告

范围：`research/hsvm` 的 V-01…V-14 与 `src/llvm` 的 `-passes=hsvm`。
本节回答一个问题：**字节码经 Polaris 编译器产出的原生代码，与解释器是否语义一致**，
以及这件事**证明了什么、没证明什么**。

## 一、链路与证据

```
字节码 (8 字节/指令)
  └ lift        → MirOp         ctest mir          103 断言   无损解码
  └ lowerOp     → IrOp          ctest lower_regs    15 断言   寄存器类 + 变异检验
                                ctest lower_full    19 断言   全 16 opcode 三方比对
  └ emitC       → C 源码        ctest emit_c        18 断言   clang -O1，退出码 0/3/5
  └ HSVMLowering→ LLVM IR       ctest vmp_gate       6 用例   真实程序端到端
                                ctest vmp_fuzz       随机程序过真编译器
```

四方一致性：
- 解释器 `Machine(Plain)` ↔ oracle `semStep`：`ctest diff`（13 断言），逐位比 regs/mem/pc/状态位
- 解释器 ↔ oracle ↔ lowering：`ctest lower_full`（19 断言）、`ctest fuzz_threeway`（随机程序）
- 解释器/oracle ↔ 原生可执行文件：`ctest vmp_gate`、`ctest vmp_fuzz`
- 同一负载两条执行路径的结果必须相等：`ctest bench_match`

gate 输出（`scripts/verify_vmp_gate.sh`，退出 0）：
```
ok sum/zero        r0=0
ok sum/small       r0=6        循环 + 条件分支 + 累加
ok crc/zero        fault       地址越界，与解释器同一处
ok copy_xor/zero   fault
ok allops/fault    fault
ok refuse          unknown opcode 被拒绝，编译失败
```

性质测试（`tools/hsvm_fuzz.cpp` + `scripts/verify_vmp_fuzz.sh`）：
```
seed 20260117 与 1/2/3/424242 各 200 个随机程序 → diverged=0（约 24 万步，130 次故障）
30 个随机程序过 -passes=hsvm：24 编译并匹配、6 个因 budget 跳过
```

## 二、这层证明了什么

1. **语义等价**：固定的四个程序和上千个随机程序，在"解释执行"和"编译成原生"两条路径上结局相同，
   包括故障停机点（越界/未对齐）与 ISA 外 opcode 的拒绝。
2. **fault 没有丢**：lowering 与 pass 都保留了解释器的越界/未对齐判定，
   没有退化成 UB——这是最容易假绿的地方。
3. **运行时故障不会被挪到编译期**：越界寄存器现在是到 fault 块的分支，而不是 `report_fatal_error`
   （这条是 `vmp_fuzz` 抓出来的，原实现会让"能跑的程序"变成"编不过"）。
4. **每一项都有可执行判据**：28 个 ctest，没有"人工确认"。

## 三、这层没有证明什么（同样重要）

1. **不构成安全主张。** 与 V1.3 文档 §10.1 一致：`R_plain ≤ 3` 未达成（最小 5.62，
   融合内核实测 6.65），§10.1 第 1 条已触发，C1/C2 路线终止。本报告只证明功能等价。
2. **测出的 1654.84× 不是 `R_plain`。**
   ```
   1M 次循环: 解释器 9.069996 s   原生 0.005481 s   两侧结果 1784293664 相同
   ```
   分母是研究层 `Machine`（每步维护 `BitVector` 状态，C1 模型需要），不是生产级 switch 解释器；
   生产解释器通常只慢 10–50×。**尺子没换**：§5.5 的 4.2–4.34 ns 基线、cap 3.0 仍然有效，
   这个数字不能当"保护代价"引用。详见 `reports/S5-nativevm/v12-bench.md`。
3. **只跑过 arm64 macOS**；`crc`/`copy_xor` 仍只覆盖故障路径，没有覆盖"正常跑完"。
4. **pass 侧没有步数预算**；`budget` 只是 oracle 侧的截断，不是语义的一部分，
   所以 `vmp_fuzz` 会跳过这类程序（原生形态没有步数概念，会一直跑）。
5. **随机测试没有覆盖**：未对齐以外的地址模式、超长程序、跨函数调用。

## 四、复现

```bash
# research 层
cd research/hsvm && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j10
ctest --test-dir build --output-on-failure

# Polaris pass（改动 src/llvm 后必须重编）
cd src/build && ninja LLVMObfuscation && ninja clang
cd - && ./research/hsvm/scripts/verify_vmp_gate.sh
./research/hsvm/scripts/verify_vmp_fuzz.sh 30 777
```

## 五、后续若要继续（按性价比排序）

1. 覆盖 `crc`/`copy_xor` 的正常完成路径（目前两者都在故障处结束）——需要给程序准备合法初值。
2. 把随机测试扩到更长程序与跨函数调用；`vmp_fuzz` 每个程序一次 clang，规模只能到几十个。
3. 跨平台：Linux/Windows 上重跑 `vmp_gate` 与 `vmp_fuzz`。这一步需要另一台机器，本机给不出证据。
4. 若要谈性能，先按 §5.5 口径重新设计实验（固定基线微基准、30 次取中位数），
   而不是拿研究层解释器当分母。
