# 性质测试：随机字节码三方比对

`tools/hsvm_fuzz.cpp`，ctest `fuzz_threeway`（200 个随机程序，固定种子）。

## 做法

随机生成 4–31 条指令的字节码，寄存器索引**大多在 [0,16)**，每 16 个里有一个故意越界（16–23）
以触发故障路径；跳转位移限制在 ±4 以内以形成可终止的循环；`Ld/St` 的立即数限制在
4096 字节地址空间内；初始寄存器值随机。

同一段字节码同时喂给三个引擎，逐步比对：
- `Machine(Plain)`（解释器）
- `semStep`（oracle）
- `lowerOp + irExec`（lowering）

每步比全部 16 个寄存器、`pc`、两个状态位；内存只在结束时和故障时整块比（每步比 4 KiB 只会
拖慢而不增信号）。

## 结果

```
seed=20260117 programs=200 steps=48530 halted=43 faulted=130 diverged=0
PASS: three engines agree on 200 random programs
```
另跑 4 个种子（1 / 2 / 3 / 424242）各 200 个程序，全部 `diverged=0`；
合计 **1000 个随机程序、约 24 万步**无分歧。

## 它抓到的真 bug：`Movi` 缺边界检查

第一次跑（程序 #30，第 2 步，`op=0x01`）就红了：

```
[DIVERGE] prog=30 step=2 pc=4 op=01 pc(sem=5 low=4 vm=4) halted(0 0 0) faulted(0 1 1)
```

`Movi` 在解释器里是唯一**没有** `regOk` 检查的 opcode：

```cpp
case Opcode::Movi:
  regs_[in.dst] = in.imm;   // dst 可达 255，越界写
```

其它 15 条 opcode 都有检查，唯独它漏了。后果不是"结果不对"，而是**损坏的字节码直接越界写内存**
（`regs_` 是 `std::vector<uint32_t>`，写 200 号元素是未定义行为）。

修法：解释器、oracle、lowering 三处都加同一个检查，断言写进 `test_semantics`
（38 → 42 条断言）。修完五个种子全绿。

**这类问题只有性质测试抓得到**：固定用例里没人会写 `movi r16, x`，
而它恰恰是"攻击者能控制的输入"——字节码本身就是攻击面。

## 边界

- 已证：1000 个随机程序（含故障、停机、循环）上三方一致。
- 未证：随机生成器覆盖不到 `Ld/St` 的 UNALIGNED 分支（立即数都是 64 的倍数），
  也没有把 pass（真编译器）纳入随机测试——每次都要调 clang，太慢。
- 未证：`diverged=0` 不等于"语义完全正确"，只是"没抓到反例"。
