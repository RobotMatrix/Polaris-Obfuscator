# V-05 访存/分支/停机 lowering + 真实程序三方比对

`src/lower.cpp` 扩展到全部 16 个 opcode，新增 `Load/Store/Jmp/Brz/Stop`。
`tests/test_lower_full.cpp`（ctest `lower_full`，19 条断言）在 `sum`/`crc`/`copy_xor`/`allops`
上做三方锁步比对：`Machine(Plain)` ↔ `semStep` ↔ `lowerOp+irExec`，每步比**全部寄存器 +
全部 4 KiB 内存（按字）+ pc + 两个状态位**。

## 结果

| 程序 | 初值 | 步数 | 三方一致 | 停机 |
|---|---|---|---|---|
| sum | 0x12345678 | 8192（截断） | 是 | 否（循环计数从寄存器读出，太大） |
| sum | 0 | 6 | 是 | **是** |
| crc | 0x12345678 / 0 | 8192（截断） | 是 | 否 |
| copy_xor | 0x12345678 / 0 | 4617 / 8192 | 是 | 否（4617 步时故障，三方一致） |
| allops | 0x12345678 / 0 | 12 | 是 | 否（地址越界故障，三方一致） |

`sum` 从零寄存器起跑 6 步就命中停机指令——这是唯一能断言"跑到停机"的组合；其余程序在
"寄存器全填大值"时循环计数也被填大，任何合理预算内都不会停。**这一点写清楚，不用
"8192 步一致"冒充"程序正确终止"**。

## 两个被测试抓出来的问题

**1. ISA 之外的 opcode 被静默降级成 `Copy`。**
`lowerOp` 原来只有 16 个 `case` 加 `default: return false`（V-04 版本）；V-05 重写时漏掉
`default`，于是 `static_cast<Opcode>(0x10)` 会走到函数末尾 `push_back(o)`，`o.kind` 是
默认值 `Copy`——**损坏的字节码会被"成功"降级成一条复制**。
`test_lower_regs` 的"ISA 外的 opcode 必须被拒绝"断言当场红了，补 `default: return false` 后转绿。

**2. 上一提交里混进了变异实验的代码。**
`ff18f7275` 里的位移掩码是 `& 63u`，不是文档写的 `& 31u`——做变异检验时我把 `&63` 版本
备份到 `/tmp/lower_mut.cpp`，回滚时把**含变异的备份**恢复了回去。本轮已改正为 `& 31u`。
教训：变异检验的回滚必须以 `git diff` 为准，不能信自己复制的临时文件。

## 覆盖边界

- 已证：16 个 opcode 的 lowering 与解释器、oracle 三方一致，含故障路径、分支、停机。
- 未证：LLVM IR 发射（V-07）、Linux/非 ARM64 平台、以及"只比输出不比轨迹"之外的性能口径。
