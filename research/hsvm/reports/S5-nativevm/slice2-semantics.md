# 阶段 5 切片 2 前置：16 opcode 语义规格（从 Machine::step 逐条核对）

切片 1（`mir.h/mir.cpp`）只保证字节码能被无损读出。切片 2 要做 lowering，前提是每个
opcode 的语义有精确、可追溯的定义。本文件就是那个定义，全部条目对应 `src/machine.cpp`
的 `switch (op)` 分支（行号为提交 `62e8361e6` 时的位置）。

## 一、寄存器与状态

- 64 个 32 位寄存器，`regs_[r]` 位于状态位 `[32r, 32r+32)`。
- `regOk(r)`：`r < 64`，否则 `fault(...)` 并停机。
- 内存 `mem_` 为字节数组；`memOk(addr)`：`addr + 4 <= size` 且 4 字节对齐，否则 fault。
- 内存不在状态 `s` 内（PC 也不在），这是 C1 的前提，lowering 必须保持。

## 二、逐条语义

| opcode | 语义 | 边界 |
|---|---|---|
| Nop | 无效果 | — |
| Movi | regs[dst] = imm | 不做 regOk 检查 |
| Mov | regs[dst] = regs[a] | a 越界则 fault |
| Add | regs[dst] = a + b（32 位回绕） | 两操作数都要 regOk |
| Sub | regs[dst] = a - b（32 位回绕） | 同上 |
| Xor | a ^ b | 同上 |
| And | a & b | 同上 |
| Or | a \| b | 同上 |
| Mul | a * b（回绕） | 同上 |
| Shl | a << (b & 31) | 位移量掩码到 31，不是 UB |
| Shr | a >> (b & 31)（逻辑右移） | 同上 |
| Ld | regs[dst] = mem32[regs[a] + imm]（小端） | 地址需 memOk |
| St | mem32[regs[a] + imm] = regs[b]（小端，4 字节） | 地址需 memOk |
| Jmp | pc += simm(imm)（有符号 32 位） | — |
| Brz | if (regs[a] == 0) pc += simm(imm) else pc += 1 | a 越界则 fault |
| Halt | 停机 | — |

`simm(imm)` = `static_cast<int32_t>(imm)`；Jmp 目标是 `int64(pc) + simm`，
因此向回跳转无需额外编码。

## 三、fault 语义（lowering 必须保留）

越界寄存器、越界或未对齐地址都会 `fault(...)` 并停机，而不是"跳过"或"截断"。
切片 2 的 lowering 若把 fault 变成 UB 或静默忽略，就改变了程序可观测行为，
`test_machine` 的既有断言会失效——这是验收条件之一。

## 四、切片 2 的验收判据（尚未实现）

1. 对 16 条 opcode，lowering 后的 IR 在相同初始状态下产生与 `Machine::step` 相同的
   寄存器/内存差异（差分测试，逐条 + `allops` 全程序）。
2. fault 情形必须在 lowering 后同样停机，且停机位置一致。
3. 内存小端、位移掩码、32 位回绕三个边界各至少一条断言。

目前只完成了判据的定义，lowering 本身未实现。
