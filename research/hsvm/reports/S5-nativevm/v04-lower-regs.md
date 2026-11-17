# V-04 寄存器类 lowering + 三方差分

`include/hsvm/lower.h`、`src/lower.cpp`、`tests/test_lower_regs.cpp`，ctest `lower_regs`，
14 条断言全绿；ctest 共 22 个测试。

## IR 形态

```
IrKind: Const | Copy | Add | Sub | Xor | And | Or | Mul | Shl | Shr
IrOp  : { kind, dst, a, b, imm }
```

一条字节码指令降成 0 或 1 条 `IrOp`。`Nop` 降成 0 条（返回 true），
`Ld`/`St`/`Jmp`/`Brz`/`Halt` 一律**拒绝**（返回 false，不追加任何操作）——
近似实现会比"没实现"更危险，因为它看起来是绿的。

## 三方比对

`Machine(Plain)` ↔ `semStep` ↔ `lowerOp + irExec`，逐步锁步，比全部寄存器与 pc。
测试程序用 16 条寄存器类指令覆盖 11 个 opcode，包含两个易错点：
`Xor r15, r14, r15`（同寄存器读写）与 `Shl r13, r1, r12`（r12=33）。

| 初值 | 步数 | 结果 |
|---|---|---|
| 0x12345678 | 16 | 三方一致 |
| 0 | 16 | 三方一致 |
| 0xFFFFFFFF | 16 | 三方一致 |

## 变异检验：这组断言不是空转

把 lowering 里的 `Shl` 改成 `Shr`（等价于弄错指令语义），测试立刻失败并定位：

```
[DIVERGE] step 9 pc=8 reg r9: interp=4026531840 oracle=4026531840 lower=9
```

说明三方比对能抓到"lowering 语义错"，并且能报到 step / pc / 寄存器号。
恢复后重新全绿。

## 一个诚实的负面发现

把位移掩码从 `& 31` 改成 `& 63`，测试**仍然全绿**。原因：ARM64 与 x86 的移位指令
本身对位移量取模 32，编译器把 `x << 57` 编成 `x << 25`，所以掩码在位级上不可观测。

结论：`& 31` 是**防御性写法**（避免 UB），不是可测行为。`test_semantics` 里那条
"`Shl 1,33 == 2`"断言验证的是我们自己的算术实现，不是可观测差异。这一点写在这里，
免得以后有人以为那条断言证明了什么。

## 覆盖边界

- 已证明：寄存器类 11 个 opcode 的三方语义一致（含同寄存器读写、位移边界）。
- 未证明：访存与分支（`Ld`/`St`/`Jmp`/`Brz`/`Halt` 被明确拒绝）、真实程序（`sum`/`crc`/`copy_xor`
  含分支，跑不到这里）、以及 LLVM IR 发射（V-07）。
