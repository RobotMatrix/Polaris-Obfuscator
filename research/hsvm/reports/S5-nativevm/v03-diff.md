# V-03 差分框架：解释器 ↔ 语义 oracle

`tests/test_diff.cpp`，ctest `diff`，13 条断言全绿。

## 做法

两个引擎逐步锁步执行同一段字节码，每步比较 `regs[0..regCount)`、`mem`（4 KiB 逐字）、
`pc`、`halted`/`faulted`。任一字段不同就打印 **第一个分歧的 step、pc、指令反汇编、字段名**
和双方的值——这是后面接 lowering 时唯一有用的调试信息。

- 解释器：`Machine`（`VmMode::Plain`，真正执行指令语义）
- oracle：`semantics.h` 的 `semStep`（纯函数，不 include `machine.h`）

## 三个实测发现（都被框架自己抓出来）

1. **寄存器数是 16，不是 64。** `Machine::kMaxRegs = 16`，`regCount_ = p.n / 32`（上限 16）。
   我上一版 `semantics.h` 写死 64、把"寄存器 63 合法"写成断言，是错的。
   现在 `SemState::regCount` 是从机器读进来的参数，断言改成 15 合法 / 16 故障。
   —— 这正是 oracle 不该依赖解释器、但必须由解释器校准的原因。

2. **`Machine::step()` 在 fault 路径返回 true**（`fault(...)` 只置标志并停机）。
   比较返回值等于比较约定，不是比较行为。框架改为比较 `faulted`/`halted` 状态位。

3. **`allops` 在 Plain 模式下第 12 步就 fault**（`ld r11, [r12+0xb0b0b0b]` 地址越界）。
   `programs.h` 的注释写了它"只在 linear 模式有意义"，现在有实测证据。
   因此真实覆盖来自 `sum`/`crc`/`copy_xor` 三个程序，allops 只用来验证"双方在同一处停机"。

## 覆盖

| 程序 | 初值 | 结果 |
|---|---|---|
| sum | 0x12345678 / 0 | 一致 |
| crc | 0x12345678 / 0 | 4096 步一致 |
| copy_xor | 0x12345678 / 0 | 4096 步一致 |
| allops | 0x12345678 / 0 / 0xFFFFFFFF | 一致（含同一处 fault） |

## 这层证明了什么，没证明什么

证明：`semStep` 与解释器在三个真实程序 + 全指令程序上逐位一致（含 fault 停机点）。
没证明：lowering 的正确性——lowering 还不存在（V-04 起）。
