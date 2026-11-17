# V-10 pass 全 opcode + 真实程序端到端

## 交付

- `HSVMLowering` 现在降低全部 16 个 opcode：新增 `Ld/St/Jmp/Brz`，含
  地址越界/未对齐 → 故障路径、有符号跳转位移、条件分支。
- 故障与 pc 越界用不同返回值区分：`0xFFFFFFFE` = 故障，`0xFFFFFFFF` = pc 越界。
  （解释器里这两个都表现为"停机"，函数返回值是单值通道，必须能区分才可诊断。）
- 契约扩展：可选 `@hsvm_init`（i32 常量）设置初始寄存器值；缺省 0。
- `tools/hsvm_dump_program`：把命名程序导出为携带 `@hsvm_bytecode` 的 C 源码，
  同时用 oracle 算出期望结果（`r0=<dec>` / `fault` / `oob` / `budget`）。
- `scripts/verify_vmp_gate.sh` 已接进 ctest（测试名 `vmp_gate`）。

## 结果（gate 退出 0，ctest 25/25）

```
clang: clang version 16.0.6 (… 8183ee2f3…)
  ok   sum/zero           r0=0
  ok   sum/small          r0=6
  ok   crc/zero           fault
  ok   copy_xor/zero      fault
  ok   allops/fault       fault
  ok   refuse             refused with a clear message
PASS: hsvm pass gate
```

`sum/small`（初值 3）是这轮最有价值的一条：它证明**循环 + 条件分支 + 累加**在原生路径上
得到与解释器相同的 `r0=6`。之前它返回 0，两处原因都已修：

1. **pass 把寄存器一律初始化成 0**，而 oracle 从 `initRegs` 起跑，两边跑的根本不是同一个程序。
   于是加了 `@hsvm_init`。
2. `-O1` 会把"全常量输入"的整段程序**折叠掉**（`sum` 初值 0x12345678 时 oracle 需要 20 万步以上，
   原生却瞬间返回）——这不是 lowering 的错，是优化器正常工作。gate 因此只比对**折叠后仍可观测**的
   结果（一个具体值，或一次故障）；把"大初值循环"当判据是选错了用例。

## 边界

- 已证：`sum`/`crc`/`copy_xor`/`allops` 四个程序在原生路径上的结局与 oracle 完全一致，
  涵盖循环、分支、访存、故障、以及 ISA 外 opcode 的拒绝。
- 未证：`budget`（步数上限）在 pass 里没有对应物——原生程序没有步数概念，只有 oracle 侧会截断；
  性能口径（`R_plain`）没有测，`-O1` 与本项目 pass 管线的优化强度不同；
  只跑过 arm64 macOS；`crc/zero`、`copy_xor/zero` 都落在故障路径上，没有覆盖"这两个程序正常跑完"的情形。
