# V-08/V-09 Polaris pass 接入 + 工具链重建

## V-09：clang 已重建，版本对齐 HEAD

```
之前: clang version 16.0.6 (… 832aca2140058b56…)
现在: clang version 16.0.6 (… 8e3dd97956f226d4…)
```
`ninja LLVMObfuscation` → `ninja clang`，增量重建耗时分钟级。
`git log 832aca214..HEAD -- src/llvm` 当时是 **2 个提交**，说明旧二进制确实落后，
不是"只改了 research 所以不用重编"——这一点之前我判断错过一次。

## V-08：`-passes=hsvm` 的 lowering pass

契约（写进 pass 头注释）：
- `@hsvm_bytecode`（C 里写 `hsvm_bytecode`）：常量 `[N x i8]`，每条指令 8 字节
- `@hsvm_entry`：声明为 `i32 ()`，pass 把它的函数体重写为降低后的程序，返回最终 `r0`

本切片降低：`Nop`、`Movi`、`Mov`、`Add`、`Sub`、`Xor`、`And`、`Or`、`Mul`、`Shl`、`Shr`、`Halt`。
`Ld/St/Jmp/Brz` **拒绝**，报 `hsvm: opcode not lowered yet: <Name>` 并中止编译——
宁可编译失败，也不产出"看起来成功"的错代码。

opcode 编号来自 `HSVMOpcodes.def`（ISA 单一真源），pass 里用宏展开，不另抄一份。

## 验证（`scripts/verify_vmp_pass.sh`，退出码 0）

```
clang: clang version 16.0.6 (… 8e3dd97956f226d4…)
  ok: ok returned 49 as expected
  ok: refused refused with a clear message
PASS: hsvm pass gate
```
- `ok`：字节码 `movi r0,42; movi r1,7; add r0,r0,r1; halt` → 原生可执行文件返回 **49**，
  与解释器/ oracle 的 `r0=49` 一致。
- `refused`：字节码含 `ld` → 编译被拒绝，错误信息含 `not lowered yet`。

## 接通过程中撞到的三件事（都记进 ADR-028）

1. **pass 名字要在两个地方登记**：`addObfuscationPass()` 的 if-链，以及
   `buildObfuscationPipeline()` 里的 `Order[]` 白名单。只改前者 → `unknown obfuscation pass 'hsvm'`。
2. **C 侧全局名是下划线**：`hsvm_bytecode`，我最初只查 `hsvm.bytecode`，pass 静默不生效，
   表现为链接期 `undefined _hsvm_entry`。现在两个名字都接受。
3. `report_fatal_error(std::string)` 在该 LLVM 版本上重载歧义，要用 `Twine`。

## 边界

- 已证：单个寄存器类程序的端到端（字节码 → pass → 原生 → 退出码）正确；不支持的 opcode 被拒绝。
- 未证：访存/分支 lowering（`Ld/St/Jmp/Brz` 仍是拒绝）、真实程序端到端（`sum`/`crc`/`copy_xor`
  都含分支）、性能口径、跨平台。
- 本 pass 没有和 `research/hsvm` 的 oracle 做自动差分：目前只有这一个 gate 脚本，V-10 才把它接进 ctest。
