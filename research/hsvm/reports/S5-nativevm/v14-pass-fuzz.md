# 随机程序过真编译器（pass 级性质测试）

`scripts/verify_vmp_fuzz.sh`，ctest `vmp_fuzz`（默认 15 个程序，可传 count/seed）。

## 做法

1. `hsvm_fuzz --emit-dir`：生成随机字节码，跑三方性质测试（解释器/oracle/lowering），
   同时写出 `prog_N.c`（含 `hsvm_bytecode`）和 `prog_N.expect`（oracle 的结局）。
2. 脚本对每个程序调用 **Polaris clang** `-O1 -mllvm -passes=hsvm` 编译，运行，比对输出。
3. oracle 跑到步数上限的程序（`budget`）跳过：原生形态没有步数概念，会一直跑下去。

生成器同时补上了之前缺的一路：`Ld/St` 的地址每 8 个里有 1 个**故意不对齐**，
用来覆盖未对齐故障分支——三方测试仍 `diverged=0`。

## 它抓到的两个问题

**1. pass 把"寄存器越界"当成编译期错误，解释器却在运行时才故障。**

```
FAIL prog_0: compile failed: hsvm: register index out of range
```
解释器语义是"执行到这条指令才故障"：同样的字节码，如果越界指令永远没被执行到，程序应当正常跑完。
pass 里 `report_fatal_error` 直接中止编译，等于**改变了程序行为**——本来能跑的程序变成编不过。
已改为：越界时发射一条到 fault 块的无条件分支（`br hsvm.fault`），与访存越界同一套处理。

**2. 生成的 C 用 `hsvm_entry(0)`，而 oracle 用的是随机初始寄存器。**

修好上一条后出现 `want=r0=1797755835 got=r0=0`——两边输入不同，比的不是同一个程序。
现在按 oracle 的 `initRegs` 生成实参。这和之前在 gate 里踩过的 `@hsvm_init` 是同一类错误：
**比较两个引擎时，输入必须逐字一致**，否则测的是两段不同的工作。

## 结果

```
clang: … f78bcd293…
ok   property: PASS: three engines agree on 30 random programs
compiled=24 skipped(budget)=6
PASS: pass fuzz gate
```
ctest 28 个测试全绿（`vmp_fuzz` 单次 0.74 s）。

## 边界

- 每个程序一次 clang 调用，所以随机规模只能到几十个；这不是性能测试。
- 跳过 `budget` 类程序：原生形态没有步数预算，这个差异是已知且刻意保留的。
- 只覆盖 arm64 macOS；随机程序长度 4–31 条指令，没有覆盖超长程序或跨函数调用。
