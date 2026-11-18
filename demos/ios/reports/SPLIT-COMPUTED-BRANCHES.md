# S2 落地：跨块边沿改成表驱动的计算分支（computed-branches）

> **后续：S2b 已把这张表加密**（`-mllvm -computed-branches-encoded`，默认关）。
> 本文 §6 记录的"表 + key 都在产物里、20 行脚本 42/42"这一条已经不再成立：
> 表项改成逐条掩码（`delta + K ^ c_i`），key 折在另一个段的 ring 里，本文的解码器
> 在 demo6 上解回 **0/46**，wbaes 3,016 → 0。代价是相对本文 +2.8% 的每调用耗时、
> wbaes 上 +8.9% 的边没转（寄存器不够）；**≤5% 的门槛仍然没达到**，判决见
> `reports/COMPUTED-BRANCHES-ENCODED.md`。下文保留 S2 当时的原始数字，作为对照。

> 状态：**已实现并入树**。机制在 `AArch64RubbishCode`（MIR, pre-emit 最后一站），
> 开关 `-mllvm -computed-branches`，**默认关**；不做任何链接后修补。
> 所有数字来自本机实跑（macOS 27.3 / arm64，本仓 clang 16.0.6），复现命令见 §12。
> 本机没有 IDA/Ghidra：本文的"不可发现"= **线性/递归反汇编无法从指令流里取到后继**，
> 是静态计数，**不是反编译器判决**，也不是"分析者恢复不出来"。

## 0. 结论先行

拆分原本留下两类可跟的边沿：`randomMoveBasicBlock` 的直接 `b`，以及 `splitBasicBlock`
自己发的 `adrp+add+br`（间接，但目标地址就写在紧邻的两条指令里）。S2 把两者都换成
**从 `__TEXT,__const` 的表里取一个 32 位相对偏移、减掉每构建 key、与表基相加、再 `br`**：

| demo6（-O1） | S1 基线 `D_sym` | S2 `D_symcb`（默认档） | S2 全边档 `D_symcball` |
|---|---|---|---|
| `adrp+add+br`（目标写在指令里） | **30** | **0** | **0** |
| 表驱动 `br` | 0 | **42** | **63** |
| 真实跨块直接边（`b`/`b.cond`/`cbz`…） | **7** | **0** | **0** |
| 同块直接边（不跨拆分） | 21 | 21 | 0 |
| 目标表可解回的边 | – | **42/42** | 63/63 |

- **正确性**：6 个 demo6 变体 stdout sha256 全部 `a3a6f0fc7d549bcc…`，9 行表逐字节相同；
  `-Wl,-dead_strip`、`strip`、`strip`+`macho_scrub` 后仍相同。
- **不透明度**：42 条边（wbaes 2,515 条）的后继从指令流里消失；demo6 上**没有**遗留的真实跨块直接边，
  wbaes 上真实跨块直接边 900 → 41（95.4% 关掉）。
- **代价：5% 的门槛没有达到**——demo6 上 **+62.8%**（140.9 → 229.3 ns/次，3 轮 × 40 进程中位数）。
  这是本文最重要的一条失败，见 §8/§9。
- **表是可读的**：表和 key 都在产物里，一段 20 行的脚本把 42/42 条边全解回来（§7）。
  所以 S2 加的是"反汇编器跟不动"，不是"分析者拿不到"。判决在 §11。

## 1. 机制

### 1.1 选边

一条边被选中当且仅当它**跨 chunk**：`ChunkId[src] != ChunkId[dst]`，其中 `ChunkId` 是
按布局顺序给每个 MBB 打的"所属 chunk 头"编号（`-1` = 拆分前的头段，其余 = 该 chunk 头的序号）。
这与 S1 的 chunk 符号区间是同一个划分（实测两边算出的 6 条跨块边完全一致，§5.2）。

拒绝规则（每条都写进 sidecar，带原因）：

| 条件 | 原因 | demo6 | wbaes |
|---|---|---|---|
| 目标不是入口块 | `entry-block` | 0 | 0 |
| 目标块以拆分的 SP 弹栈开头 | `sp-reload-target` | 0 | 0 |
| 块内终结符不止一条，或终结符不是最后一条 | `term-chain` | 10 块 | 283 块 |
| 一个块里正好 2 条终结符之外的形态、或不是跨块 | `not-cross-chunk` | 21 条 | 9 条 |
| 找不到 ≥2（条件边 ≥3）个死寄存器 | `regs` / `regs-cond` | 0 | **189** |

`ARMRC_CB_ALL=1` 把选边从"跨块"放宽到"该函数里所有直接分支"，只用于测量两档的差别。

### 1.2 发出的指令

无条件边（每条 +3 条指令，相对拆分原来的 `stp/adrp/add/br` + 目标处 `ldp`）：

```
  stp  x16, x17, [sp, #-16]!      ; 只有拆分自己的边用这对（x16/x17 是 IP 寄存器，
  adrp xB, <table>@PAGE           ;  块里可能活着，所以照 S1 的做法溢出）。
  add  xB, xB, <table>@PAGEOFF    ; 指向本函数表的第 0 项
  ldrsw xT, [xB, #idx]            ; 表项 = (target - table) + key，下标就是表内序号
  sub  xT, xT, #key               ; 每构建 12 位 key
  add  xB, xT, xB                 ; target = table + 偏移
  br   xB
```

条件边（每条 +9 条指令）——两条臂都变成数据，`csel` 选一个，一条 `br`：

```
  adrp xB, <table>@PAGE ; add xB, xB, <table>@PAGEOFF
  ldrsw xT, [xB, #idx_taken] ; ldrsw xA, [xB, #idx_fall]
  sub  xT, xT, #key          ; sub  xA, xA, #key
  subs wzr, wReg, #0         ; cbz/cbnz 的条件；tbz/tbnz 用 ands wzr, wReg, #bit；
  csel xT, xT, xA, eq        ; b.cc 直接用原来的 NZCV，不需要这行
  add  xB, xT, xB ; br xB
```

- 寄存器：拆分自己的边固定用 X16/X17（成对溢出/成对弹回，目标块开头一条 `ldp` 顶替原来的 `ldr`）。
  其余边从 **X0–X7、X9–X15** 里挑**在所有后继上都死**的寄存器（`LivePhysRegs` + `addLiveOutsNoPristines`
  取后继 live-in 的并集），拿不到就**不转换**并记账（wbaes 上 189 条，见 §9）。
- 入口块永远是普通入口：任何指向它的边都不转换，prologue 的地址没有第二种到达方式。
- 终点（`b F` 的 F 臂）按**布局顺序的下一块**取，而不是 `MBB.successors()`：拆分会手工搬块、
  手工改 successor 表，记录下来的 CFG 和汇编器实际排出的顺序已经不一致（demo6 里就有一个
  4 个 successor 的 `Bcc` 块）。

### 1.3 目标表

每个函数一张表，放在 `__TEXT,__const`，由一条 inline asm 发出（`.section` 切换后再切回，
`__text` 里不落任何字节）：

```
    .section __TEXT,__const
    .p2align 2
L__pcb<seeded>:
    .long <chunk symbol> - L__pcb<seeded> + <key>
    ...
    .section __TEXT,__text,regular,pure_instructions
```

- 表项是**表相对**的偏移（不是地址）：同段内两个符号相减，ld64 在链接时算成常数，
  **不需要 rebase、不需要 dyld 修正**，PIE 下滑动无影响（实测 `dyld_info -fixups` 里
  `__const` 没有任何 rebase/bind 条目）。
- 标签以小写 `L` 开头 ⇒ 汇编器临时符号，**不进 nlist**（demo6 nlist 仍是 6 条，wbaes 仍是 1,621 条）。
- 不加 `.no_dead_strip` 也活着：`__text` 里的 `adrp/add` 引用了它，`-dead_strip` 会把它当活原子（实测 §4.3）。
- key 每构建一个（`splitmix64(obf-seed 或时钟种子)` 取 12 位），**不消耗** `nextObfRandom`，
  所以开不开这个 flag，垃圾码布局不变。12 位是为了让 `sub #key` 只占一条指令；代价见 §7。

### 1.4 开关与 sidecar

```
-mllvm -computed-branches                        # 总开关，默认 false
-mllvm -computed-branches-sidecar=<path>         # 追加 (fn, 边类型, 源块, 目标块, 表下标) 与拒绝原因
ARMRC_CB_ALL=1                                   # 只用于测量：把选边放宽到所有直接分支
```

> 改名后：`ARMRC_CB_ALL` → `-mllvm -computed-branches-all-edges`（语义不变；
> 下面的命令是改名前的记录）。

sidecar 片段（seed 12345）：

```
polaris-computed-branches	1
seed	3039
key	486
fn	_Z12shortestPathPA9_ji	conv	5	skipped	0	refused	16	entries	22	table	L__pcb7a872387e295
cb	_Z12shortestPathPA9_ji	b	17	18	0
cb	_Z12shortestPathPA9_ji	cond	19	20	1
refused	_Z12shortestPathPA9_ji	term-chain	13	-
```

## 2. 被测对象

```
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp
WB="demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c"
```

| 变体 | 源 | 编译 |
|---|---|---|
| `D_base` | demo6 | `-O1 -mllvm -obf-seed=12345`（拆分，两个新开关都关） |
| `D_sym` | demo6 | `+ -mllvm -split-symbols`（S1，作对照的 ground truth） |
| `D_cb` | demo6 | `+ -mllvm -computed-branches`（S2 默认档） |
| `D_symcb` | demo6 | `+ -mllvm -split-symbols -mllvm -computed-branches`（S1+S2，地址可比） |
| `D_cball` / `D_symcball` | demo6 | 同上 + `ARMRC_CB_ALL=1`（全边档） |
| `P_cb_B` | demo6 | `D_symcb` → `strip` → `macho_scrub --unwind neutralise`（profile B） |
| `B_base` / `B_cb` / `B_all` | `reports/demo6_bench.cpp` | 计时探针（同 shortestPath，printf 换成累加） |
| `W_base` / `W_sym` / `W_symcb` | wbaes | `-O2 -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345`，`ARMRC_NO_DATAFLOW=1`；**只做静态测量**（该 demo 在本树启动即 SIGTRAP，基线一样，S1 §9.3） |

测量脚本：`reports/s2_measure.py`（分支普查 + 表解码）、`reports/s2_bench.py`（每进程计时）。

## 3. 正确性

| 变体 | rc | 行数 | stdout sha256（前 16） |
|---|---|---|---|
| `D_base` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_sym` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_cb` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_symcb` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_cball` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_symcball` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `P_cb_B`（strip+scrub） | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_cb` + `-Wl,-dead_strip` | 0 | 9 | `a3a6f0fc7d549bcc` |

完整 sha256 = `a3a6f0fc7d549bcc9b2639e768b985ccd36f747d53895e5a9b2a2ffbc46a5846`，
与 S1 §7 / §4.1 记录的 demo6 基线一致（`ab_measure.py --run` 也报同一个值）。

计时探针三个变体的返回值校验和都是 `1600032`，即换算路径没有算错。

## 4. 不透明度（静态计数，不是反编译器判决）

### 4.1 demo6 分支普查

`otool -tv` + `s2_measure.py`。`br` = 间接跳转；`plain` = 紧邻 `adrp+add` 给出目标符号的
间接跳转（S1 之前/之后拆分用的形态）；`tbl` = 表驱动形态；`direct` = `b`/`b.cond`/`cbz`/`tbz` 等。

| 变体 | `__text` | `__const` | 指令数 | `br` | 其中 `tbl` | 其中 `plain` | `b` | `b.cond` | `cbz/tbz` | 落在 `__text` 内的直接边 |
|---|---|---|---|---|---|---|---|---|---|---|
| `D_base` | 3,356 | 324 | 605 | 32 | 0 | 30 | 18 | 13 | 14 | 34 |
| `D_sym`（S1） | 3,356 | 324 | 605 | 32 | 0 | **30** | 18 | 13 | 14 | 29 |
| **`D_symcb`（S2 默认）** | 3,896 | 508 | 761 | 44 | **42** | **0** | 11 | 9 | 17 | 23 |
| `D_symcball`（S2 全边） | 4,544 | 648 | 898 | 65 | **63** | **0** | 3 | 1 | 11 | 2 |

`plain` 的 30 条在 `D_sym` 里**全部**解到 chunk 头的地址（`plain_targets_into_chunk = 30`）——
这就是 S2 要关掉的那条捷径：目标地址就写在 `br` 前面的两条指令里。

### 4.2 跨块 vs 同块

用同一产物的 chunk 符号区间（`_k…`，S1 发的）给每条直接边两端找归属：

| 变体 | 直接边（落在 `__text`） | 其中 `.byte` 垃圾误码 | 真实边 | 同块 | 跨块 |
|---|---|---|---|---|---|
| `D_sym`（S1） | 29 | 1 | 28 | 21 | **7** |
| **`D_symcb`（S2 默认）** | 23 | 2 | 21 | 21 | **0** |
| `D_symcball`（S2 全边） | 2 | 2 | 0 | 0 | **0** |

21 条同块边在两个档位下**逐条相同**（7 `b` / 4 `b.eq` / 4 `b.ne` / 4 `cbnz` / 2 `cbz`），
这正是"只转跨块边"的预期：块内部的循环回边不动。

两条跨块"边"的现场（`prev` 是前一条指令）：

```
0x1000006cc  tbz   w17, #0x15, 0x100000810   prev=.long 0x7cf89ea6
0x1000011f0  tbnz  x3,  #0x2a, 0x100001050   prev=.long 0x4680284d
```

两条都是 `.byte` 填充区的随机解码（目标地址落在别的 chunk 里纯属巧合），**不是可执行的边**。
也就是说：demo6 默认档下**真实的跨块直接边是 0 条**，S1 基线的 7 条全部转成了表驱动。

### 4.3 后继"不可发现"的条数

| | demo6 | wbaes |
|---|---|---|
| 转换的边（表项驱动的 `br`） | **42** = 30（原 `adrp+add+br`）+ 12（原直接 `b`/`b.cond`，含 S1 剩下的 7 条跨块边） | **2,515** = 843 + 1,672 |
| 其中原本"读两条指令就知道目标" | 30 | 843 |
| 其中原本"读位移就知道目标" | 12 | 1,672 |
| 转换后仍能从指令流解出后继的 | **0** | **0** |
| 反汇编器还能跟到的真实跨块直接边 | **0**（S1 是 7） | **41**（S1 是 900，见 §9） |

`__text` 里的 `br` 从 32 涨到 44（demo6）/ 858 涨到 2,530（wbaes），`plain` 全部归零，
这就是"递归下降断在哪"的直接读数。

## 5. 还看得见什么（没有被隐藏的部分）

1. **同块直接边全部保留**：demo6 默认档 21 条（7 `b`、4 `b.eq`、4 `b.ne`、4 `cbnz`、2 `cbz`，
   与 S1 基线逐条相同）。它们的两端在同一个 chunk 里，不泄漏拆分边界，但确实让分析者在 chunk
   内部重建出原来的块结构。全边档把它们也干掉（剩 0 条），代价见 §8。
2. **布局 fallthrough 永远可见**：块 A 掉进 A+4 不需要指令，任何静态工具都看得见。
   这正是"跨块边"必须靠 S2、同块边可以不管的原因。
3. **`ret` 两条**（每个函数一条）与**函数入口**：prologue 仍是普通入口，指向它的边一律不转换。
4. **跳转表 `br`**：`switch` 的 `br xN`（demo6 里那 4 个 successor 的块）本来就不带目标地址，
   S2 不动它——它已经不可跟，但它的表在 `__const` 里是绝对值数组（`-mllvm -aarch64-jump-table` 相关，另一码事）。
5. **`.byte` 垃圾永远产生假分支**：demo6 里稳定的 2 条"跨块直接边"就是垃圾的随机解码（§4.2）。
   统计"分支条数"时它们会污染读数，所以本文分开列。
6. **没有做的**：FDE 与 unwind（S1 已说明 MC 拒绝嵌套 `.cfi_startproc`），所以每个 chunk
   仍然没有 unwind 记录；profile B 里 `__unwind_info` 被整表中立化。

## 6. 目标表本身：可读，能 100% 解回

原样 dump（`otool -s __TEXT __const`）：

```
0000000100001438	fffff91e fffff49e fffff49e fffff94a
0000000100001448	fffff5a6 fffff5a6 fffff976 fffff6c2
```

`key = 0x1e6`（侧车 `key 486`，同时出现在每条边的 `sub xT, xT, #0x1e6` 里）。解：

| 表项 | 原始 | 减 key | 目标 |
|---|---|---|---|
| 0 | `0xfffff91e` | −2248 | `0x100000b70` |
| 1 | `0xfffff49e` | −3400 | `0x1000006f0` |
| 2 | `0xfffff49e` | −3400 | `0x1000006f0` |
| 3 | `0xfffff94a` | −2204 | `0x100000b9c` |
| 4 | `0xfffff5a6` | −3136 | `0x1000007f8` |
| 5 | `0xfffff5a6` | −3136 | `0x1000007f8` |

`reports/s2_measure.py` 就是把这段写成了脚本：**42/42** 解回 `__text` 内，
其中 35 条正落在 chunk 头上、7 条落在 chunk 内部的块首（wbaes：2,515 条里 1,158 条落 chunk 头）。
**这是 S2 的真实弱点，不是可以藏起来的东西**：表在 rodata，key 在同一段代码的 `sub` 里，
"表 + key ⇒ 后继"这条推理是确定的、可离线批量做的。

它挡住的是**不做数据流折叠的读者**：线性扫描看不到 `br` 的后继，递归下降在这里断开，
`adrp+add` 那条一次性捷径没有了，每条边要多解一步（load → sub → add）才能接上。

## 7. 代价

### 7.1 体积与指令数

| | demo6 `D_sym`（S1） | demo6 `D_symcb`（S2 默认） | demo6 `D_symcball`（全边） | wbaes `W_sym`（S1） | wbaes `W_symcb` |
|---|---|---|---|---|---|
| 文件 | 35,064 | 35,064（**±0**） | 33,640（**±0** 相对 `D_base`） | 236,264 | 302,440（+28.0%） |
| `__text` | 3,356 | 3,896（+540，+16.1%） | 4,544（+1,188，+35.4%） | 118,168 | 167,736（+49,568，+41.9%） |
| `__const` | 324 | 508（+184） | 648（+324） | 603 | 12,667（+12,064） |
| 指令数 | 605 | 761（+156） | 898（+293） | 22,778 | 35,170（+12,392） |
| strip+scrub 后 | 34,160（B2） | 34,160 | – | 184,608（B2） | – |

demo6 的**文件大小**看起来没变（`D_sym` 35,064 → `D_symcb` 35,064；`D_base` 与 `D_cb` 都是
33,640）：`__TEXT` 段按 16 KB 页对齐，`__text` +540 与 `__const` +184 共 724 B 落在原有的页内
填充里（三个变体的 `__LINKEDIT fileoff` 都是 32768）。所以体积要看**段大小**，不是 `ls`。

**每条转换边的指令数（实测）**：demo6 默认档 156/42 = **3.7 条**；全边档 293/63 = **4.7 条**；
wbaes 12,392/2,515 = **4.9 条**。按形态算：拆分自己的边 5→8（+3）、直接 `b` 1→6（+5）、
条件边 1→10（+9）。

### 7.2 耗时：**未达 ≤5% 目标**

`reports/demo6_bench.cpp`（同 shortestPath，printf 换累加）× `s2_bench.py`
（每档 3 轮 × 40 进程，轮内交错，取中位数；每进程 20,000 次调用）：

| 轮 | `B_base` | `B_cb`（默认档） | `B_all`（全边档） |
|---|---|---|---|
| 1 | 142.1 ns | 230.8 ns | 226.2 ns |
| 2 | 140.9 ns | 228.8 ns | 225.1 ns |
| 3 | 140.9 ns | 229.3 ns | 224.8 ns |
| **中位数** | **140.9 ns/次** | **229.3 ns/次（+62.8%）** | **224.8 ns/次（+59.6%）** |
| 进程墙钟（中位） | 4.54 ms | 6.24 ms | 6.15 ms |

- **+62.8%，门槛是 ≤5%：这一条失败了**，且不是噪声（三轮同向，轮内交错采样）。
- 换算到每条边：+88 ns / 42 条 ≈ 2.1 ns ≈ **7 个周期/条**，正好是"一次 L1 load → 分支目标
  就绪"的延迟链条（加上每条边少一次直接分支预测）。
- 关键读数：**成本不随转换条数增长，而随"转换了哪些边"变化**。用上一版选边（只转 35 条）测到
  +67.1%，比现在转 42 条的 +62.8% 还高；全边档转 63 条反而 +59.6%。差别在**热循环里的边有没有被转**，
  不在条数。demo6 的每次调用只有 ~140 ns（≈450 周期），却要过 40+ 次分支，所以相对退化被放得很大。
- 同样的相对退化**不能**外推到 70 MB 正式产物：那里每条被转换边之间的真实工作量高得多。
  但本机无法验证（wbaes 跑不起来，§9.1），所以本文**不主张**"正式产物 ≤5%"。

### 7.3 编译期成本

`wbaes` 三档全量编译（`-O2` + 三个混淆 pass）墙钟差异在秒级噪声内；`demo6` 单次编译无法可靠测量。
没有新增 pass，没有额外文件读写（除非打开 sidecar）。

## 8. 失败的机制（原始事实，没有绕过）

1. **寄存器不够：wbaes 有 189 条边没转。** 条件边要 3 个在所有后继上都死的通用寄存器（X0–X7、X9–X15），
   在 `-O2` + 垃圾码 + 拆分之后，189 条边找不到。它们的处理是**保持原样**（直接 `b`/`b.cond`），
   sidecar 记 `skip <fn> regs[-cond] <src> <dst>`。没有用溢出糊过去，因为条件边的两条臂都要落
   `ldp` 还原，而这两条臂的块首还可能被别的边共用——那会把 SP 平衡搞坏。
2. **`term-chain`：wbaes 283 个块、demo6 10 个块拒绝。** 这些块的终结符不止一条（典型是
   `cbz; b`、`br; …`），只改第一条会留下不可达但仍在的旧分支，所以整块跳过。
   demo6 的 `cbz/tbz` 原始计数 14 → 17 全是垃圾区重排的误码变化：真正被转换的 4 条条件边都是
   `b.cc`（6 条真实的 `cbz/cbnz` 同块边在两个档位下都还在）。wbaes 的 `cbz/tbz` 计数
   **324 → 324 一条没动**——那一档里 CBZ/TBZ 全部落在 `term-chain` 块里。
3. **时序超预算**（§7.2）：这是设计取舍的直接后果——"每条边一次表读 + 间接跳转"。
   要压下去只有三条路，都不在本次范围：(a) 按 PGO/冷热选边（只转冷边，正是任务里
   "plus optionally cold blocks" 的那半句）；(b) 把表基 hoist 到一个保留寄存器（要改 prologue/epilogue）；
   (c) 表按 4 KB 对齐省掉 `add`（每条少 1 条指令，但每个函数最多浪费 4 KB 填充）。
4. **入口块、SP 弹栈块、跳转表 `br` 一律不动**：这是刻意保留的，不是漏做。

## 9. wbaes（真混淆产物，静态）

| | `W_base` | `W_sym`（S1） | `W_symcb`（S1+S2） |
|---|---|---|---|
| 文件 | 151,048 | 236,264 | 302,440 |
| `__text` | 118,168 | 118,168（逐字节相同） | 167,736 |
| `__const` | 603 | 603 | 12,667 |
| 指令数 | 22,778 | 22,778 | 35,170 |
| `br` | 858 | 858 | 2,530 |
| 其中表驱动 | 0 | 0 | **2,515** |
| 其中 `adrp+add+br` | 843 | 843 | **0** |
| 表项/边 | – | – | 2,515（= 843 + 1,672） |
| 直接边（`__text` 内） | 2,196 | 1,184 | 339 |
| 跨块直接边（真实） | – | **900** | **41** |
| 同块直接边（真实） | – | 185 | 185 |
| `.byte` 误码（不算边） | – | 98 | 112 |
| nlist / LC_FUNCTION_STARTS | 37 / 19 | 1,621 / 1,584 | 1,621 / **1,584** |
| 进程 | SIGTRAP(133) | SIGTRAP | SIGTRAP |

- 覆盖率：900 → 41 跨块直接边（**95.4%** 关掉），843 → 0 可解算的 `adrp+add+br`；
  同块边 185 条一条没动（预期）。剩下的 41 条来自 §8.1 的 189 条寄存器不足与 §8.2 的 283 个
  `term-chain` 块里真正跨块的那部分。
- `__text` 从 118,168 涨到 167,736（+41.9%），文件 +66,176 B（+28.0% 相对 S1，+100% 相对基线）。
  在 70 MB 产物上是 0.1% 量级的段增长；12 KB 的表相对可忽略。
- 该 demo 在本树启动即 SIGTRAP（基线一样，S1 §9.3），所以**没有运行时/耗时数据**。

## 10. 和 profile B（strip + scrub）的交互

`D_symcb` → `strip` → `macho_scrub --unwind neutralise`（seed `s2-demo6-B`）：

| gate | 值 |
|---|---|
| `strip` / `scrub` 返回码 | 0 / 0 |
| 文件 | 34,160 |
| nlist 定义符号 | 1（`__mh_execute_header`，被改种子名，不是函数起点） |
| `LC_FUNCTION_STARTS` | **27**（真 2 / 伪 25） |
| 其中带符号 | **0** |
| 导出表 | **0** |
| `__unwind_info` 条目 | **0** |
| 全文件 `WBAES\|hsvm\|hy_vm\|_ZN` | **0** |
| 死 trie 串 / 未认领 `__LINKEDIT` 字节 | 0 段 / 0 B |
| 运行 | rc=0，9 行，stdout sha `a3a6f0fc7d549bcc` |

`fnstarts_payload_identical_to D_symcb = True`：**`LC_FUNCTION_STARTS` 的 payload 与未 strip 的
S1+S2 产物逐字节相同**，即 27 个 chunk 起点一个不少（wbaes 侧 1,584 个同样不变）。
表标签是临时符号，strip 之后 nlist 里也没有它。

结论：**S2 与 profile B 完全兼容**，B 的三个 gate（0 名字 / 0 unwind / 起点表不变）都成立。

## 11. 判决

**S2 增加的"不透明度"挡得住反汇编器，挡不住分析者。**

- 挡得住的部分（可测）：demo6 上 42 条跨块边（wbaes 2,515 条）的后继不再出现在指令流里；
  `adrp+add+br` 这条"目标就写在紧邻两条指令"的捷径归零；真实的跨块直接边 demo6 从 7 降到 0。
  对线性扫描/递归下降，这些边就是断点，且**没有任何一条遗留下来的边指向 chunk 头**。
- 挡不住的部分（同样可测）：表和 key 都在产物里，`s2_measure.py` 用 20 行代码把 42/42 条边
  全解回来（wbaes 1,158 条落 chunk 头）。所以对"愿意看一眼 `sub #imm` 的人"，S2 只是把
  "读一条 `b`"变成"读一条 `sub` + 一次表查找"。
- **收益的定位**：它是给"工具链自动化"加成本，不是给"人工分析"加成本。要真的把这条也关掉，
  key 必须来自运行期（例如 `__stack_chk_guard`、dyld 提供的随机值）或每条边用不透明谓词选表项——
  两者都会再加 2–4 条指令/边，在 §7.2 已经 +63% 的基础上再加，风险很直接。
- **代价是实打实的**：+63% 的每调用耗时（demo6），+16% / +42% 的 `__text`（demo6 / wbaes）。
  按 G4（每块耗时退化 ≤5%）判，**这一版不达标**。

因此建议的落地方式不是"全局打开"，而是：**默认关，按 profile 只转冷边**（或在真正对性能
不敏感的模块上打开）。这也和 `MIR-SPLIT-STRENGTHENING.md` 里 S2 的定位一致：
"打断递归下降"是 S1/S3 的补充，不是免费的。

## 12. 复现

```sh
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp
M=demos/ios/reports/s2_measure.py ; BENCH=demos/ios/reports/demo6_bench.cpp
WB="demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c"

# demo6（6 个变体）
$CL -O1 $S -mllvm -obf-seed=12345 -o D_base
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=sym.tsv -o D_sym
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -computed-branches \
    -mllvm -computed-branches-sidecar=cb.tsv -o D_cb
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=symcb.tsv -mllvm -computed-branches \
    -mllvm -computed-branches-sidecar=symcb_cb.tsv -o D_symcb
ARMRC_CB_ALL=1 $CL -O1 $S -mllvm -obf-seed=12345 -mllvm -computed-branches \
    -mllvm -computed-branches-sidecar=cball.tsv -o D_cball
ARMRC_CB_ALL=1 $CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=symcball.tsv -mllvm -computed-branches \
    -mllvm -computed-branches-sidecar=symcball_cb.tsv -o D_symcball

# 正确性 + 不透明度
for f in D_base D_sym D_cb D_symcb D_cball D_symcball; do ./$f | shasum -a 256; done
python3 $M D_symcb --json D_symcb.json
python3 $M D_sym --json D_sym.json

# 计时
$CL -O1 $BENCH -mllvm -obf-seed=12345 -o B_base
$CL -O1 $BENCH -mllvm -obf-seed=12345 -mllvm -computed-branches -o B_cb
ARMRC_CB_ALL=1 $CL -O1 $BENCH -mllvm -obf-seed=12345 -mllvm -computed-branches -o B_all
python3 demos/ios/reports/s2_bench.py --iters 20000 --procs 40 --rounds 3 B_base B_cb B_all

# profile B
cp D_symcb P_cb && strip P_cb
python3 demos/wbaes/tools/macho_scrub.py --in P_cb --out P_cb_B \
    --seed s2-demo6-B --unwind neutralise
python3 demos/ios/reports/ab_measure.py P_cb_B --baseline D_base --run
python3 demos/ios/reports/s3_measure.py P_cb_B --baseline D_base --same-fnstarts-as D_symcb

# 默认关 = 不改代码（用改动前的同一个 clang 编同一命令，比较 __text 字节）
$CL -O1 $S -mllvm -obf-seed=12345 -o D_old   # 在 git checkout 掉补丁的编译器上
otool -s __TEXT __text D_old > a.txt ; otool -s __TEXT __text D_base > b.txt ; cmp a.txt b.txt

# wbaes（静态；该 demo 启动即 SIGTRAP，基线一样）
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 -o W_base
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=w_sym.tsv -o W_sym
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=w_symcb.tsv \
    -mllvm -computed-branches -mllvm -computed-branches-sidecar=w_cb.tsv -o W_symcb
python3 $M W_symcb --json W_symcb.json
```

`research/hsvm` ctest（编译器改动后跑）：**28/28 Passed**，5.23 s。

## 13. 默认关闭的证据

- 用 `git checkout` 掉补丁后重编同一个 clang，同一条命令编 demo6：`__text` 与改动后的
  `D_base` **逐字节相同**（`cmp` 无输出；`__const` 都是 324 B）。整文件只有 290 字节不同，
  全部在 `dataoff 33232` 之后（ad-hoc 代码签名区）。
- 结构化对比与 S1 发布的数字一致：`__text` 3,356、nlist 6、`LC_FUNCTION_STARTS` 2、
  stdout sha `a3a6f0fc7d549bcc`。
- 所有新逻辑都在 `cl::opt<bool> ComputedBranches`（默认 false）或 `getenv("ARMRC_CB_ALL")`
  之后；唯一的无条件改动是 `ChunkBlocks` 的填充条件从 `SplitSymbols` 放宽到
  `SplitSymbols || ComputedBranches`（两个都关时结果是空集，等价于原行为）。

## 14. 限制 / 没做的事

1. **只做 Mach-O**：非 Mach-O triple 打一行 `[computed-branches] only implemented for Mach-O, skipped`。
   表用的是 Mach-O 的 `.section` + 符号差，ELF 上要换 `.quad sym1-sym2` + `.section .rodata`，未测未做。
2. **key 只有 12 位**，就为了 `sub #key` 一条指令能编码（imm12）。它不提供密码学强度：
   就算换成 64 位，key 仍必须出现在产物里，§11 的结论不变；12 位只是让"猜"更便宜，
   而"解"本来就不需要猜。
3. **表按每个函数一张、4 字节一项、不重排**：下标就是边出现的顺序，同一 target 的多条边会出现
   重复项（demo6 里 46 项对 42 条边，4 条条件边各占 2 项）。没有做去重/洗牌。
4. **没有 PGO 冷热选边**：`ARMRC_CB_ALL` 只是为了测"全边档"，不是给用户用的档位。
   真正的落地应该拿块频率做选择（§8.3）。
5. **同一个 `br` 的 `x16/x17` 溢出策略**（拆分自己的边）沿用 S1 的 16 字节 SP 槽；
   条件边/直接边用死寄存器，**没有**溢出回退，所以 wbaes 上有 189 条边没转（§8.1）。
6. **没有 IDA/Ghidra**：所有"不可发现"都是 `otool -tv` 的静态读数 + 本文的脚本，
   不等于任何商业反编译器的函数识别结果。
7. **wbaes 没有运行时数据**（基线 SIGTRAP），因此 S2 在真混淆产物上的耗时**未测**。
