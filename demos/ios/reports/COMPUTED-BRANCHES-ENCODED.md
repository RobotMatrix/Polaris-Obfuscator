# S2b 落地：目标表加密（key 不在指令里、条目不是 delta）+ 冷边/预算档位

> 状态：**已实现并入树**。开关 `-mllvm -computed-branches-encoded`（表加密）与
> `-mllvm -computed-branches-cold-only`（只转非环边），**两个都默认关**；
> 只给 `-computed-branches` 时产物与 S2 **逐字节相同**（§3.3）。
> 全部数字来自本机实跑（macOS 27.3 / arm64，本仓 clang 16.0.6），复现命令见 §11。
> 本机没有 IDA/Ghidra：本文所有"解不出"都是**脚本读产物**的静态计数，不是反编译器判决。

## 0. 结论先行

S2 的表之所以交底，是因为三条同时成立：表项是**表相对 delta**、key 是紧邻的
`sub #imm`、一张表只有**一个 key**。S2b 把三条全改掉：

| | S2（`-computed-branches`） | S2b（`+ -computed-branches-encoded`） |
|---|---|---|
| 表项内容 | `delta + key`（key=0x1e6） | `delta + M_i`，`M_i = K ^ c_i` 每条一个 |
| 表项离真 delta 多远（demo6） | 恒为 486 B（就是 key） | **最小 554,829,010 B**，中位 1,266,796,467 B |
| key 在哪 | 每条边的 `sub #imm` | 2 个字在 `__DATA_CONST,__const`，运行期折成 `K = W0 ^ W1` |
| key 与表的距离（demo6） | 0（同一个 `sub`） | **10,024 B，不同段**（wbaes 22,392 B） |
| 指令里出现 K 或 W0/W1 立即数 | key 就是立即数 | **0 处**（全文 grep） |
| 一次性扫表解回（legacy 解码器） | **46/46**（35 落 chunk 头） | **0/46** |
| 找到 ring、把字当 key（naive 解码器） | – | **0/46** |
| 复现整套方案（scheme 解码器） | – | 46/46（35 落 chunk 头） |

- **不透明度：达标，但不是保密。** 表单独没用、指令里的 `c_i` 单独没用、K 不是立即数、
  key 不在表的附近。要解回来必须**跟着数据流跑到另一个段 + 知道编译器里的掩码推导**
  （§4.3）。所以收益是"把一次线性扫描变成一次方案复现"，**不是"解不出来"**。
- **代价：5% 的门槛仍然没达到，而且和 S2b 无关。** demo6 上 S2 +62.2%、S2b +66.8%，
  即**加密本身只值 +6.4 ns（相对 S2 +2.8%）**；钱花在"把直接分支换成 load→br"上。
  冷边档位（只转环外边）**一条执行中的边都没少**，实测 +65.7%，等于没省（§6.3）。
  预算前沿实测：每函数只转 1 条边 +20.2%，8 条 +20.8%，24 条 +51.1%（§6.2）。
  **≤5% 在这条 140 ns 的被调用方上买不到任何一条被执行的边。**
- **取舍：保不透明度。** 加密相对整套机制几乎免费（+4.5% 于基线，+2.8% 于 S2），
  而代价是机制本身的；把加密砍掉只会回到"20 行脚本 46/46"，省不到 3%。

## 1. 机制

### 1.1 三条改动

1. **key 离开指令流。** 每个函数一对 32 位字 `W0/W1` 落在 `__DATA_CONST,__const`
   （ld64 把 `__DATA,__const` 折进只读的 `__DATA_CONST` 段），消耗序列用
   `adrp/add/ldr` 取 8 字节，再 `eor x, x, x, lsr #32` 折成 `K = W0 ^ W1`。
   两个存储字都不是 K，K 不出现在任何指令里，且与表不同段、相距 10 KB 量级。
2. **每条一个掩码。** 表项 = `(target - table) + M_i`，`M_i = K ^ c_i`，`c_i` 由
   （函数 ring，表下标）经 splitmix 派生、并**限制成 AArch64 逻辑立即数**（`eor #imm`
   能编码的形态）。因此：表不是 delta 数组；**指向同一 target 的两条边也不再长得一样**；
   掩码序列不是等差数列，无法由手工解出的几条插值。
3. **消费侧只多一条 `eor`。** 序列用 `eor wK, wK, #c_i` 还原 `M_i`，再 `sub`。
   `c_i` 是明文立即数——单独拿到它没有用，因为还差 K。

`c_i` 的取值有两条硬约束，都是实测撞出来的：

- 必须是**逻辑立即数**，且 MIR 里必须传 **13 位 N:immr:imms 编码**（`encodeLogicalImmediate`）。
  传值会被 MC 层静默截成垃圾指令（本机实测：`.long 0x523ffc84`，运行时 SIGBUS）。
- 置位不能全在低 16 位：`c_i` 很小 ⇒ `K ^ c_i` 接近 K ⇒ `entry - K` 落在真目标旁边，
  **仍然落进 `__text`**。修前 naive 解码器在 demo6 上蒙对 4/46，修后 0/46。

### 1.2 三种序列形态（实测指令数）

无条件边，有三个 scratch 寄存器（`convertComputedBranches` 的直接 `b`）：

```
  adrp xK, <ring>@PAGE ; add xK,xK,<ring>@PAGEOFF ; ldr xK,[xK]
  eor  xK, xK, xK, lsr #32        ; K = W0 ^ W1
  adrp xB, <table>@PAGE ; add xB,xB,<table>@PAGEOFF
  ldrsw xT, [xB, #idx]
  eor  wK, wK, #c_i               ; M_i
  sub  wT, wT, wK                 ; = target - table
  add  xB, xB, wT, sxtw ; br xB
```
11 条（S2 是 6 条）。demo6 实测形态（`0x100000588`）：

```
adrp x4, 4 ; 0x100004000        add x2, x2, #0x8f0      eor w4, w4, #0xffffe007
add  x4, x4, #0x18              ldrsw x3, [x2, #0x3c]   sub w3, w3, w4
ldr  x4, [x4]                   (eor w4 见右)           add x2, x2, w3, sxtw
eor  x4, x4, x4, lsr #32        adrp x2, 1              br  x2
```

拆分自己的边（`emitIndirectBranch`，只有 X16/X17）把"基址"放到最后重算，13 条：

```
stp x16,x17,[sp,#-0x80]!        ; S1 的溢出对（不动）
adrp x16,<table> ; add ; ldrsw x17,[x16,#idx]
adrp x16,<ring> ; add ; ldr x16,[x16] ; eor x16,x16,x16,lsr#32
eor w16,w16,#c_i ; sub w17,w17,w16
adrp x16,<table> ; add ; add x16,x16,w17,sxtw ; br x16
```
条件边（`csel` 选臂）17 条：两条目各一次 `sub`，第二条目的掩码由
`eor wK, wK, #d`（`d = c_T ^ c_F`，也是逻辑立即数）从第一条的掩码推出，**不多占寄存器**。

- 表项仍是 `sym - table + 常数`：同段两符号相减，ld64 算成常数，**无 rebase、无 dyld 修正**
  （`dyld_info -fixups` 里只有 `__got` 的 3 条 bind，`__DATA_CONST,__const` 的 `nreloc 0`）。
- ring 标签同样以 `L` 开头 ⇒ 不进 nlist（wbaes nlist 1,621 与 S2 相同）。
- 没有新增 pass、没有链接后修补、没有改链接器。

### 1.3 开关

```
-mllvm -computed-branches                 # S2 总开关（默认 false，行为不变）
-mllvm -computed-branches-encoded         # S2b 表加密（默认 false）
-mllvm -computed-branches-cold-only       # 只转两个端点都不在任何环里的边（默认 false）
-mllvm -computed-branches-sidecar=<path>  # 每条边/每个拒绝原因，加密档额外写 ring 与 W0/W1
ARMRC_CB_LIMIT=<n>                        # 仅测量：每函数最多转 n 条边（0=不限）
```

sidecar 片段（加密档，seed 12345）：

```
fn	_Z12shortestPathPA9_ji	conv	5	skipped	0	refused	16	entries	22	table	L__pcb7a872387e295	ring	L__pcke6a5e7529e12 443556885 1151180999
```

## 2. 被测对象

```
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp
BENCH=demos/ios/reports/demo6_bench.cpp ; M=demos/ios/reports/s2_measure.py
```

| 变体 | 源 | 编译 |
|---|---|---|
| `D_base` | demo6 | `-O1 -mllvm -obf-seed=12345` |
| `D_plain` | demo6 | `+ -mllvm -split-symbols -mllvm -computed-branches`（= S2） |
| `D_enc` | demo6 | `+ -mllvm -computed-branches-encoded` |
| `D_cold` | demo6 | `+ -mllvm -computed-branches-cold-only` |
| `D_enccold` | demo6 | `+ -encoded -cold-only` |
| `P_enc_B` | demo6 | `D_enc` → `strip` → `macho_scrub --unwind neutralise` |
| `B_base` / `B_plain` / `B_enc` / `B_cold` / `B_enccold` | `demo6_bench.cpp` | 同上的计时探针 |
| `B_enc_lim<n>` | `demo6_bench.cpp` | `ARMRC_CB_LIMIT=<n>` 的加密档 |
| `W_plain` / `W_enc` | wbaes | `-O2 -passes=sub,bcf,fla`，`ARMRC_NO_DATAFLOW=1`，**只做静态测量**（该 demo 在本树启动即 SIGTRAP，基线一样，见 S1 §9.3 / S2 §9） |

## 3. 正确性

### 3.1 stdout（demo6，9 行表）

| 变体 | rc | 行数 | stdout sha256（前 16） |
|---|---|---|---|
| `D_base` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_plain` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_enc` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_cold` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_enccold` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `D_enc` + `-Wl,-dead_strip` | 0 | 9 | `a3a6f0fc7d549bcc` |
| `P_enc_B`（strip+scrub） | 0 | 9 | `a3a6f0fc7d549bcc` |

完整 sha256 = `a3a6f0fc7d549bcc9b2639e768b985ccd36f747d53895e5a9b2a2ffbc46a5846`，
与 S1/S2 记录一致。计时探针 10 个变体的校验和都是 `1600032`。

`-dead_strip` 之后 ring 仍在（`__DATA_CONST,__const` 16 B）：`__text` 的 `adrp` 引用了它，
ld64 视为活原子。

### 3.2 回归

`research/hsvm` ctest：**28/28 Passed**，5.13 s。

### 3.3 默认关 = 不改行为

- 只给 `-computed-branches`（加密关）时，`D_plain` 的 `__text` 与**改动前那个 clang**
  编出的 S2 产物**逐字节相同**（`cmp` 无输出）。
- 一个开关都不给时：`__text` 3,356 B / `__const` 324 B / 605 条指令 / nlist 6 / sha
  `a3a6f0fc…`——与 S1/S2 发布的 `D_base` 完全一致。
- 所有新逻辑都在 `ComputedBranchesEncoded` / `ComputedBranchesColdOnly` /
  `getenv("ARMRC_CB_LIMIT")` 之后；唯一无条件改动的行是诊断计数器，不产生指令。

## 4. 不透明度：三个解码器的读数

`reports/s2_measure.py` 现在把边分成两种形态（S2 的 `sub #imm` 与 S2b 的 `eor #imm`），
并对目标表跑三个解码器：

| 解码器 | 它知道什么 | 做法 |
|---|---|---|
| `legacy` | S2 的方案 | 读 `sub #imm` 当 key，`target = table + (entry - key)` |
| `naive` | 只能跟着数据流找到 ring | 把 `W0`/`W1`/`W0^W1`/`W0*W1`/`~W0` 分别当 key，`sub` 与 `xor` 各试一遍 |
| `scheme` | S2b 的完整方案（只存在于编译器源码里） | `K = W0^W1`，逐条按 `eor #imm` 累积掩码，再 `sub` |

### 4.1 demo6

| 变体 | 指令 | `__text` | `__const` | ring | 表驱动边 | 表项 | legacy | naive | scheme |
|---|---|---|---|---|---|---|---|---|---|
| `D_base` | 605 | 3,356 | 324 | 0 | 0 | 0 | – | – | – |
| `D_plain`（S2） | 761 | 3,896 | 508 | 0 | 42 | 46 | **46/46**（35 落 chunk 头） | 0 | – |
| **`D_enc`** | 1,043 | 5,024 | 508 | 16 | 42 | 46 | **0/46** | **0/46** | 46/46（35） |
| `D_cold` | 650 | 3,508 | 416 | 0 | 23 | 23 | **23/23**（23 落 chunk 头） | 0 | – |
| `D_enccold` | 801 | 4,112 | 416 | 16 | 23 | 23 | **0/23** | **0/23** | 23/23（23） |

"落 chunk 头"是"这条边真的被解出来了"的判据：S2 那 30 条拆分自己发的边一律指向 chunk 头，
另外 12 条指向 chunk 内部的块首，所以 46 个表项里 35 个落在 chunk 头上，与
SPLIT-COMPUTED-BRANCHES.md §6 的 42/42（35 落 chunk 头）一致。

### 4.2 wbaes（静态）

| | `W_plain`（S2） | `W_enc`（S2b） |
|---|---|---|
| 文件 | 302,440 | 351,992（+16.4%） |
| `__text` | 167,736 | 221,872（+32.2%） |
| `__TEXT,__const` | 12,667 | 11,771 |
| ring（`__DATA_CONST,__const`） | 0 | 56 B（7 个函数 × 8 B） |
| 指令 | 35,170 | 48,704（+38.5%） |
| 表驱动边 | 2,515 | 2,292（−8.9%，见 §7） |
| 表项 | 3,016 | 2,793 |
| legacy | **3,016/3,016**（1,657 落 chunk 头） | **0/2,793** |
| naive | – | 129/2,793，其中**落 chunk 头 0** |
| scheme | – | 2,790/2,793（1,437 落 chunk 头） |
| nlist / `LC_FUNCTION_STARTS` | 1,621 / 1,584 | 1,621 / 1,584 |

wbaes 上 naive 的 129 条是"落进 221 KB 的 `__text`"而不是"解出了后继"：落 chunk 头 0 条，
即没有一条命中真后继。函数越大，这个计数越容易虚高，所以本文只用"落 chunk 头"作判据。

### 4.3 表项不是 delta（可量）

`scheme` 解码器顺带给出每个表项的掩码 `M_i`（表项与真 delta 的距离）。加密档：

| | 最小 `|M_i|` | 中位 `|M_i|` | 最大的真 delta |
|---|---|---|---|
| `D_enc` | **554,829,010 B** | 1,266,796,467 B | 函数大小量级（≤ 10 KB） |
| `W_enc` | **62,998,947 B** | 1,235,954,976 B | ≤ 数 KB |

也就是说：**没有任何一个表项落在它真 delta 的 60 MB 之内**，"读表 ⇒ 得到偏移"这条推理在
数值上不成立，而不是"看起来乱"。

### 4.4 要解回来需要做什么（诚实清单）

`scheme` 解码器拿到 46/46，说明**产物里的信息是够的**——这不可能避免，运行期必须能算出目标。
它比 S2 多付出的四步：

1. 认出 `adrp/add/ldr` + `eor …, lsr #32` 是在另一个段取 key（`__TEXT,__const` 里没有它）；
2. 猜到折叠是 `K = W0 ^ W1`（不是 `W0`、不是乘积、不是 `(K<<32)|K`）；
3. 猜到 `eor #c_i` 的立即数要**逐条累积**异或到 K 上（条件边第二条目用的是差值 `d`）；
4. 逐条重算掩码，才能把表项变回 delta。

这四步**都不在产物里**，只在编译器源码里。反过来说：只要有人把这套方案读一遍，
S2b 就退化成 S2。**所以 S2b 买的是"自动化成本"，不是保密**——和 S2 的定位一致，
只是把"一次线性扫描"抬到"复现一个方案"。

## 5. 表本身：前后 dump

S2（`otool -s __TEXT __const`，`key = 0x1e6`）：

```
0000000100001438	fffff91e fffff49e fffff49e fffff94a
0000000100001448	fffff5a6 fffff5a6 fffff976 fffff6c2
```

每项减 486 就是"到表的偏移"，肉眼可读；索引 1 与 2 指向同一个块，所以两个词**逐字节一样**
（`fffff49e`）。S2b（`D_enc`，同一 seed、同一批边）：

```
00000001000018f0	2111f936 5ed269a2 5e9173a2 a0ed7979
0000000100001900	a12d773d 59126be2 5f127046 5e11f656
```

索引 1 与 2 仍然指向同一个块（`0x1000007c0`），两个词却是 `5ed269a2` 与 `5e9173a2`：
**重复项不再一致**，`scheme` 解码给出的掩码差就是 `M_1 - M_2`。索引 4/5、7/8、10/11、13/14
同样是"同 target、不同词"（这 5 对就是 S2 里那 5 对重复项）。ring
（`otool -s __DATA_CONST __const`）：

```
0000000100004018	1a702415 449da0c7      ← W0, W1（K = 0x5eed84d2 不在文件里）
```

全文 grep `#0x1a702415|#0x449da0c7|#0x5eed84d2|#0x1a70|#0x5eed`：**0 处**。

## 6. 代价

### 6.1 每调用耗时（`s2_bench.py`：3 轮 × 40 进程 × 20,000 次调用，轮内交错，取中位数）

| 变体 | ns/次 | 进程墙钟 | 相对基线 | 转换的表项 |
|---|---|---|---|---|
| `B_base` | **140.9** | 4.48 ms | – | 0 |
| `B_plain`（S2） | 228.6 | 6.25 ms | **+62.2%** | 46 |
| `B_enc`（S2b 全边） | 235.0 | 6.38 ms | **+66.8%** | 46 |
| `B_cold`（S2 冷边） | 233.5 | 6.32 ms | +65.7% | 23 |
| `B_enccold`（S2b 冷边） | 233.8 | 6.35 ms | +65.9% | 23 |

- **加密的边际成本：235.0 − 228.6 = 6.4 ns/次（相对 S2 +2.8%，相对基线 +4.5%）**，
  摊到 46 个表项是 0.14 ns/项——因为它只多 6 条 ALU/load 指令，且与表项 load 并行。
- 代价的主项是机制本身：228.6 − 140.9 = 87.7 ns，即每条被执行的转换边约 2 ns
  （与 S2 §7.2 的 2.1 ns/边一致），本质是"load → 分支"的依赖链 + 少一次直接分支预测。

### 6.2 预算前沿（`ARMRC_CB_LIMIT`，同一轮测量）

| 每函数转换条数 | 1 | 2 | 8 | 16 | 24 | 42（全部） |
|---|---|---|---|---|---|---|
| ns/次 | 169.4 | 184.1 | 170.3 | 178.6 | 212.9 | 235.0 |
| 相对基线 | **+20.2%** | +30.6% | **+20.8%** | +26.7% | +51.1% | +66.8% |

曲线**不是单调的**，原因可测：转 1 条时转的是 emission 顺序最前面的那条拆分边，它正好在
热循环里，每次调用要被走几十次；转 8 条时新增的都是更冷的边，且布局改变把一部分代价抵消。
但**下界仍然远高于 5%**：demo6 的一次调用只有 140.9 ns（≈450 周期），
5% 就是 7 ns，而**单独一条热循环里的转换边就要 28.5 ns**（169.4 − 140.9）。
换句话说：≤5% 的预算在这条被调用方上**买不到一条被执行的边**。

### 6.3 冷边档位为什么没有省（实测，不是推测）

`cold-only` 把环内的边留成直接 `b`（保留 S1 的溢出对以维持 SP 平衡）。demo6 上它把
表项从 46 砍到 23（−50%，sidecar 记 6 条 `refused hot`），**耗时却从 +62.2% 变成 +65.7%**。
读数只有一个解释：被砍掉的 23 项不在每次调用的执行路径上。

这不是"CFG 少了边"：sidecar 旁边的诊断计数器显示，被 `convertComputedBranches` 改写的边
**在 CFG 里都有记录**（demo6：7/7 与 9/9）。原因是**函数太小**——`shortestPath` 一次调用
≈450 周期，几乎每个块每次调用都走一遍，所以"不在环里"≈"每次调用走一次"，仍然要付
load→br 的代价。冷边档位真正能省的是"整个块都不执行"的边，那在 demo6 里几乎不存在。
（wbaes 上它跳过的是 412 条寄存器不足的边之外的那部分，静态上无法证明它们是否执行——
该 demo 跑不起来。）

### 6.4 没做的一项：批量取表项

条件边是唯一一条序列里取两个表项的形态（demo6 只有 4 条），把它们合成一次 8 字节 load
最多省 4 次 load/调用（约 4 ns 量级），而代价在无条件的 38 条边上。
**判断（未实测）：这一项买不到 1%，不值得为它加一条新的序列形态。** 本文的测量支持这个
判断：加密多 6 条指令只花了 6.4 ns，说明瓶颈不在指令数，在那条 load→br 依赖链。

## 7. wbaes：加密档的覆盖损失

| | `W_plain`（S2） | `W_enc`（S2b） |
|---|---|---|
| 转换的边 | 2,515 | 2,292（−223，−8.9%） |
| sidecar `skip … regs` | 189 | **412** |
| sidecar `refused term-chain` | 283 | 283 |

原因明确：无条件边现在需要 **3 个** scratch 寄存器（基址、key/掩码、表项三者同时活），
S2 只要 2 个。`-O2` + 垃圾码 + 拆分之后，`-O2` 的活寄存器本来就紧，223 条边因此退回直接分支。
条件边仍是 3 个（掩码用 `eor #d` 串联，不额外占寄存器），所以 `regs-cond` 一条没变。

这是加密的**真实代价**，不是可以藏起来的东西：demo6（小函数、寄存器宽裕）覆盖率不变，
wbaes（真混淆产物）掉 8.9%。

## 8. 与 profile B（strip + scrub）的交互

`D_enc` → `strip` → `macho_scrub --unwind neutralise`（seed `s2b-demo6-B`）：

| gate | 值 |
|---|---|
| `strip` / `scrub` 返回码 | 0 / 0 |
| 文件 | 34,160 |
| nlist 定义符号 | 1（`__mh_execute_header`，已改种子名） |
| 导出表 | 0 |
| `__unwind_info` 条目 | 0（104 B → 0，2 个 index 条目） |
| 全文件 `WBAES\|hsvm\|hy_vm\|_ZN` | 0 |
| 死 trie 串 / 未认领 `__LINKEDIT` 字节 | 0 / 0 B（1,432 B 中 0 B） |
| `LC_FUNCTION_STARTS` | 27（真 2 / 伪 25），带符号 0，无名 27 |
| `fnstarts_payload_identical_to D_enc` | **True** |
| 运行 | rc=0，9 行，sha `a3a6f0fc7d549bcc` |

**S2b 与 profile B 完全兼容**：ring 是 `__DATA_CONST` 的普通数据（`nreloc 0`），
strip 不碰它，scrub 的四个 gate（0 名字 / 0 导出 / 0 unwind / 起点表不变）全部成立。

## 9. 判决与推荐

**能不能同时满足不透明度和 ≤5%？在这条被调用方上：不能。**

- 不透明度已经拿到（legacy 46→0、naive 0、表项离 delta 6 亿 B 量级），
  而且**加密只花 +2.8%（相对 S2）**。
- ≤5% 拿不到，且**与加密无关**：瓶颈是"直接分支换成 load→br"，S2 就已经 +62.2%。
  预算前沿显示这条被调用方上连 1 条热边都放不进 5%（§6.2）。
- 冷边档位（任务给的三个方向之一）**实测无效**：跳掉 50% 的表项，耗时不变（§6.3）。
  原因是函数太小、几乎每个块每次都执行；这个档位只在"有大量永不执行的块"的产物上有意义。

**推荐落地方式（按优先级）：**

1. **保留加密，默认关。** 它是纯增益：相对 S2 只贵 2.8%，却把"S2 的 20 行脚本 46/46"
   变成"必须复现一套方案"；wbaes 上 legacy 从 3,016/3,016 变 0/2,793。
   代价是 wbaes 上 8.9% 的覆盖率（§7），也记在账上。
2. **`-computed-branches-cold-only` 不作为默认。** 它在 demo6 上零收益、在 wbaes 上无法证明收益，
   而它会主动放弃 50% 的边的不透明度。要按冷热选边，正确做法是 PGO/调用图（按**函数**选，
   不是按块），因为拆分产生的块没有任何 profile 信息可用（§6.3）。这一点本文没有实现。
3. **不要对热的小函数开 computed branches。** 判据用函数级的（例如"每次调用的工作量"或
   调用频率），不要用块级静态启发式。这是 S2 已经得出的结论，S2b 的测量把它坐实了。
4. **如果必须在"不透明度"和"5%"里只留一个：留不透明度。** 因为代价几乎全部来自机制本身，
   砍掉加密只省 2.8%，却把表重新变成一眼可读的 delta 数组。

## 10. 限制 / 没做的事

1. **key 必须出现在产物里。** 运行期要能算出目标，所以方案一定可被复现（§4.4）。
   S2b 把"读一条 `sub` 就够"抬成"跟着数据流跨段 + 知道掩码推导"，不是把它们变成不可能。
   想要"读不到"，得让 K 依赖运行期才存在的值（例如加载后的指针），那要重定位或构造器改写，
   会破坏"无 rebase / 无链接后修补"这条 S2 的前提，本文没做。
2. **冷边档位是静态近似。** 用 DFS back edge 标记环成员，没有 dominator tree（pre-emit 没有），
   且按边两端判定（保守方向：少转）。它**不识别执行频率**，demo6 上因此零收益（§6.3）。
3. **wbaes 没有运行时数据**（基线 SIGTRAP），所以 wbaes 上的耗时、以及"冷边档位在真产物上
   能不能省"**未测**。
4. **只做 Mach-O**：ring 用 `__DATA,__const`（ld64 折进 `__DATA_CONST`）。ELF 上要换
   `.section .data.rel.ro` 或同样在 `__DATA`，未测。
5. **demo6 是微基准**：140.9 ns/次、450 周期，几乎每个块每次都执行，所以相对退化被放大。
   **不能**把它外推到 70 MB 产物；也**没有**主张"正式产物 ≤5%"。
6. **`ARMRC_CB_LIMIT` 只是测量档**（和 `ARMRC_CB_ALL` 同级），不是给用户用的旋钮：
   它按 emission 顺序截断，不按冷热。
7. **没有 IDA/Ghidra**：所有"解不出"都是 `otool -tv` + 本文脚本的静态读数。

## 11. 复现

```sh
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp
BENCH=demos/ios/reports/demo6_bench.cpp ; M=demos/ios/reports/s2_measure.py
WB="demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c"

# demo6 五个变体
$CL -O1 $S -mllvm -obf-seed=12345 -o D_base
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols -mllvm -computed-branches \
    -mllvm -computed-branches-sidecar=cb_plain.tsv -o D_plain
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols -mllvm -computed-branches \
    -mllvm -computed-branches-encoded \
    -mllvm -computed-branches-sidecar=cb_enc.tsv -o D_enc
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols -mllvm -computed-branches \
    -mllvm -computed-branches-cold-only -o D_cold
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols -mllvm -computed-branches \
    -mllvm -computed-branches-encoded -mllvm -computed-branches-cold-only -o D_enccold
for f in D_base D_plain D_enc D_cold D_enccold; do ./$f | shasum -a 256; done

# 三个解码器（legacy / naive / scheme），JSON 里有逐条计数
python3 $M D_plain --json D_plain.meas.json
python3 $M D_enc   --json D_enc.meas.json
python3 $M D_enc -v          # 逐边打印 base/idx/raw/ring/eor

# 表与 ring 的原样 dump
otool -s __TEXT __const D_enc ; otool -s __DATA_CONST __const D_enc
otool -tv D_enc | grep -ciE '#0x1a702415|#0x449da0c7|#0x5eed84d2'   # 0

# 计时（含预算前沿）
$CL -O1 $BENCH -mllvm -obf-seed=12345 -o B_base
$CL -O1 $BENCH -mllvm -obf-seed=12345 -mllvm -computed-branches -o B_plain
$CL -O1 $BENCH -mllvm -obf-seed=12345 -mllvm -computed-branches \
    -mllvm -computed-branches-encoded -o B_enc
for n in 1 2 8 16 24; do ARMRC_CB_LIMIT=$n $CL -O1 $BENCH -mllvm -obf-seed=12345 \
    -mllvm -computed-branches -mllvm -computed-branches-encoded -o B_enc_lim$n; done
python3 demos/ios/reports/s2_bench.py --iters 20000 --procs 40 --rounds 3 \
    ./B_base ./B_plain ./B_enc ./B_cold ./B_enccold \
    ./B_enc_lim1 ./B_enc_lim2 ./B_enc_lim8 ./B_enc_lim16 ./B_enc_lim24

# profile B
cp D_enc P_enc && strip P_enc
python3 demos/wbaes/tools/macho_scrub.py --in P_enc --out P_enc_B \
    --seed s2b-demo6-B --unwind neutralise
python3 demos/ios/reports/ab_measure.py P_enc_B --baseline D_base --run
python3 demos/ios/reports/s3_measure.py P_enc_B --baseline D_base --same-fnstarts-as D_enc

# wbaes（静态；该 demo 启动即 SIGTRAP）
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -computed-branches -o W_plain
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -computed-branches -mllvm -computed-branches-encoded \
    -o W_enc
python3 $M W_plain --json W_plain.meas.json ; python3 $M W_enc --json W_enc.meas.json

# 回归
cd research/hsvm/build && ctest      # 28/28 Passed, 5.13 s
```
