# S4 落地：先合再拆 + 每构建随机粒度

> 状态：**已实现并入树**。编译器改动在 `MergeFunction.cpp`（`-mllvm -merge-then-split`）与
> `AArch64RubbishCode.cpp`（`-mllvm -split-granularity=random`），默认全关。
> 所有数字来自本机实跑（macOS 27.3 / arm64，本仓 clang 16.0.6）。
> 前三份：`SPLIT-SYMBOLS.md`（S1 机制）、`SPLIT-SYMBOLS-S3.md`（S3）、
> `SPLIT-SYMBOLS-AB.md`（A/B 两条 profile）。本文只回答 S4 的两个问题：
> **合再拆之后，可见边界还能不能还原到原函数**，以及**粒度随机化能不能让签名跨构建失效**。

## 0. 结论先行

**判为"断了"（attribution broken），但不是"全断"：区间与归属断了，入口没断。**

| 问题 | 基线（无 S4） | S4（合并 + 拆分） | 断了吗 |
|---|---|---|---|
| 可见符号区间数 / 4 个源函数 | **4 个区间**，每区间 1 个源函数 | **1 个区间**，含 **4 个源函数** | ✅ 断了 |
| 每个可见函数起点能映射到 1 个源函数 | 是（4/4） | **否**（1 个区间对 4 个源函数） | ✅ 断了 |
| chunk 归属（哪个 chunk 属于哪个源函数） | — | 每个源函数的 2 个 chunk **落在 2 段不连续的地址区间**，与别人交错；名字零泄漏（0/24） | ✅ 断了 |
| 源函数**入口**地址 | 4 个 nlist 符号 | 合并体的 switch 分发（`cmp w0,#key; b.cond 目标`）仍可静态跟出 4 个 case 目标；这 4 个目标**都不是** `LC_FUNCTION_STARTS` 条目，也**不是** chunk 起点（实测 0/10 重合） | ⚠️ 泄漏（入口可猜，归不回去） |
| 粒度跨构建签名 | 固定规则（4/8 条指令），同名函数每次相同 | 3 个种子：chunk 数 12/12/10 与 13/9/9，边界偏移集合 Jaccard **0.13–0.16**（同种子对照 1.000） | ✅ 断了 |

代价（demo6_merge4）：体积 33,800 → 34,632 B（**+2.5%**），`__text` 2,812 → 2,784 B（−1.0%），
每调用 **−7.6%**（不是退化），profile B 仍是 0 名字 / 0 unwind / `LC_FUNCTION_STARTS` 载荷逐字节不变。
功能：**14 个变体全部 rc=0、9 行 Dijkstra 表、stdout sha `a3a6f0fc7d549bcc`**（与 S1 基线一致）。

诚实的一句话：S4 破坏的是**符号区间与语义归属**这一层；**合并体的分发链仍是源函数入口的清单**，
这是 S2（计算分支）该管的边，S4 没有、也不该在 MIR 层伪装它。

## 1. 机制

### 1.1 先合：`-merge-then-split`

```
-mllvm -passes=merge -mllvm -merge-then-split        # 需要函数带 mergefunction 注解（或 policy 指定）
-mllvm -merge-scope-sidecar=<path>                    # 追加 (merged, src fn, idx) 映射，测量用 ground truth
```

- **void 函数走直连路径**（本次新增）：注解函数直接进 `MergeList`，`merge()` 把它克隆进
  `__merged_function`、改写全部调用点、再 `eraseFromParent()`。
  **源函数的符号随之消失**——这一条是关键：如果按老路给每个源函数留一个 `_internal` + 薄 wrapper，
  二进制里就还有"一个源函数一个符号"的 1:1 形状，S4 白做。
  void 直连的代价写进注释与本文 §8.1：被合并的函数不能再是导出 ABI 的一部分。
- **scope marker**（`-merge-then-split` 才发）：每个被克隆的 IR 基本块头插一条
  `polaris_merge_scope_<idx>` 的内联汇编，`AArch64RubbishCode` 在 ISel 前把它擦掉（0 字节入产物），
  只留下"这个 MBB 来自哪个源函数"的 ground truth。marker 是真正的指令，所以它跟着块走：
  后面任何 IR pass（flattening 等）搬块都不丢归属。
- **合并体属性清空**：`CloneFunctionInto` 会把每个源函数的 attribute list 拷到合并体上（最后一个赢），
  于是前面的函数体可能违反它（例如"写内存"的体落在 `memory(none)` 下面）。合并体不保证其中任何一条，
  所以直接清空 `AttributeList`。
- 空列表不再建函数：没有注解函数时不留下一个"没有 case 的 `__merged_function`"（否则那是分析者能看见的符号）。

### 1.2 再拆：粒度随机化

```
-mllvm -split-granularity=random     # 默认 fixed，保持原行为逐字节不变
-mllvm -split-chunk-min=3 -mllvm -split-chunk-max=7
```

- 固定规则的原始语义没动（`BlockSize = 4`：第 4 条可插入垃圾的指令处切一次，之后每 8 条切一次）。
- `random` 时每个切点重新抽一个长度：`[min, max]` 条"可插入指令"，种子 = `splitNameSeed()`
  （`-obf-seed`，否则进程时钟）× 函数名哈希 × 基本块号，用 splitmix64——
  **不消耗 `nextObfRandom()`**，所以垃圾码布局不因这个开关而变（与 S1 名字生成同一约束）。
- 下限 **3** 是实测出来的硬边界，不是拍脑袋：`min=2` 时 demo6 的汇编报
  `conditional branch requires assembler-local label`／`unsupported relocation of local symbol` 共 10 条，
  `min=3` 起 0 条（§8.2）。wbaes 那种大函数上 3–7 也不干净（19 条），5–9 才干净——
  所以**范围要按产物挑**，默认给 3–7（demo6 / demo6_merge4 实测干净）。

## 2. 被测对象与构建命令

```
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp ; S4=demos/ios/demo6_merge4.cpp
WB="demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c"
```

`demos/ios/demo6_merge4.cpp` 是本次新增：demo6 的 Dijkstra 拆成 4 个源函数
（`s4_init` / `s4_pick` / `s4_relax` / `s4_report`），都带 `mergefunction` 注解与 `backend-obfu` 标记，
输出与 demo6 **逐字节相同**。它是"4 个源函数 → 1 个区间"的最小载体；demo6 自己只有一个被混淆函数，
合并对它无事可做，所以 demo6 只用来测正确性、粒度与代价。

```sh
# 全部产物（脚本 demos/ios/reports/build_s4.sh，可重跑）
sh demos/ios/reports/build_s4.sh                 # 默认把 18 个变体写到当前目录

# demo6（合并无事可做 ⇒ 等价于"随机粒度单独上线"）
$CL -O1 $S -mllvm -obf-seed=12345 -o D_base
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols -mllvm -split-symbols-sidecar=d_s1.tsv -o D_S1
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -passes=merge -mllvm -merge-then-split \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=d_s4.tsv \
    -mllvm -split-granularity=random -mllvm -split-chunk-min=3 -mllvm -split-chunk-max=7 -o D_S4
# … 同一条命令换 -obf-seed=777 / 424242 ⇒ D_S4b / D_S4c；去掉 random ⇒ D_S4fixed

# demo6_merge4（真·合并 + 拆分）
$CL -O1 $S4 -mllvm -obf-seed=12345 -o M_base
$CL -O1 $S4 -mllvm -obf-seed=12345 -mllvm -split-symbols -mllvm -split-symbols-sidecar=m_s1.tsv -o M_S1
$CL -O1 $S4 -mllvm -obf-seed=12345 -mllvm -passes=merge -mllvm -merge-then-split \
    -mllvm -merge-scope-sidecar=m_m.tsv -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=m_s4.tsv -mllvm -split-granularity=random \
    -mllvm -split-chunk-min=3 -mllvm -split-chunk-max=7 -o M_S4
$CL -O1 $S4 -mllvm -obf-seed=12345 -mllvm -passes=merge -mllvm -merge-then-split \
    -mllvm -merge-scope-sidecar=m_mfix.tsv -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=m_s4fix.tsv -o M_S4fixed     # 固定粒度（归因测量用）
$CL -O1 $S4 -mllvm -obf-seed=12345 -mllvm -passes=merge -mllvm -merge-then-split \
    -mllvm -merge-scope-sidecar=m_monsplit.tsv -o M_mergeonly  # 只合不拆

# profile B：strip → scrub（顺序不能反，AB §7.1）
cp M_S4 M_S4_B1 && strip M_S4_B1
python3 demos/wbaes/tools/macho_scrub.py --in M_S4_B1 --out M_S4_B2 --seed s4-B --unwind neutralise
```

测量脚本：`demos/ios/reports/s4_measure.py`（区间/归属/run 数）、
`s4_overlap.py`（两次构建的边界偏移 Jaccard）、`ab_measure.py`（profile B gate，未改）。

```sh
python3 demos/ios/reports/s4_measure.py M_S4fixed --sidecar m_s4fix.tsv \
        --merge-scope m_mfix.tsv --baseline M_base
python3 demos/ios/reports/s4_overlap.py D_S4 d_s4.tsv D_S4b d_s4_b.tsv
```

## 3. 正确性（G4 功能面）

| 变体 | 源 | 关键 flag | rc | stdout sha256（前 16） | 行数 |
|---|---|---|---|---|---|
| `D_base` | demo6 | 无 | 0 | `a3a6f0fc7d549bcc` | 9 |
| `D_S1` | demo6 | `-split-symbols` | 0 | `a3a6f0fc7d549bcc` | 9 |
| `D_S4` / `D_S4b` / `D_S4c` | demo6 | + merge + `-merge-then-split` + random 3–7（种子 12345 / 777 / 424242） | 0 | `a3a6f0fc7d549bcc` | 9 |
| `D_S4fixed` | demo6 | 同上但 fixed | 0 | `a3a6f0fc7d549bcc` | 9 |
| `M_base` | demo6_merge4 | 无 | 0 | `a3a6f0fc7d549bcc` | 9 |
| `M_S1` | demo6_merge4 | `-split-symbols` | 0 | `a3a6f0fc7d549bcc` | 9 |
| `M_mergeonly` | demo6_merge4 | `-passes=merge -merge-then-split` | 0 | `a3a6f0fc7d549bcc` | 9 |
| `M_S4` / `M_S4b` / `M_S4c` | demo6_merge4 | 合并 + 拆分 + random 3–7（3 个种子） | 0 | `a3a6f0fc7d549bcc` | 9 |
| `M_S4fixed` | demo6_merge4 | 合并 + 拆分 + fixed | 0 | `a3a6f0fc7d549bcc` | 9 |
| `M_S4_B1` / `M_S4_B2` | demo6_merge4 | 上者再 strip / strip+scrub+unwind | 0 | `a3a6f0fc7d549bcc` | 9 |

即：**4 个源函数合成 1 个之后再拆开，9 行表一个字符都没变**，且表内容与 S1 基线完全相同
（`0/4/12/19/21/11/9/8/14`，`sha a3a6f0fc…`）。这是本次唯一能证明"合并+拆分没有改语义"的硬证据。

## 4. 归因：可见边界还能不能回到源函数

### 4.1 区间与归属（demo6_merge4）

| 变体 | 可见函数符号 | 可见区间 | 区间里的源函数 | chunk 总数 | 带归属的 chunk |
|---|---|---|---|---|---|
| `M_base`（基线） | 5（4 + main） | 5 | 每区间 1 个 | 0 | – |
| `M_S1`（只拆） | 5 + 25 chunk 标签 | 5 | 每区间 1 个 | 25 | – |
| `M_mergeonly`（只合） | **2**（`main` + `__merged_function`） | **1** | **4** | 0 | – |
| `M_S4fixed`（合 + 拆） | `main` + 24 chunk 标签 | **1**（`_main` 覆盖全部） | **4** | **24** | **8** |
| `M_S4`（合 + 拆 + random 3–7，种子 12345） | `main` + 20 chunk 标签 | 1 | 4 | 20 | 2 |
| `M_S4b`（种子 777） | `main` + 20 | 1 | 4 | 20 | 6 |
| `M_S4c`（种子 424242） | `main` + 20 | 1 | 4 | 20 | 6 |

`M_mergeonly` 的 2 个可见起点里，`__merged_function` 一个符号就盖住了 4 个源函数的全部代码；
`M_S4fixed` 里这 4 个源函数又被打散成 24 个 chunk 起点，**没有任何一个可见区间与源函数一一对应**。

### 4.2 每个源函数拿到几个 chunk、散成几段（`M_S4fixed`）

| 源函数 | chunk 数 | chunk 大小（B） | 地址序里的连续段数 |
|---|---|---|---|
| `_Z7s4_initPjPbi` | 2 | 32, 256 | **2** |
| `_Z7s4_pickPjPbPi` | 2 | 32, 136 | **2** |
| `_Z8s4_relaxPA9_jPjPbi` | 2 | 32, 440 | **2** |
| `_Z9s4_reportPj` | 2 | 32, 332 | **2** |
| 合计 | 8（另有 16 个 chunk 属于 `main` / 无归属块） | – | 8 段 / 4 个源函数 |

**每个源函数正好被切成 2 段并与其他源函数的段交错**，所以最省事的攻击——
"一个函数 = 地址上一段连续的 chunk"——**只能拿到 4 个碎片中的 8 段，且段与段之间无法配对**。
`M_S4` / `M_S4b` / `M_S4c` 上同一指标是 1/2/3 个源函数被切碎（随机粒度把合并体的块切得更少）。

### 4.3 名字与顺序里有没有线索

| 检查 | 结果 |
|---|---|
| chunk 名字里含源函数名（或前 6 字符） | **0 / 24**（全部是 `_k` + 12 hex，`makeChunkSymbolName` 不含原名片段） |
| 顺序（地址升序）是否按源函数分块 | 否：4 个源函数都在 2 段，段序交错，无单调性 |
| `LC_FUNCTION_STARTS` 是否点到源函数入口 | **0/10**：合并体内 10 个条件分支目标的地址，**没有一个**是 `LC_FUNCTION_STARTS` 条目，也**没有一个**是 chunk 起点 |

### 4.4 仍然可用的入口预言机（诚实边界）

合并体的分发没有被隐藏：

```
0000000100000bf8   cmp   w0, w8            ; w8 = 某个 case key
0000000100000bfc   mneg  x15, x15, x13     ; （夹在中间的是垃圾指令）
0000000100000c00   b.gt  0x100000d8c       ; → 一个 case 的入口
```

4 个 case key 的比较链 + 直接条件分支 ⇒ 分析者从合并体入口跟 3–4 个 `b.cond` 就能拿到
**4 个源函数的入口地址**。但这些地址既不是符号、也不是 `LC_FUNCTION_STARTS`、也不是 chunk 起点，
所以拿到入口之后**仍然拼不出"哪段代码属于哪个函数"**：区间、长度、归属都缺。

结论落到一句话：**S4 把"区间 ↔ 源函数"的 1:1 打掉了，把"chunk ↔ 源函数"也打掉了；
留下来的只有"有 4 个入口"这件事。** 入口的隐藏是 S2/S3 的活（计算分支 + 去符号），不是 S4 的。

## 5. 粒度：跨构建的签名还剩多少

### 5.1 chunk 数（demo6，同源、只换种子）

| 变体 | 粒度 | `shortestPath` | `main` | 合计 chunk | 可见起点 |
|---|---|---|---|---|---|
| `D_S1` / `D_S4fixed` | fixed（4/8 条） | 12 | 13 | **25** | 27 |
| `D_S4` | random 3–7，种子 12345 | 12 | 13 | 25 | 27 |
| `D_S4b` | random 3–7，种子 777 | 12 | **9** | 21 | 23 |
| `D_S4c` | random 3–7，种子 424242 | **10** | **9** | 19 | 21 |

### 5.2 边界偏移的重合（相对每个函数的第一个 chunk）

| 对比 | `shortestPath` 偏移 Jaccard | `main` 偏移 Jaccard | 平均 | chunk 大小序列相同？ |
|---|---|---|---|---|
| `D_S1` vs `D_S1`（同种子对照） | **1.000** | **1.000** | 1.000 | 是 |
| fixed vs random（同种子 12345） | 0.182 | 0.217 | 0.200 | 否 |
| 种子 12345 vs 777 | 0.182 | 0.143 | 0.162 | 否 |
| 种子 777 vs 424242 | 0.091 | 0.176 | 0.134 | 否 |

**同种子完全可复现（1.000），换种子只剩 0.13–0.16 的重合**——偏移集合里剩下的重合基本是
"第一个 chunk 的偏移 0"加少量巧合。也就是说：**拿另一构建的 (chunk 数, 偏移表, 大小序列)
去认同一个函数，认不出来**。`-obf-seed` 一旦不给，`splitNameSeed()` 取进程时钟，每次构建都不同，
默认行为本身就是跨构建不通用。

### 5.3 每构建的方差从哪来（机制说明）

- 每个切点的长度独立抽样，所以 chunk 的**位置与大小**每构建都变；
- 但**每个 MBB 每次 pass 只切一刀**（`if (DidSplit) break;`，这是原实现的限制：一次迭代里多次
  `splitAt` 会让 Header/Tail 指针失效）。所以 chunk **数量**的方差被这个上限压住了：
  粗函数（`main`）随种子在 9–13 之间抖，细函数（`s4_*`）随种子在 1–2 之间抖。
  想让数量本身也大幅变化，得放开"一块多刀"，那是单独的稳定性工作，本次没做。

## 6. 代价

### 6.1 体积与 `__text`

| 变体 | 文件大小 | 相对基线 | `__text` | 相对基线 |
|---|---|---|---|---|
| `D_base` | 33,640 | – | 3,356 | – |
| `D_S1`（只拆） | 35,064 | **+4.2%** | 3,356 | 0 |
| `D_S4`（+random 3–7） | 35,064 | +4.2% | 3,332 | −24 |
| `D_S4b` / `D_S4c` | 34,856 / 34,744 | +3.6% / +3.3% | 2,936 / 2,964 | −420 / −392 |
| `M_base` | 33,800 | – | 2,812 | – |
| `M_S1`（只拆） | 35,144 | +4.0% | 2,812 | 0 |
| `M_mergeonly`（只合） | 33,560 | **−0.7%** | 3,336 | **+524** |
| `M_S4fixed`（合+拆） | 34,856 | +3.1% | 3,336 | +524 |
| `M_S4` / `M_S4b` / `M_S4c` | 34,632 / 34,616 / 34,616 | +2.5% / +2.4% / +2.4% | 2,784 / 2,888 / 2,832 | −28 / +76 / +20 |
| `M_S4_B1` / `M_S4_B2` | 34,024 / **33,984** | +0.7% / **+0.5%** | 2,784 | −28 |

读法：
- **合并的 `__text` 代价是 +524 B（+18.6%）**：分发链（4 个 case key 的比较）+ 每个调用点多出来的
  实参（`switch` 值 + 被调函数没用到的位置要传 `null`）。`demo6_merge4` 的 4 个函数都很小，
  所以相对占比高；wbaes 那种大函数上这部分会被摊薄（§7）。
- 拆分的 `__text` 是"垃圾区 + X16 重装"的净额，方向随种子/布局变（−420…+524 B），
  它由同一个构建种子驱动，所以**体积本身也在跨构建抖动**——这既是 S4 想要的（签名不通用），
  也意味着"体积增长"要给区间而不是单值。
- 体积大头仍在 `__LINKEDIT`（chunk 标签 16 B/条 + 字符串表），与 S1 相同机制。

### 6.2 每调用耗时（`demos/ios/reports/demo6_bench4.cpp`，3 轮 × 15 进程取中位）

| 变体 | ns / 次调用（中位数的中位数） | 相对基线 | 校验和 |
|---|---|---|---|
| `H_base` | 157.05 | – | 1600032 |
| `H_S1`（只拆） | 160.85 | **+2.4%** | 1600032 |
| `H_S4`（合 + 拆 + random 3–7） | **145.15** | **−7.6%** | 1600032 |
| `H_S4fixed`（合 + 拆） | 140.85 | **−10.3%** | 1600032 |

合并把 4 次真实 `bl`/`ret`（每个都有栈帧、参数搬运）换成一次调用 + 一个分发链，
**净效果是变快**，所以 G4 的 ≤5% 门槛不是"勉强达标"而是"反向达标"。校验和一致说明没有改语义。
注意这是 `-O1`、函数很小、调用密集的最坏情形；真实产物上合并的收益/代价取决于函数大小分布。

### 6.3 profile B（strip + scrub + unwind neutralise）仍然成立

| gate | `M_S4_B2` | `W_S4_B2` |
|---|---|---|
| `LC_FUNCTION_STARTS` 条数 | 20 | 1,440 |
| 其中带符号 | **0** | **0** |
| nlist 定义符号 | 1（`__mh_execute_header`） | 1 |
| 导出表 | **0** | **0** |
| `__unwind_info` 条数 | **0** | **0** |
| 全文件 tell（nlist/exports/strtab/raw） | 0/0/0/0 | 0/0/0/0 |
| `LC_FUNCTION_STARTS` 载荷 vs 未 strip 版本 | **逐字节相同**（`3705267d6cd4c1e2`） | **逐字节相同**（`4a9d8efad919f3c4`） |
| 运行 | rc=0，9 行，`a3a6f0fc…` | （基线本身 SIGTRAP，静态） |

即 **S4 与 profile B 不冲突**：拆出的 chunk 标签被 `strip` 一次清掉，`__unwind_info` 中立化后 0 条，
起点表一个字节都没动。

## 7. wbaes 静态测量

`demos/wbaes/demo_wbaes.cpp` 在本树启动即 SIGTRAP（S1 §9.3 记录的既有问题），所以只做静态测量。

```sh
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla,merge -mllvm -obf-seed=12345 -o W_base
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=w_s1.tsv -o W_S1
# merge 的目标由 policy 文件指定（wbaes 的注解里没有 mergefunction 这个词）
cat wb_policy.json
{ "passes": ["merge"], "targets_mangled": ["_ZNK5WBAES7encryptEPKhPh", "_ZNK5WBAES7decryptEPKhPh"] }
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla,merge -mllvm -obf-seed=12345 \
    -mllvm -policy-file=wb_policy.json -mllvm -merge-then-split \
    -mllvm -merge-scope-sidecar=w_m.tsv -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=w_s4.tsv -mllvm -split-granularity=random \
    -mllvm -split-chunk-min=5 -mllvm -split-chunk-max=9 -o W_S4
```

| | `W_base` | `W_S1` | `W_S4` |
|---|---|---|---|
| 文件 | 151,048 | 236,264 | **211,784** |
| `__text` | 118,168 | 118,168 | **102,052** |
| 可见起点 | 21 | 1,584 | 1,440 |
| chunk 符号 | 0 | 1,584 | 1,440 |
| 合并进 1 个区间的源函数 | – | – | **2**（`encrypt` + `decrypt`） |
| 可见区间 | 19 | 19 | **17** |
| profile B 后名字 / unwind / 起点载荷 | – | AB 表 | **0 / 0 / 不变** |

**这张表有一个必须说清的混杂因素**：`__text` 从 118,168 掉到 102,052（**−13.7%**），
不是 S4 省了代码，而是**合并发生在 `fla` 之前**——合并体是新建函数、不带注解，
于是 `flattening` 不再作用于这两个函数体（S4 直连路径把它们从模块里删掉了）。
也就是说这一行**不是**"S4 的成本"，是"merge 与 fla 在固定 pass 顺序下的相互作用"：

- 想同时要两者，要么把 `merge` 放到 `fla` 之后（`Pipeline.cpp` 的 `Order[]` 是"sub/mba/alias/bcf/merge/fla/…"，
  改顺序会影响所有既有用法，本次没动），要么给合并体继承注解（会改变默认行为，没做）。
- 想只量 S4 的成本，看 `__LINKEDIT`：`W_S4` 比 `W_base` 多 60 KB，全是 1,440 条 chunk 标签
  （16 B/条 + 字符串表），与 `W_S1` 的 85 KB 同源。

**合并在 wbaes 上只覆盖 2 个函数的原因**：MIR 真正拆的两个函数（`enc_core` / `dec_core`）返回 `int`，
而 `merge()` 只吃 void，S4 的直连路径也只对 void 生效。把这两个也塞进 merge 会走老的
"`_internal` + 薄 wrapper"路径，实测 **6/6 次构建直接崩**（§8.1）。所以 wbaes 这一栏是
"合并对 void 函数的真实产物做了一遍"，不是"wbaes 的全部函数都被合并了"。

## 8. 实测到的失败与修复（没有绕过）

### 8.1 原有的 merge 在 void 函数上是坏的（已修，且决定了 S4 走直连）

```
$ clang++ -O1 t1.cpp -mllvm -passes=merge -o t1     # void a(int*) { for(...) p[i]=i; }
clang-16: error: unable to execute command: Killed: 9
```
- 第一处：`process()` 对 void 函数也 `IRB.CreateAlloca(RetType)`，`DataLayout::getAlignment(void)` 直接炸
  （`git stash` 掉本次改动后 100% 复现）。**void 恰好是 `merge()` 唯一接受的形状**，
  所以这个 pass 在其设计目标上从来没成功过。
- 修掉 alloca 之后暴露第二处：`while (!F.empty()) F.front().eraseFromParent();` 这条"掏空函数"的路径
  在**带循环的函数体**上破坏堆（10 次里 4–10 次 `SIGKILL`/`SIGTRAP`，GuardMalloc 下定位到
  `BasicBlock::eraseFromParent`）。同一命令在改动前的二进制上是 0/10 —— 它是本来就存在的潜伏 bug，
  被我加的代码改变了堆布局才稳定暴露。
- 结论：**S4 的 void 直连路径完全不碰这段代码**（不建 `_internal`、不掏空、不重建 entry），
  实测 **0/20 失败**（t1/t2/b_v_loop 三个带循环的样例）。老 wrapper 路径保持原样未动，
  non-void + 循环仍可能偶发（本次测得 1/20），这是既有问题，本文不声称修好。

### 8.2 细粒度会踩 Mach-O 汇编器的 local label 规则

```
min=2 max=8 → 10 条 error: conditional branch requires assembler-local label. 'LBB0_12' is external.
                    error: unsupported relocation of local symbol 'LBB0_21'. Must have non-local symbol earlier in section.
min=3 max=9 → 0 条
```
wbaes 上反过来：`3–7` 出 19 条，`5–9` 与 fixed 各 0 条。原因是切点落得太靠近条件分支终结符时，
被切出来那一块的 `LBB` 标签前面没有非局部符号可定位。**这是拆分本身既有的位置约束**
（固定规则只是恰好没踩到），所以 `-split-chunk-min` 的下限被钳到 3，且范围要按产物实测挑。
它是**构建期硬报错**，不是静默错编——这一点很重要。

### 8.3 merge 与 fla 的先后

见 §7：`Order[]` 里 `merge` 在 `fla` 之前，合并体没有注解 ⇒ 合并后的函数体不再被 flattening 处理。
这是"先合再拆"必须付的结构性代价，本文只测量、不假装解决。

## 9. 判决：断了还是糊了

**断了，但只断在符号层与归属层——这是 S4 的定义域。**

支持"断"的实测：
1. 4 个源函数 → **1 个可见区间**（`M_mergeonly` 2 个起点；`M_S4fixed` 24 个 chunk 起点全部落在 `main` 之后那一个区间里）；
2. 每个源函数的 chunk 被切成 **2 段并与其他函数交错**，所以"连续段 = 函数"这条最省事的复原路径失效；
3. chunk 名 **0/24** 含源函数信息；同一次构建里 24 个名字互不相同；
4. `LC_FUNCTION_STARTS` 与合并体分发目标 **0/10** 重合 —— 即便跟出分发，也拿不到"哪段属于哪个函数"；
5. 粒度跨构建：同种子 1.000、换种子 0.13–0.16 的边界重合，签名不可迁移。

支持"只是糊了"的部分（必须写出来）：
1. **分发链仍是入口清单**：`cmp key / b.cond` 直接给出 4 个 case 目标 ⇒ "这里原本有 4 个函数" 这件事没藏住，
   跟 3–4 条分支就能拿到入口地址；只是入口地址不在任何函数表里。
   要藏它，得让分发本身变成 S2 的计算分支（`-computed-branches` 只转跨 chunk 边，不转 switch 分发）。
2. **chunk 数量与大小分布仍与函数规模相关**：源函数越大，chunk 越多；配合"这段区间里有 24 个 chunk"
   可以估出"里面至少 2–4 个函数"。这是统计信息，不是确定映射。
3. **`_main` 仍是可见符号**：合并体挂在 `main` 之后，区间的起点是已知的。
4. **`__merged_function` 在 profile A 下仍是一个符号**（`M_S4` 里可见），只是不带原名。

因此：**在"每个可见边界能不能映射回一个源函数"这个问题上，答案是"不能"（1 个区间 ↔ 4 个源函数，
chunk 交错且无名）；在"能不能看出这里有几个函数"这个问题上，答案是"能"（分发链）。**
把 S4 当作"破坏 1:1 归属"来用是对的；把它当作"藏住函数数量"来用是错的，那需要 S2+S3 叠加。

## 10. 复现

```sh
CL=src/build/bin/clang++ ; M=demos/ios/reports/s4_measure.py ; O=demos/ios/reports/s4_overlap.py
mkdir -p /tmp/s4 && cd /tmp/s4 && sh <repo>/demos/ios/reports/build_s4.sh

python3 $M M_S4fixed --sidecar m_s4fix.tsv --merge-scope m_mfix.tsv --baseline M_base
python3 $M M_mergeonly --merge-scope m_monsplit.tsv --baseline M_base
python3 $M W_S4 --sidecar w_s4.tsv --merge-scope w_m.tsv --baseline W_base
python3 $O D_S1 d_s1.tsv D_S1 d_s1.tsv        # 对照：同种子 1.000
python3 $O D_S4 d_s4.tsv D_S4b d_s4_b.tsv      # 换种子
python3 demos/ios/reports/ab_measure.py M_S4_B2 --baseline M_base --run
python3 demos/ios/reports/s3_measure.py M_S4_B2 --baseline M_base --same-fnstarts-as M_S4
for f in H_base H_S1 H_S4 H_S4fixed; do ./$f 20000; done    # bench4，见 §6.2
```

`research/hsvm` ctest（改动后跑）：**28/28 Passed**，5.45 s。

## 11. 限制 / 没做的事

1. **merge 只吃 void**（`merge()` 的既有契约）：S4 的直连路径因此只对 void 生效；
   wbaes 的 `enc_core`/`dec_core` 是 `int`，只能走老 wrapper 路径，而那条路径在带循环的函数体上会崩（§8.1）。
   要把 S4 推广到 non-void，需要让 `merge()` 的调用点改写支持"在调用者里分配返回槽"，
   本次没做（改动面在 `merge()` 的核心循环）。
2. **一个 MBB 只切一刀**：chunk **数量**的构建间方差被这个上限压住（§5.3）。
3. **分发链没伪装**（§9 第 1 条）：switch 的分发仍是直接条件分支。
4. **merge 与 fla 的先后**（§8.3）：合并体不再被 flattening 处理，wbaes 的 `__text` 因此 −13.7%，
   这一项不能算成 S4 的收益。
5. **没有 IDA/Ghidra**：本文的"函数"仍是 nlist / `LC_FUNCTION_STARTS` / chunk 标签的条目，
   以及手工跟出的 10 个条件分支目标；不是反汇编器的自动函数识别结果。
6. **只测 Mach-O arm64**；ELF 上 `[split-symbols] only implemented for Mach-O` 会跳过。
7. **合并的 `__text` +524 B 是 demo6_merge4 的小函数场景**，大函数上未测（wbaes 那栏被 fla 混杂掉了）。
8. 部分小函数只有 1–2 个 chunk（`s4_report` 在 `M_S1` 里只有 1 个），所以"chunks per source function"
   这一列的绝对值依赖源函数规模，不能当成常量。
