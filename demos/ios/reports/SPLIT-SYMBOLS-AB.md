# S1+S3 收口：A / B 两条 profile（标签对等 vs 齐平）

> 状态：**已实现并入树**，编译器改动在 `AArch64RubbishCode`（`-mllvm -split-symbols`，默认仍关），
> 工具改动在 `demos/wbaes/tools/macho_scrub.py`。所有数字来自本机实跑
> （macOS 27.3 / arm64，本仓 clang 16.0.6，Xcode 16.4 的 `strip`/`codesign`/`otool`/`nm`）。
> 本机没有 IDA/Ghidra，所以本文只描述**文件里有什么**，不写"IDA 认不出"这类句子。
>
> 前两份：`SPLIT-SYMBOLS.md`（S1 机制）、`SPLIT-SYMBOLS-S3.md`（S3 现状与三个漏洞）。
> 本文要修的就是 S3 §0 里那三条：符号类别的零假阳性探测、导出表死字节、`__unwind_info`。

## 0. 结论先行

**S3 文档里"有名字 ⇒ 真函数"这个 100% 精确的探测器已经关掉了，而且不是靠删标签，是靠把标签放进
同一类别。** A 上实测到：27/27 与 1584/1584 个 `LC_FUNCTION_STARTS` 都带符号，其中真起点
2/2 与 19/19、伪起点 25/25 与 1565/1565，**两类同进同出**；B 上实测到另一头：0/27 与 0/1584，
也是两类同进同出。

| | A（标签对等，保留回溯） | B（齐平，无回溯） |
|---|---|---|
| chunk 标签类别 | `external`（与真函数符号同类） | 全被 `strip` 删掉 |
| demo6 带符号起点 | **27/27**（真 2、伪 25） | **0/27** |
| wbaes 带符号起点 | **1584/1584**（真 19、伪 1565） | **0/1584** |
| `LC_FUNCTION_STARTS` | 27 / 1584（payload 逐字节不变） | 27 / 1584（同） |
| 导出表 | A3（+scrub）0 条；A1/A2 30 / 1601 条（全是标签） | 0 条 |
| `WBAES\|hsvm\|hy_vm\|_ZN` 命中 | A3：0（nlist/exports/strtab/全文件） | 0（含死字节） |
| `__unwind_info` | 4 / 17 条（**真 2/15**，精度 0.50/0.88 —— A 的残留泄漏） | 0 条 |
| 崩溃回溯 | **有名字**（种子名，`k1e361876d075` / `ewr4kc4gzq`） | **无名字**，只剩 imageOffset |
| demo6 输出 | 9 行 Dijkstra 表，stdout sha `a3a6f0fc7d549bcc` | 同左（逐字节相同） |
| 体积（demo6 / wbaes） | 35,024 / 235,040 B | 34,160 / 184,608 B |

**判决：默认发 B，A 作为"需要线上归因时"的可选项。** 理由不是"B 更彻底"这种口号，而是 A 还剩一个
可测的预言机：A 里 `__unwind_info` 仍以 0.88 的精度点名 15 个真函数（§4.2 / §5.2），只要解析 17 条
unwind 表项就能把 1584 个候选收窄到 15 个真的；不修 CFI 就修不掉它（§7.2 给出 MC 的原始报错），
而中立化它会同时拿走回溯——也就是 A 存在的理由。所以 A 只是**中间态**：
把"有名字"这条线索关闭了，但没关闭"结构"这条。详细权衡见 §10。

## 1. 修的三件事（对应任务 A/B）

| 漏洞（S3 §0 原话） | 修法 | 位置 |
|---|---|---|
| chunk 标签是 local，真函数是 external，`-Wl,-x,-S` 之后"有名字"= 真函数（2/27、15/1584，假阳性 0） | 标签用 `.globl` 发（与真函数同类别），并给每个函数入口再发一个种子别名，使"有无名字"与链接类别无关 | `AArch64RubbishCode.cpp` `emitLinkageParityLabel` / `emitEntrySymbol` |
| 完整 strip 后旧导出表的纯字符串还留在文件里（`WBAESTables`/`dec_core` 可被 `strings` 读出） | 按 trie 可达性把不可达字节清零；另把 `__LINKEDIT` 里没有任何 load command 认领的字节清零 | `macho_scrub.py` `zero_trie_slack` / `zero_linkedit_slack` |
| `__unwind_info` 不被 strip/scrub 触碰，仍枚举 15 真 + 2 伪（精度 0.88） | 给 chunk 发 CFI **做不到**（§7.2），改为一并中立化：写成零条目的合法表 | `macho_scrub.py --unwind neutralise` |
| `macho_scrub` 后置条件误杀自己生成的 `_zn…` 名字（S3 实测 2%） | 后置条件改为"原名字精确不残留 + 残留名只按前缀开头匹配"，并豁免本次生成的名字 | `macho_scrub.py` `harden()` |
| scrub 之后不能再 `strip` | 仍是硬失败，但把原因隔离到"导出表改写"这一步，并把支持顺序写进工具文档 | `tools/README.md`、§7.1 |

## 2. 编译器改动

```cpp
// emitLinkageParityLabel(): 每个 chunk 的首条指令前
".globl " + Sym + "\n" + [".no_dead_strip " + Sym + "\n"] + Sym + ":\n"
```

- `.no_dead_strip` 保留原样（去掉它 `ld -dead_strip` 会把 chunk 整段删掉，S1 §1 已测）。
- 先试的路线是任务里点名的 **private extern**：MC 收得下（`AsmParser` 的
  `DK_PRIVATE_EXTERN -> MCSA_PrivateExtern`，`MCMachOStreamer` 里就是 `setPrivateExtern(true)`），
  探针 `a.s` 的 object 里也确实写出来了：

  ```
  $ clang -c a.s -o a.o && nm -m a.o
  0000000000000000 (__TEXT,__text) external _f
  0000000000000000 (__TEXT,__text) private external [no dead strip] _kabc
  ```

  **但链接后就没了**：ld64 对可执行文件把 N_PEXT 定义降级成 non-external，于是 `-x` 照样只删
  chunk、留下真函数——原封不动的那个探测器：

  ```
  $ nm -m P_split | grep '_k0'
  0000000100001114 (__TEXT,__text) non-external (was a private external) _k03f630dba706
  ```

  所以最终用 `.globl`，不用 `.private_extern`，也没有走"改 MCSymbol 属性"那条路（不需要）。
- **函数入口别名** `emitEntrySymbol()`：每个函数入口再发一个 `.globl _k…`。
  理由是实测出来的：只把 chunk 改成 `.globl`、不动真函数时，wbaes 的 `-x` 变体是
  **1580/1584**，而没标签的那 4 个**全是真函数**（它们是 local-linkage 的 static 函数，
  `-x` 把它们的真符号删了，chunk 标签却留下）——等于把探测器翻了个面，变成"没名字 ⇒ 真函数"。
  加上入口别名后是 1584/1584，两面都关掉。
- 别名不带 `.no_dead_strip`：它就在函数自己的 atom 里，`-dead_strip` 删函数时一起走，
  不会把所有函数钉死在产物里（实测 `-Wl,-dead_strip` 变体输出仍是同一张 9 行表）。
- 别名对**未经混淆的函数**也发（`runOnMachineFunction` 里 `checkShouldProcess` 失败的分支），
  否则 wbaes 那 4 个 static 函数根本没被这个 pass 摸到，还是没有标签。

sidecar 新增一种行（`entry<TAB>fn<TAB>sym`），版本号仍是 1，
`s1_measure.py`/`s3_measure.py` 都按记录类型过滤，未知类型会被忽略（实测两者都照常工作）。

## 3. 被测对象

```
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp
WB="demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c"

# demo6
$CL -O1 $S -mllvm -obf-seed=12345 -o D_base
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=d_A1.tsv -o D_A1                       # A1 split only
$CL -O1 $S -Wl,-x,-S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=d_A2.tsv -o D_A2                       # A2 split + (-x,-S)
python3 demos/wbaes/tools/macho_scrub.py --in D_A1 --out D_A3 \
    --seed ab-demo6-A                                                    # A3 split + scrub
cp D_A1 D_B1 && strip D_B1                                               # B1 full strip
python3 demos/wbaes/tools/macho_scrub.py --in D_B1 --out D_B2 \
    --seed ab-demo6-B --unwind neutralise                                # B2

# wbaes（ARMRC_NO_DATAFLOW=1；该 demo 在本树启动即 SIGTRAP，见 S1 §9.3，只做静态测量）
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 -o W_base
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=w_A1.tsv -o W_A1
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=w_A2.tsv -Wl,-x,-S -o W_A2
python3 demos/wbaes/tools/macho_scrub.py --in W_A1 --out W_A3 --seed ab-wbaes-A
cp W_A1 W_B1 && strip W_B1
python3 demos/wbaes/tools/macho_scrub.py --in W_B1 --out W_B2 \
    --seed ab-wbaes-B --unwind neutralise
```

测量脚本：`demos/ios/reports/ab_measure.py`（本任务新增；把 s3_measure 的字段加上"标签按类别拆分"、
"trie 死字节里的可打印串"、"`__LINKEDIT` 未认领字节"）：

```
python3 demos/ios/reports/ab_measure.py D_A1 --baseline D_base --sidecar d_A1.tsv --run
python3 demos/ios/reports/ab_measure.py W_B1 --baseline W_base --sidecar w_A1.tsv
```

## 4. Profile A 测量

### 4.1 demo6（基线 33,640 B，2 个真起点）

| 变体 | 文件 | 起点 | 带符号 | 真/伪 | 标签类别 | 导出 | `__unwind_info` | tells(全文件) | 死 trie 串 | 运行 |
|---|---|---|---|---|---|---|---|---|---|---|
| `D_base` | 33,640 | 2 | 2 | 2 / 0 | external | 3 | 1（真 1） | 0 | 0 | rc=0，9 行 |
| **A1** split | 35,064 | 27 | **27** | **2 / 25** | external | 30 | 4（真 2） | 0 | 0 | rc=0，9 行 |
| **A2** split+(-x,-S) | 35,064 | 27 | **27** | **2 / 25** | external | 30 | 4（真 2） | 0 | 0 | rc=0，9 行 |
| **A3** split+scrub | 35,024 | 27 | **27** | **2 / 25** | external | **0** | 4（真 2） | **0** | 0 | rc=0，9 行 |
| B1 split+strip | 34,200 | 27 | 0 | 0 / 0 | – | 1 | 4（真 2） | 0 | 30 段 | rc=0，9 行 |
| B2 B1+scrub+unwind | 34,160 | 27 | 0 | 0 / 0 | – | 0 | **0** | 0 | **0** | rc=0，9 行 |

demo6 的 `-Wl,-x,-S` 现在**什么也没删**（A1 与 A2 文件大小、nlist、导出表完全相同）：
30 条导出 = 25 个 chunk + 2 个函数名 + 2 个入口别名 + `__mh_execute_header`。

### 4.2 wbaes（基线 151,048 B，19 个真起点、17 条导出）

| 变体 | 文件 | 起点 | 带符号 | 真/伪 | 标签类别 | 导出 | `__unwind_info` | tells(全文件) | 死 trie 串 | 运行 |
|---|---|---|---|---|---|---|---|---|---|---|
| `W_base` | 151,048 | 19 | 19 | 19 / 0 | 15 external + 4 local | 17 | 14（真 14） | 21 | 0 | SIGTRAP（既有） |
| **A1** split | 236,264 | 1,584 | **1,584** | **19 / 1,565** | 19 external（+4 local 重复名） | 1,601 | 17（真 15） | 21 | 0 | SIGTRAP |
| **A2** split+(-x,-S) | 235,720 | 1,584 | **1,584** | **19 / 1,565** | external | 1,601 | 17（真 15） | 18 | 0 | SIGTRAP |
| **A3** split+scrub | 235,040 | 1,584 | **1,584** | **19 / 1,565** | external | **0** | 17（真 15） | **0** | 0 | SIGTRAP |
| B1 split+strip | 185,512 | 1,584 | 0 | 0 / 0 | – | 1 | 17（真 15） | 4 | **1,608 段 / 34,176 B** | SIGTRAP |
| B2 B1+scrub+unwind | 184,608 | 1,584 | 0 | 0 / 0 | – | 0 | **0** | **0** | **0** | SIGTRAP |

demo6 的 `-Wl,-x,-S` 一个符号也没删（nlist 33/30、导出 30、体积 35,064 三项 A1 与 A2 完全相同）。
wbaes 上 `-x` 删了 15 个 local 符号（nlist 1,621 → 1,606），**其中没有一个 chunk 标签**，
1,584 个起点仍然全部有名字。

### 4.3 三态对比：探测器怎么一步步关掉的

| 状态 | demo6 `-x` 带符号 | wbaes `-x` 带符号 | 剩下的判定方式 |
|---|---|---|---|
| S1 原始（local 标签；用改动前的 clang 复现） | 2/27（真 2、伪 0） | 15/1584（真 15、伪 0） | **"有名字" ⇒ 真函数，精度 100%** |
| 第一步：chunk 改 `.globl`（别名还没发给未被混淆的函数） | 27/27（真 2、伪 25） | 1580/1584（伪 1565 全中，4 个真起点无名） | **"没名字" ⇒ 真函数（4/4 真）** ← 反向探测器 |
| 第二步：别名发给**每个**函数（本任务最终态） | 27/27 | **1584/1584** | 无——两类同进同出 |

第一步的两行是分开实测的产物（demo6 用 `G_split`，wbaes 用 `x_strip`，见 §11 复现），不是推导。
wbaes 那 4 个没标签的起点全是 local-linkage 的 static 函数：`-x` 删掉它们的真符号，
而 chunk 标签（external）留下——所以只改 chunk 的类别等于把探测器翻了个面。
第二步的入口别名发到**所有**函数（包括本 pass 不处理的）之后才归零。

同一次构建里两类标签的 `n_type` 完全一致（`N_EXT|N_SECT`，`n_desc=0x0`），
`nm -m` 里两种名字都写作 `external`，只有字母表不同（`__Z…` vs `_k…`）——名字**形状**仍是线索，
这一点只有 A3（scrub 把真名也换种子名）能消掉，A1/A2 不行。

## 5. Profile B 测量（齐平）

### 5.1 gate

| gate | demo6 (`D_B2`) | wbaes (`W_B2`) |
|---|---|---|
| `LC_FUNCTION_STARTS` 条数 | 27 | 1,584 |
| 其中带符号 | **0** | **0** |
| nlist 定义符号 | 1（`__mh_execute_header`，改名成种子名，地址 `0x100000000` 即 Mach-O 头本身，不是起点） | 同名同址 |
| nlist 未定义（libc 导入） | 3（`___stack_chk_fail`/`___stack_chk_guard`/`printf`） | 5（+`arc4random`/`putchar`） |
| 导出表 | **0** | **0** |
| 字符串表里的 tell | **0** | **0** |
| `__cstring` 里的 tell | 0 | 0 |
| 全文件 `WBAES\|hsvm\|hy_vm\|_ZN` 原始字节 | **0** | **0** |
| 死 trie 字节里的可打印串 | **0**（B1 是 30 段，例如 `athPA9_ji`、`6a00c28b662`） | **0**（B1 是 **1,608 段**，例如 `decryptPK7AES_ctxPh`、`ECB_`、`2AES_init_ctxP7AES_ctxPKh`） |
| `__LINKEDIT` 里未认领的非零字节 | 0（B1 也是 0，泄漏全在被认领但不可达的 trie 里） | 0 |
| `__unwind_info` 条数 | **0** | **0** |
| 运行 | **rc=0，9 行 Dijkstra 表，stdout sha `a3a6f0fc7d549bcc`**（与基线逐字节相同） | 基线本身 SIGTRAP（rc=133），静态测量 |

`__mh_execute_header` 是**唯一**残留的定义符号：它由 ld64 以 `N_REFERENCED_DYNAMICALLY`
写进 nlist，`strip` 也保留它，scrub 只是把名字换成种子名。它不在 `LC_FUNCTION_STARTS` 里，
地址是镜像头而不是任何函数，所以它不构成函数名预言机；但"0 个名字"这句严格说应是
"0 个函数名 + 1 个镜像头符号"。

### 5.2 `__unwind_info`：为什么是中立化而不是"按比例"

先把两条路都试了，只有一条成立：

1. **给 chunk 发 CFI —— 做不到。** MC 的 frame 层不接受函数体里再开一个 frame：

   ```
   $ clang -c cfi.s -o cfi.o
   cfi.s:13:2: error: starting new .cfi frame before finishing the previous one
   cfi.s:16:2: error: this directive must appear between .cfi_startproc and .cfi_endproc directives
   ```
   （同一文件里 `_f:` 已经 `.cfi_startproc`，`_kchunk:` 再开一次即报错；与 S1 §1 记的现象一致。）
   `__eh_frame` 在本仓 arm64 产物里根本不存在，所以也没有"另写 FDE"的便宜路。
2. **中立化 —— 做到，并用两项测量确认它没砸东西。**
   `--unwind neutralise` 把 section 写成 `version=1, 0 encodings, 0 personalities,
   indexOffset=28, indexCount=0`，其余字节清零，**size 与 offset 都不变**（不移动任何 load command）：

   | | B1（strip 完，未中立化） | B2（中立化后） |
   |---|---|---|
   | unwind 表项 | 17（真 15、伪 2，精度 0.88） | **0** |
   | 崩溃帧 | 4 帧、无名字 | 4 帧、无名字（**帧还在，只是没名字**） |
   | 进程 | 正常启动 | 正常启动（demo6 rc=0、9 行输出） |

   代价与预期有出入，必须写清楚：**帧没有丢**。同一次故障（`demo6_crash.cpp`，
   `CRASH=1`，同一地址 `imageOffset 2248`）在 B1/B2 上都拿到 4 帧
   （2248 / 2220 / 2944 / dyld `start`），B2 只是**全部没有符号**（`symbol: null`）。
   即：这台机器上崩溃报告器在没有 compact unwind 时仍能走完这段栈（代码有帧指针），
   所以 B 的代价是"归因归零"，不是"连栈都没有"。这个结论对 `-O2` 去掉帧指针的正式产物
   **不保证**，届时可能连帧都拿不到——这一点没有测，不能写成结论。

## 6. Profile A 的崩溃回溯

`demo6_crash.cpp`（本次新增，`shortestPath` 里加一行 `if (getenv("CRASH")) *(volatile int*)0 = 1;`）
逐变体链接、**每个副本先随机化 `LC_UUID` 再重签**（否则命中系统符号缓存，S3 §5 记过这个坑），
`CRASH=1` 跑，读 `~/Library/Logs/DiagnosticReports/*.ips` 的 faulting thread：

| 变体 | 出错帧 | 同栈第 2 帧 | 调用者帧 |
|---|---|---|---|
| `C_base`（无 S1） | `shortestPath(unsigned int (*) [9], int) + 992` | 同函数 + 964 | `main + 24` |
| **A1** split | `k1e361876d075 + 84` | `k1e361876d075 + 56` | `k57e32c435e69 + 24` |
| **A2** split+(-x,-S) | `k1e361876d075 + 84` | 同上 | `k57e32c435e69 + 24` |
| **A3** split+scrub | `ewr4kc4gzq + 84` | 同上 | `x5tvsnlzpk + 24` |
| B1 split+strip | **无符号**（`imageOffset 2248`） | 无符号 | 无符号 |
| B2 +scrub+unwind | **无符号** | 无符号 | 无符号 |

A 的三条都**认得出名字**，但名字全是种子名——包括 `main`，因为入口别名和真符号同址，
符号化器取到的是别名。这是 A 的成本：线上能归因到"某个地址 + 某个函数区间"，但这个函数名
对人不含信息（要还原得用 sidecar 或 dSYM）。B 则完全没有名字。

探针的构建（与 §3 同参数，只换源文件；`C_base` 用不带 `-split-symbols` 的那条）：

```sh
CR=demos/ios/reports/demo6_crash.cpp
$CL -O1 $CR -mllvm -obf-seed=12345 -o C_base
$CL -O1 $CR -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=c_A1.tsv -o C_A1
$CL -O1 $CR -Wl,-x,-S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=c_A2.tsv -o C_A2
python3 demos/wbaes/tools/macho_scrub.py --in C_A1 --out C_A3 --seed ab-crash-A
cp C_A1 C_B1 && strip C_B1
python3 demos/wbaes/tools/macho_scrub.py --in C_B1 --out C_B2 \
    --seed ab-crash-B --unwind neutralise
```

## 7. 失败的机制（原始命令与报错，没有绕过）

### 7.1 scrub 之后仍然不能 `strip`

```
$ cp D_A3 /tmp/after_scrub_bin && strip /tmp/after_scrub_bin
/Applications/Xcode16.4.app/.../strip: fatal error: file not in an order that can be processed
        (function starts data out of place): /private/tmp/after_scrub_bin
$ echo $?
1
```

隔离到具体一步（对 `D_A1` 逐项施加，然后各自 `strip`）：

| 只做这一步 | `strip` 结果 |
|---|---|
| 改写导出表为空 trie（`scrub_exports`） | **rc=1**（同上报错） |
| 清零死 trie 字节（`zero_trie_slack`） | rc=0 |
| 清零未认领的 `__LINKEDIT` 字节（`zero_linkedit_slack`） | rc=0 |
| `__unwind_info` 中立化 | rc=0 |
| 改符号表/字符串表 + 保留导出表（`--exports keep`） | rc=0（只印一条签名失效警告） |

所以触发条件是**导出表被改写**（datasize 变了），至此不再猜 ld64 内部实现。
支持的顺序是 **strip → scrub**，B 就是按这个顺序做的；反过来**不支持**，命令与报错如上。
（也试过"保留原 datasize、只把内容清空"，同样 rc=1，所以不是 datasize 变小的问题。）

### 7.2 递归 CFI 被 MC 拒绝

见 §5.2 的原始报错。

## 8. `macho_scrub` 后置条件修复

旧检查对整个字符串表做 `WBAES|hsvm|hy_vm|wbaes|hytab|_ZN|_ZNK` 的**不分大小写、不锚定**搜索，
于是自己生成的 base32 名字里出现 `zn` 就自爆。S3 在 17 个名字时实测 2%；
现在 S1 的 chunk 标签把这个表撑到 **1,616 个定义名**，命中率按名字数线性放大：

```
# 用工具自己的 seeded_name 采样 200 个 seed，模拟旧检查 / 新检查
old unanchored check rejects 151/200 seeds
new anchored+exempt check rejects 0/200 seeds
first old rejection: ('seed-0', ['_znz5tfodcf', '_znjft63dd5'])
```

即 **75.5% 的构建会被自己的后置条件拒绝**（旧检查），不是 2%。新检查两条：
(1) 改写前存在的原名字，一个都不许留在新字符串表里（按名字精确比对）；
(2) 残留名字只有**开头**是 tell 前缀才算泄漏，且豁免本次生成的名字。

验证：

```
$ python3 demos/wbaes/tools/macho_scrub.py --in W_A1 --out /tmp/seed0 --seed seed-0
...
symbols dropped : 15
$ echo $?
0
```
```
# 负向对照：故意漏改一个名字，检查必须报错
$ python3 - <<'EOF' (把 seeded_name 对 __ZN5WBAES8enc_core… 原样返回)
rejected as designed: original name(s) survived in the string table:
                       __ZN5WBAES8enc_coreERK11WBAESTablesS2_PKhPh
EOF
```

## 9. 体积、耗时、代码不变性

| | demo6 | wbaes |
|---|---|---|
| 基线 | 33,640 B | 151,048 B |
| A1 / A2 / A3 | 35,064 / 35,064 / 35,024 B（+4.2% / +4.2% / +4.1%） | 236,264 / 235,720 / 235,040 B（+56.4% / +56.1% / +55.6%） |
| B1 / B2 | 34,200 / 34,160 B（+1.7% / +1.5%） | 185,512 / 184,608 B（+22.8% / +22.2%） |
| `__text` 差异 | **2 字节**（都在 `.byte` 垃圾填充里，见下） | **0 字节**（118,168 B 逐字节相同） |
| `LC_FUNCTION_STARTS` payload | `cf8bc917396450a3`，5 个变体全同 | `5aac0df7d6ea23a5`，5 个变体全同 |
| `strip` / `scrub` 墙钟 | – | 14.7 ms / 44.2 ms |
| 进程（40 次中位） | 1.46–1.60 ms，6 个变体 stdout sha 全是 `a3a6f0fc7d549bcc` | SIGTRAP（既有） |

demo6 那 2 个字节是 `.byte` 垃圾块的寄存器字段：`ror w2, w2, w16` vs `w8`（0x86c）、
`asr w6, w6, w16` vs `w8`（0xb98），紧邻 `brk #1` 的永不执行区域——入口别名让
`nextObfRandom` 的抽取位置挪了一格。wbaes 侧 0 差异，说明真实指令没有被改动。

wbaes B2 那 +33.5 KB 要说清：`__LINKEDIT` 里旧 trie 的 34,176 B 区域现在**全是零**
（datasize 已是 2，后面的函数起点/symtab/签名仍按 S1 的布局留在原位），
也就是**零填充，不是名字**。要回收得重排 `__LINKEDIT` 并截断，本次没做（§12）。

## 10. 判决：默认发哪条

按代价/收益逐条算，结论是**默认发 B，A3 作为"必须保留线上归因"时的选项**。

支持 B 作为默认：

- A 只关掉了"符号层"的预言机。A 的 `__unwind_info` 仍以 0.88 的精度点名 15 个真函数
  （§4.2：17 条里 15 真、2 伪）——分析者不需要碰符号表，解析 17 条表项就能把 1584 个候选
  收窄到 15 个真的，剩下的 2 个伪项用 `LC_FUNCTION_STARTS` 一比就掉。**S1 的 83× 收益在 A 下
  被这张表兑回去一半以上**，而这张表只有 CFI 能"按比例"化（MC 拒绝，§5.2）。
- B 把三张表（nlist / exports / strtab）、死字节、unwind 一次清零，gate 全部达标（§5.1），
  并且 demo6 仍然跑出同一张 9 行表（stdout sha 与基线逐字节相同）。
- B 的代价比预期小：中立化 unwind 之后崩溃**帧还在**（2248/2220/2944 三帧 + dyld），
  只是没有名字；也就是说 B 牺牲的是归因，不是栈本身。体积 +1.5%（demo6）/ +22.2%（wbaes，
  其中 34,176 B 是零填充，可回收）。

支持保留 A（作为选项）的理由：

- A 有名字（种子名），线上崩溃还能落到"某个地址区间"，还能用 sidecar/dSYM 还原；
  B 完全没有这个能力。
- A 不需要 `strip`，所以不踩 §7.1 的顺序约束；在必须保留 `LC_FUNCTION_STARTS` 之外的元数据
  （或要跑 `strip -S` 的发布流水线）时，A 是唯一能组合的一条。
- A3（split + scrub）已经把名字语义、导出表、以及"有名字 ⇒ 真函数"一起处理掉，
  是"只修符号层"能做到的最强状态。

不推荐：A1/A2 单独发（名字形状 `__Z…` vs `_k…` 仍是线索）；B1（strip 完不 scrub，
1,608 段死 trie 字符串把旧名字拼回去读）。

## 11. 复现（全部命令）

```sh
CL=src/build/bin/clang++ ; M=demos/ios/reports/ab_measure.py
S=demos/ios/demo6_mir_noeh.cpp ; WB="demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c"
```

构建命令见 §3（demo6 与 wbaes 各 6 条，全部）与 §6（崩溃探针的 6 条）。§4.3 第一步的两个中间产物：

```sh
# 只有 .globl、别名还没发给未被混淆的函数（demo6 的 2 个函数都被混淆，所以这版就是 27/27）
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=g.tsv -o G_split
# wbaes 同一状态 + -x：1580/1584，缺的 4 个是未被混淆的 static 函数
ARMRC_NO_DATAFLOW=1 $CL -O2 $WB -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=x.tsv -Wl,-x,-S -o x_strip
```

以下是测量：

```sh
python3 $M D_A1 --baseline D_base --sidecar d_A1.tsv --run
python3 $M D_A2 --baseline D_base --sidecar d_A2.tsv --run
python3 $M D_A3 --baseline D_base --sidecar d_A3.tsv --run
python3 $M D_B1 --baseline D_base --run
python3 $M D_B2 --baseline D_base --run
python3 $M W_A1 --baseline W_base --sidecar w_A1.tsv
python3 $M W_A2 --baseline W_base --sidecar w_A2.tsv
python3 $M W_A3 --baseline W_base --sidecar w_A3.tsv
python3 $M W_B1 --baseline W_base
python3 $M W_B2 --baseline W_base

# 起点表没被动过
python3 demos/ios/reports/s3_measure.py D_B2 --baseline D_base --same-fnstarts-as D_A1

# 崩溃回溯（必须换 UUID）
python3 demos/ios/reports/s3_measure.py --reuuid C_A3 --out /tmp/U_C_A3 && CRASH=1 /tmp/U_C_A3
# 读 ~/Library/Logs/DiagnosticReports/U_C_A3-*.ips

# 后置条件回归（200 个 seed 的采样脚本见 §8，命令就是那 6 行）
python3 demos/wbaes/tools/macho_scrub.py --in W_A1 --out /tmp/seed0 --seed seed-0

# 失败的顺序
cp D_A3 /tmp/after_scrub_bin && strip /tmp/after_scrub_bin     # rc=1，报错见 §7.1
```

`research/hsvm` ctest（编译器改动后跑）：`28/28 Passed`，5.26 s。

## 12. 限制 / 没做的事

1. **A 的 `__unwind_info` 仍是 0.88 精度的真函数清单**（17 条里 15 真）。要么发 CFI（MC 拒绝，
   §5.2），要么中立化（那就变成 B）。这是 A 与 B 之间唯一不可同时满足的约束，本文不假装解决它。
2. **A1/A2 的名字形状仍是线索**（`__Z12shortestPath…` vs `_k1ee2b…`）。要消掉必须跑 scrub（A3）。
3. **B 的体积没有回收**：wbaes B2 里 34,176 B 的零填充可以靠重排 `__LINKEDIT` 收掉，未做。
4. **B 的 unwinding 在 `-O2` 无帧指针产物上没有验证**：本文的崩溃探针是 `-O1`，走帧指针成功了；
   正式产物可能连帧都拿不到。
5. **wbaes 仍无法运行**（SIGTRAP，基线也一样，S1 §9.3 记过），所以 B 的"还能跑"只在 demo6 上验证。
6. 只用 Mach-O arm64；ELF 未测（`[split-symbols] only implemented for Mach-O` 会打印并跳过）。
7. 没有 IDA/Ghidra，所有"函数"都是 `LC_FUNCTION_STARTS` 与 nlist 的条目，不是反汇编器的函数识别结果。
