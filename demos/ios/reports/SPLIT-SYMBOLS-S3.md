# S3 落地：去符号之后，真函数边界还认得出来吗

> 状态：**已测量，已入树**（`demos/ios/reports/s3_measure.py` + 本文）。机制侧没有新编译器代码：
> S3 就是 S1 产物再加一道链接期/链接后的符号处理。所有数字来自本机实跑
> （macOS 26/arm64，本仓 clang 16.0.6，`ld64` + Xcode 16.4 `strip`/`codesign`）。
> 本文只描述**文件里有什么**；本机没有 IDA/Ghidra，所以不写"IDA 认不出"这类句子。
>
> 上一份：`SPLIT-SYMBOLS.md`（S1）。路线图：`../MIR-SPLIT-STRENGTHENING.md`（S3 一节）。

## 0. 结论先行

1. **S1 与 S3 不抵消。** `LC_FUNCTION_STARTS` 在 (a) `-Wl,-x,-S` 和 (b) `macho_scrub`
   之后都完整存活：demo6 27 条、wbaes 1584 条，**payload 与 S1 产物逐字节相同**
   （sha256 前缀 `cf8bc917396450a3` / `5aac0df7d6ea23a5`，`dataoff` 也没动）。
   原因是这张表由 ld64 在链接时按 atom 地址写出，之后 strip/scrub 只改 `LC_SYMTAB` 与
   导出表，不碰它。**所以"去符号把 S1 修的边界也一起删掉"这件事没有发生。**
2. **但 (a) 与 (b) 都不是"齐平无标签"。** 两者都只删 local 符号，external 定义仍在：
   - (a) 之后，27 个起点里只有 2 个带符号，1584 个里只有 15 个——**带符号的那些全是真函数**
     （`labelled_forged = 0`），且这 2/15 个名字仍是原始 C++ 名，还留在导出表里带地址。
     对"藏起真边界"来说这比 S1 更糟：符号表变成了 **100% 精确的真函数探测器**。
   - (b) 之后同样只剩 2/15 个带符号的起点，但这 2/15 个名字换成了种子名
     （`_di7wfzxkiw` 之类）。语义不再泄露，**"有没有名字"本身仍是标签**。
3. **只有"完整 strip"（不带 `-x`，连 external 一起删）才得到"多等候选、零标签"**：
   27/27 与 1584/1584 个起点全部无符号，导出表只剩 `__mh_execute_header`。
   这是 S3 想要的终态，代价是崩溃回溯归零（§5）。
4. **结构没有被完全销毁：`__unwind_info` 还站在那里。** 它既不被 strip 也不被 scrub 改动，
   仍枚举 4（demo6）/ 17（wbaes）个地址，其中 2 / 15 是真函数起点
   （精度 0.50 / 0.88）——因为 S1 只发符号、不发 CFI，25 个 chunk 里只有 2 个顺带拿到 unwind 表项。
   所以"齐平"只在 `LC_FUNCTION_STARTS` 这一层成立；在 unwind 这一层真函数仍被单独挑出来。
5. **组合顺序有硬约束**：先 `-Wl,-x,-S` 再 scrub 可以；先 scrub 再 `strip` **直接失败**
   （§7.2 的原始报错）。也就是说 (a)(b) 不是可交换的两步。

一句话判决：**S1+S3（按 S3 文档原意的 (a)/(b)）留下的是"许多等价候选 + 两个（或十五个）被
点名的真函数"，不是"齐平无标签"；(a) 甚至把真函数指得更清楚。只有完整 strip 才到
"多等候选、无标签"，而那时分析者手上仍有 unwind 表可以按 0.88 的精度把真函数挑出来，
并且线上崩溃归因变成零。**

## 1. 被测对象与三个变体

S1 产物为基准，只在链接期/链接后加处理，源码与 `__text` 不动（实测：所有变体
`__text` sha256 与 S1 产物相同，`__sections` 表逐项相同）。

| 变体 | 怎么来的 |
|---|---|
| `split only` | S1：`-mllvm -split-symbols`（+ sidecar） |
| `split+strip` | 再加 `-Wl,-x,-S`（本地符号与 debug map 丢弃） |
| `split+scrub` | `split only` → `tools/macho_scrub.py`（local 丢弃、external 改种子名、导出表清空、重签） |
| `split+strip+scrub` | 先 `-Wl,-x,-S`，再 `macho_scrub.py`（唯一能组合成功的顺序） |
| `split+fullstrip` | `cp` 之后 `strip`（不带 `-x`：连 external 一起删）——对照组 |

```
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp

$CL -O1 $S -mllvm -obf-seed=12345 -o B_mir
$CL -O1 $S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=chunks.tsv -o C_sym                  # S1
$CL -O1 $S -Wl,-x,-S -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=chunks2.tsv -o C_sym_strip          # (a)
python3 demos/wbaes/tools/macho_scrub.py --in C_sym --out C_sym_scrub \
    --seed s3-demo6-2026-11-18                                        # (b)
cp C_sym C_sym_fullstrip && strip C_sym_fullstrip                     # 对照
python3 demos/wbaes/tools/macho_scrub.py --in C_sym_strip \
    --out C_sym_strip_scrub --seed s3-demo6-2026-11-18b               # (a)+(b)
```

真混淆产物（S1 §3 的 `W_cf` 家族，`ARMRC_NO_DATAFLOW=1`，只做静态测量——该 `-O2` 构建
在本树启动即 SIGTRAP，与本改动无关，见 `SPLIT-SYMBOLS.md` §9.3）：

```
ARMRC_NO_DATAFLOW=1 $CL -O2 demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c \
    -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 [-Wl,-x,-S] \
    [-mllvm -split-symbols -mllvm -split-symbols-sidecar=wb.tsv] -o W_cf_sym[_strip]
```

## 2. 中心问题：`LC_FUNCTION_STARTS` 还在不在

`python3 demos/ios/reports/s3_measure.py <bin> --baseline <bin> [--sidecar]`

demo6（基线 33,640 B，2 个真函数起点）：

| 变体 | `LC_FUNCTION_STARTS` | 其中带符号 | payload sha256 | dataoff/size |
|---|---|---|---|---|
| `B_mir`（无 S1） | 2 | 2 | `77ead975d8b33804` | 32992 / 40 |
| `split only` | **27** | 27 | `cf8bc917396450a3` | 32992 / 40 |
| `split+strip` (a) | **27** | **2** | `cf8bc917396450a3` | 32992 / 40 |
| `split+scrub` (b) | **27** | **2** | `cf8bc917396450a3` | 32992 / 40 |
| `split+fullstrip` | **27** | **0** | `cf8bc917396450a3` | 32992 / 40 |
| `split+strip+scrub` | **27** | **2** | `cf8bc917396450a3` | 32992 / 40 |

wbaes（基线 151,048 B，19 个真函数起点）：

| 变体 | `LC_FUNCTION_STARTS` | 其中带符号 | payload sha256 | dataoff/size |
|---|---|---|---|---|
| `W_cf`（无 S1） | 19 | 19 | `2530ccbd6bcf8ef9` | 148208 / 1880 |
| `split only` | **1584** | 1584 | `5aac0df7d6ea23a5` | 148208 / 1880 |
| `split+strip` (a) | **1584** | **15** | `5aac0df7d6ea23a5` | 148208 / 1880 |
| `split+scrub` (b) | **1584** | **15** | `5aac0df7d6ea23a5` | 148208 / 1880 |
| `split+fullstrip` | **1584** | **0** | `5aac0df7d6ea23a5` | 148208 / 1880 |
| `split+strip+scrub` | **1584** | **15** | `5aac0df7d6ea23a5` | 148208 / 1880 |

27 条 / 1584 条全部落在 `__text` 内、全部 4 字节对齐（`s3_measure.py` 的
`function_starts_4B_aligned` = 27/27 与 1584/1584）。

**答案： survives，而且是逐字节 survives。** 去符号删的是 `LC_SYMTAB` 的条目和字符串表，
不是这张表；(b) 连 `LC_SYMTAB` 的布局都重排了，payload 依然一个字节没变。

## 3. 边界歧义度：候选里有多少真起点，分析者拿什么区分

ground truth = 同一构建关掉 `-split-symbols` 时的起点集合（`--baseline`），与 sidecar 的
chunk 名一起用。`labelled_*` = 该起点在 nlist 里有符号。

demo6：

| 变体 | 候选起点 | 真 | 假 | 真占比 | 带符号(真/假) | 无符号 | 分析者的区分依据 |
|---|---|---|---|---|---|---|---|
| `split only` | 27 | 2 | 25 | 0.074 | 2 / 25 | 0 | 名字形状：`__Z12shortestPathPA9_ji` vs `_k1ee2b55640e5` ⇒ 2 个真函数一眼可辨 |
| `split+strip` (a) | 27 | 2 | 25 | 0.074 | 2 / 0 | 25 | **"有名字"⇒ 真函数**（精度 100%）+ 导出表里还有原名和地址 |
| `split+scrub` (b) | 27 | 2 | 25 | 0.074 | 2 / 0 | 25 | **"有名字"⇒ 真函数**（名字语义已丢，`_di7wfzxkiw`） |
| `split+fullstrip` | 27 | 2 | 25 | 0.074 | 0 / 0 | 27 | 无标签：27 个等价候选 |
| `split+strip+scrub` | 27 | 2 | 25 | 0.074 | 2 / 0 | 25 | 同 (b) |

wbaes：

| 变体 | 候选起点 | 真 | 假 | 真占比 | 带符号(真/假) | 无符号 | 分析者的区分依据 |
|---|---|---|---|---|---|---|---|
| `split only` | 1584 | 19 | 1565 | 0.012 | 19 / 1565 | 0 | 名字形状（`_ZN5WBAES…` vs `_k…`）+ 导出表原名 |
| `split+strip` (a) | 1584 | 19 | 1565 | 0.012 | 15 / 0 | 1569 | **"有名字"⇒ 真函数**；导出表 17 个原名+地址 |
| `split+scrub` (b) | 1584 | 19 | 1565 | 0.012 | 15 / 0 | 1569 | 同左，名字换成种子名 |
| `split+fullstrip` | 1584 | 19 | 1565 | 0.012 | 0 / 0 | 1584 | 无标签：1584 个等价候选 |
| `split+strip+scrub` | 1584 | 19 | 1565 | 0.012 | 15 / 0 | 1569 | 同 (b) |

两点必须写清楚：

- **`labelled_forged` 在 (a)(b) 里是 0。** 也就是说，"起点有没有名字"在这两个变体里是
  一个**零假阳性的真函数判定器**。S1 至少让真假边界都带名字（虽然名字形状不同），
  (a)/(b) 把假边界的名字删干净、真边界的名字留着，等于替分析者做完了筛选。
- `fullstrip` 的 2 / 15 个真起点没有符号、其余也无符号 ⇒ 分析者手上就是
  "1584 个候选、0 个标签、19 个是真的（1.2%）"。这正是任务里问的
  "many equal candidates, no labels"——但它是**完整 strip** 带来的，不是 `-Wl,-x,-S`。

### 3.1 还有一张表没被处理：`__unwind_info`

这是本次测量里最需要注意的一条。`s3_measure.py` 解析紧凑 unwind 表
（一级索引 → 二级页 → 压缩条目，24 位函数偏移 + 8 位编码索引）：

| 变体 | `__unwind_info` 枚举的地址 | 其中真起点 | 其中非真起点 | 精度 |
|---|---|---|---|---|
| `B_mir` | 1 | 1 | 0 | 1.00 |
| `C_sym`（S1） | 4 | 2 | 2 | 0.50 |
| `C_sym_strip` / `_scrub` / `_fullstrip` / `_strip_scrub` | 4（同上，逐字节不变） | 2 | 2 | 0.50 |
| `W_cf` | 14 | 14 | 0 | 1.00 |
| `W_cf_sym`（S1） | 17 | 15 | 2 | 0.88 |
| `W_cf_sym_strip` / `_scrub` / `_fullstrip` / `_strip_scrub` | 17（同上） | 15 | 2 | 0.88 |

demo6 的 4 条是 `0x1000004e8`（真，`shortestPath`）、`0x100000540`（**chunk**）、
`0x100000b30`（真，`main`）、`0x100000b88`（chunk）；wbaes 的 17 条里 15 条是真函数
（`enc_gate`/`enc_core`/`init`/`encrypt`/`decrypt`/`main`/8 个 AES 函数），2 条是 chunk。

所以 S1 说的"ld64 为新增的函数起点补了 `__unwind_info` 表项"在数量上不成立：
`__unwind_info` 从 88 → 104 B（+16 B），表项从 1 → 4；25 个 chunk 里**只有 2 个**拿到表项，
1565 个里也只有 2 个。S1 不发 CFI，unwind 表就基本只认识真函数。这给了分析者一个
**0.88 精度的边界预言机**，而且它不依赖任何名字表，strip 与 scrub 都不碰它。

**这就是"结构没被销毁"的具体位置。** 要让真边界真正混进假边界，S1 必须给每个 chunk 发
CFI（`MIR-SPLIT-STRENGTHENING.md` §2 S1 里写了为什么没做：inline asm 里嵌
`.cfi_startproc` 与函数自身的冲突），否则 unwind 表永远是"真函数清单"。

## 4. 名字泄漏（`WBAES|hsvm|hy_vm|_ZN`）

`macho_symbols.py` 的符号表 / 导出表 / 字符串表三处 + `__cstring` + 全文件原始字节：

| 变体 | symbols | exports | strtab | `__cstring` | 全文件命中字节 |
|---|---|---|---|---|---|
| `C_sym*`（demo6，全部变体） | 0 | 0 | 0 | 0 | 0 |
| `W_cf`（基线） | 9 | 6 | 9 | 0 | 21 |
| `W_cf_sym`（S1） | 9 | 6 | 9 | 0 | 21 |
| `W_cf_sym_strip` (a) | 6 | **6** | 6 | 0 | 18 |
| `W_cf_sym_scrub` (b) | **0** | **0** | **0** | 0 | **0** |
| `W_cf_sym_strip_scrub` | **0** | **0** | **0** | 0 | **0** |
| `W_cf_sym_fullstrip` | **0** | **0** | **0** | 0 | **4** |

demo6 本身不含 WBAES 名字，所以它在每个变体上都是 0，说明不了 S3 的效果；判断要看 wbaes。

- **(a) 不满足 0 命中，而且是三条里最差的**：`-x` 只删 local，导出表原封不动，
  17 条导出里 6 条是 tell 名，**并且带地址**：

  ```
  __ZN5WBAES8enc_gateEv                       0x100000580
  __ZN5WBAES8enc_coreERK11WBAESTablesS2_PKhPh 0x10000058c
  __ZN5WBAES4initEv                           0x10000c070
  __ZNK5WBAES7encryptEPKhPh                   0x10000c074
  __ZN5WBAES8dec_coreERK11WBAESTablesS2_PKhPh 0x10000ce80
  __ZNK5WBAES7decryptEPKhPh                   0x10001b9f8
  ```

  加上删掉的 1565 个 chunk 名，(a) 让导出表变成一份**更干净的真函数索引**：
  只剩 17 条，条条是真入口。这正是 `EXPORT-HARDENING.md` 记的那个坑的反向版本——
  那里是"改了符号表没清导出表"，这里是"删了符号表却靠导出表把名字全留下"。
- **(b) 与 (a)+(b) 满足 0 命中**（symbols/exports/strtab/`__cstring`/全文件全 0）。
  `macho_scrub` 的做法（trie 改写成 2 字节空 trie + 旧区域清零 + 字符串表重建后清空）
  是唯一把三张表都清干净的路。
- **完整 strip 不满足"全文件 0 命中"**：三张表是 0，但文件里还剩 4 个 tell 字节——
  旧的导出表内容以纯字符串形式留在 `__LINKEDIT`（0x24202–0x24298，`LC_DYLD_EXPORTS_TRIE`
  的 584 字节区域内）。`strip` 把 trie 根节点改写成了只剩 `__mh_execute_header`，
  **旧名字的节点结构被覆盖、无法再解析出地址**（实测：从 dataoff 起按 584/700/900 字节
  强行解析都只得到 1 条 `__mh_execute_header`），但 `WBAESTables`/`dec_core`/`enc_core`
  这些字符串还能被 `strings` 读出来。即：**名字在、地址不在**。要清干净仍需 (b)。

## 5. 还能跑吗，崩溃回溯还认得出什么

**运行**：demo6 的 6 个变体全部 `rc=0`、输出 9 行 Dijkstra 表、stdout sha256 全为
`a3a6f0fc7d549bcc`（与 `B_mir` 逐字节相同）。wbaes 全部 `rc=-5`（SIGTRAP，
既有问题，`SPLIT-SYMBOLS.md` §9.3 已记，与 S1/S3 都无关）。

**崩溃回溯**：在 demo6 上加了 `demo6_crash.cpp`（scratch 探针：在 `shortestPath` 的松弛循环里
`if (getenv("CRASH")) *(volatile int*)0 = 1;`），每种处理各链接一次，`CRASH=1` 跑，
读系统 crash report（`~/Library/Logs/DiagnosticReports/*.ips`）的 faulting thread。
**探针副本的 `LC_UUID` 都随机化了再重签**，否则系统会按 UUID 命中符号缓存
（实测过这个坑：同一 UUID 的 stripped 副本仍能解析出已经不在文件里的名字）。

| 变体 | 出错帧 | 调用者帧 |
|---|---|---|
| `plain`（无 S1） | `shortestPath(unsigned int (*) [9], int) + 808` | `main + 52` |
| `split only`（S1） | `k97202718bc53 + 92`（假 chunk 名） | `main + 52` |
| `split+strip` (a) | **无符号**（只有 imageOffset 2216） | `main + 52` |
| `split+scrub` (b) | **无符号** | `6wa4pvxm5e + 52`（种子名） |
| `split+strip+scrub` | **无符号** | `meh5ydndix + 52`（种子名） |
| `split+fullstrip` | **无符号** | **无符号** |

所以：

- **S1 之后回溯"还能用"，但指错了**——它给你一个假函数名（`k97202718bc53 + 92`），
  这是欺骗效果，也是线上归因变难的成本。
- **(a)/(b) 之后出错帧直接没有名字**，只剩 `imageOffset`。要靠 dSYM 才能回到源码行，
  而 dSYM 在没有符号的产物上是空的。调用者帧还在 (a) 里叫 `main`（external 没删），
  在 (b) 里叫种子名。
- **完整 strip 之后整个调用栈都没有名字**（连 `main` 也没了）。
- 这是**成本，不是收益**：Verdict 里必须算进去。

## 6. 体积与耗时

| | demo6 | wbaes |
|---|---|---|
| 基线 | 33,640 B | 151,048 B |
| `split only`（S1） | 34,440 B（+800，+2.4%） | 201,800 B（+50,752，+33.6%） |
| `split+strip` (a) | 33,672 B（−768 vs S1，+32 vs 基线） | 152,368 B（−49,432 vs S1，+1,320 vs 基线） |
| `split+scrub` (b) | 34,400 B（−40） | 200,800 B（−1,000） |
| `split+strip+scrub` | 33,648 B（−792） | 151,664 B（−50,136） |
| `split+fullstrip` | 33,648 B（−792） | 151,664 B（−50,136） |

`__text` 在所有变体里逐字节相同（demo6 `1fc42d8f76f83c2a`、wbaes `d67ba2bb3dd90f62`），
`__sections` 表逐项相同。**S1 那 +33.6% 的体积几乎全是可回收的元数据**：
(a) 之后只比基线大 1,320 B (+0.9%)，即 S1 的符号成本可以被去符号完全抵掉，
函数起点的收益（19 → 1584）保留。

耗时：

| 项 | 结果 |
|---|---|
| 编译+链接（demo6，4 次取中位） | `B_mir` 56 ms / `C_sym` 54 ms / `C_sym_strip` 54 ms（噪声内） |
| `strip`（Xcode 16.4） | 4.6 ms（34,440 B）/ 3.4 ms（201,800 B） |
| `macho_scrub.py`（含重签 `codesign`） | 44.8 ms（34,440 B）/ 44.4 ms（201,800 B）——基本是进程启动+签名，与体积无关 |
| demo6 进程（3 轮 × 40 次，中位） | `B_mir` 1.65 / `C_sym` 1.56 / `C_sym_strip` 1.46 / `C_sym_scrub` 1.44 / `C_sym_fullstrip` 1.56 ms |

进程时间差在 1.44–1.65 ms 之间来回摆动、方向随机（同轮内标准差 0.05–0.2 ms），
而 `__text` 逐字节相同 ⇒ **指令级成本 0，差异是噪声**。

## 7. 失败的机制（原始命令与报错，没有绕过）

### 7.1 `-Wl,-x,-S` 不等于"去符号"，它留下的是"只有真函数有名字"

上面 §2/§3/§4 已经把数字给了。机制层面的原因很直接：`-x` 删的是 **non-external**
（本地）符号，`__Z12shortestPathPA9_ji`、`_main`、`__ZN5WBAES…` 都是 external，
所以它们既留在 nlist，也留在 dyld 导出表里（导出表根本不看 `-x`）。
S1 的 chunk 符号是 local，所以被整批删掉——**留下的恰好是真函数**。
这一点在 S1 文档 §9.2 里只是作为"顺带观察"提到，本次测量说明它是 (a) 的主要效果，
而且是反向的。

### 7.2 scrub 之后不能再 `strip`

```
$ cp C_sym_scrub /tmp/x && strip /tmp/x
.../usr/bin/strip: fatal error: file not in an order that can be processed
                   (function starts data out of place): /tmp/x
$ echo $?
1
```

同一命令在 **未 scrub** 的 `C_sym` / `W_cf_sym` 上成功（rc=0），在
`C_sym_scrub`、`W_cf_sym_scrub`、`CR_scrub` 上都失败；`--exports zero` 模式同样失败
（`exports removed : 3 name(s), 80 B trie -> 0 B` 之后 strip 报同一个错）。
所以 (a)(b) 只能按 **strip → scrub** 组合，反过来是硬失败，不是"没测"。
（报错来自 ld64 的 file-order 校验：scrub 改了 `__LINKEDIT` 里 trie 的 datasize 却把
`LC_FUNCTION_STARTS` 留在原位，重写器拒绝这个排布。此处只报事实，不猜它内部实现。）

### 7.3 `macho_scrub.py` 的自检会误杀自己生成的名字（低频）

```
$ python3 demos/wbaes/tools/macho_scrub.py --in C_sym --out /tmp/x --seed t0
  __Z12shortestPathPA9_ji  -> _zns4zohl73
  ...
string table still carries [b'_zn']
$ echo $?
1
```

`_zns4zohl73` 里的 `zn` 被 post-condition 的 `_ZN`（`re.I`）命中。
`harden_export.py` 会因此随机失败。实测频率（用工具自己的 `seeded_name` 采样 200 个 seed）：
17 个 external 名的 wbaes 规模 **4/200 ≈ 2%**，3 个名字的 demo6 规模约 0.3%（3 名 × 1/1024）。
修法很小（post-condition 只该检查"原名字是否残留"，不该检查自己生成的 base32 名），
但那是导出工具的改动，不在本次任务范围，**没有改**，只在这里报出来。

## 8. 判决

按任务的两个问法逐条回答：

| 问题 | 答案 |
|---|---|
| `LC_FUNCTION_STARTS` 在 (a) 与 (b) 之后还在吗 | **在**，27 / 1584 条，payload 逐字节相同 |
| S1 与 S3 会互相抵消吗 | **不会**。strip/scrub 只动 `LC_SYMTAB` 与导出表 |
| 最终产物里有多少起点带符号 | (a) 2/27、15/1584；(b) 2/27、15/1584；完整 strip 0/27、0/1584 |
| 真起点占比（sidecar/基线 ground truth） | demo6 2/27 = **0.074**；wbaes 19/1584 = **0.012** |
| 分析者能区分真/假起点吗 | (a)(b) 能，而且是最省事的方式：**有名字的就是真的**（0 假阳性）。(a) 连名字+地址一起给（导出表 6 条 tell 名）。(b) 只给"有无名字"，语义没了。只有完整 strip 才没有标签 |
| 名字泄漏 0 命中 | (b) 与 (a)+(b)：三张表 + `__cstring` + 全文件全 0。(a)：6/6 导出名保留且带地址。完整 strip：三张表 0，但文件里 4 个 tell 字节的旧名字字符串残留 |
| 还能跑吗 | demo6 全变体 9 行表逐字节相同；wbaes 静态（既有 SIGTRAP） |
| 崩溃回溯 | S1 指到假函数名；`(a)`/`(b)` 出错帧无名（只剩 imageOffset）；完整 strip 整栈无名 |

**所以 S3 按 `MIR-SPLIT-STRENGTHENING.md` §2 的原方案（`-Wl,-x,-S` + 清导出表）实现后，
分析者拿到的不是"many equal candidates, no labels"，而是"许多等价候选、外加 2 个（demo6）
或 15 个（wbaes）被点名的真函数"。** 那不是齐平，是**反向标注**：假边界无标签、真边界有标签，
且导出表还会把真边界按名字列出来。(a) 单独用比 S1 更差。

要真到"多等候选、无标签"，需要三步，缺一不可：

1. **完整 `strip`**（不是 `-Wl,-x,-S`），把 external 一起删；
2. 再跑 `macho_scrub` 清导出表与字符串表（顺序不能反，§7.2）；
3. 让 S1 给每个 chunk 发 CFI/unwind 表项——否则 `__unwind_info` 仍以 0.88 精度
   把真函数从 1565 个假边界里挑出来（§3.1）。

第 3 步没做，所以现在的诚实说法是：**"起点层齐平了（完整 strip 之后），结构层没齐平"**。
代价是线上崩溃归零（§5），这是真实成本。

> 后续：`reports/SPLIT-SYMBOLS-AB.md` 把上面三条都做了并重测。第 1/2 步（完整 strip + scrub）
> 成为 B profile：0 个带符号起点、0 个 tell 字节（含死 trie 里的 1,608 段字符串）、0 条 unwind 表项，
> demo6 仍跑出同一张 9 行表。第 3 步的结论是**做不到按比例**（MC 拒绝嵌套 `.cfi_startproc`，
> 原始报错在该文档 §5.2），只能中立化；A profile 则改走"标签与真函数同类别"那条路，
> 让"有名字"不再是探测器，代价是 unwind 表仍点名 15 个真函数。

## 9. 复现

```sh
CL=src/build/bin/clang++ ; S=demos/ios/demo6_mir_noeh.cpp ; M=demos/ios/reports/s3_measure.py

# S1 与 S3 的 6 个变体（§1 的 6 条命令）
python3 $M C_sym       --baseline B_mir --sidecar chunks.tsv --run
python3 $M C_sym_strip --baseline B_mir --run
python3 $M C_sym_scrub --baseline B_mir --run
python3 $M C_sym_strip_scrub --baseline B_mir --run
python3 $M C_sym_fullstrip   --baseline B_mir --run
python3 $M C_sym --baseline B_mir --same-fnstarts-as C_sym_strip   # payload 相同 -> True

# wbaes 侧（静态）
ARMRC_NO_DATAFLOW=1 $CL -O2 demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c \
    -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 -mllvm -split-symbols \
    -mllvm -split-symbols-sidecar=wb.tsv -o W_cf_sym
python3 $M W_cf_sym --baseline W_cf --sidecar wb.tsv

# 崩溃探针（必须换 UUID，否则命中系统符号缓存）
python3 $M --reuuid CR_scrub --out U_CR_scrub
CRASH=1 ./U_CR_scrub
python3 - <<'EOF'
import json,glob
f=sorted(glob.glob("/Users/lasysloth/Library/Logs/DiagnosticReports/U_CR_scrub-*.ips"))[-1]
d=json.loads(open(f).read().split("\n",1)[1]); imgs=list(d["usedImages"])
for fr in d["threads"][d["faultingThread"]]["frames"][:3]:
    print(imgs[fr.get("imageIndex",0)].get("name"), fr.get("imageOffset"), fr.get("symbol"))
EOF
```

`s3_measure.py` 打印的字段：`function_starts*`（含 4 字节对齐）、`starts_with_symbol` /
`starts_with_chunk_symbol`、`labelled_real` / `labelled_forged`、`unwind_entries` /
`unwind_real` / `unwind_not_real`、`leak_counts` / `leak_raw_file_bytes`、`run`、
`fnstarts_payload_sha256`（配 `--same-fnstarts-as` 判定"没被动过"）。

## 10. 默认行为未变

- 编译器一行没改：本任务只新增 `demos/ios/reports/s3_measure.py`（纯测量）与本文。
  `-split-symbols` 仍默认关，`-Wl,-x,-S` 与 `strip` 都是链接器/系统工具，不进默认构建。
- `macho_scrub.py` / `harden_export.py` 未改（§7.3 的误杀只报告，不修）。
- S1 产物无需重编：本文所有变体都从同一个 `C_sym` / `W_cf_sym` 派生，
  §2 的 payload sha 就是"没动过"的证据。
