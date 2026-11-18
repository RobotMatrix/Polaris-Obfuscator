# S1 落地：为每个拆出块伪造函数符号（split-symbols）

> 状态：**已实现并入树**。机制在 `AArch64RubbishCode`（MIR，pre-emit 最后一站），
> 开关 `-mllvm -split-symbols`，默认关；所有数字来自本机实跑（macOS arm64 / 本仓 clang 16.0.6）。
> 本文只主张"符号与 LC_FUNCTION_STARTS 被虚增"，**不主张 IDA 函数数**（本机没有 IDA，见 §8）。

## 1. 机制

`exported-binaries/README.md` 的问题陈述是对的：符号区间由 nlist 决定，块搬来搬去
都发生在区间内部，所以工具看到的函数数不变。S1 就是把区间切开：

```
AArch64RubbishCodePass::emitChunkSymbols(MF)     // process() 末尾，所有块布局定稿后
  for each chunk MBB (splitBasicBlock 的 Body/End + randomMoveBasicBlock 的新块)
    BuildMI(INLINEASM, ".no_dead_strip <NAME>\n<NAME>:\n")   // 插在该块第一条指令之前
```

- 用 `AArch64::INLINEASM`（`addExternalSymbol` 持有字符串）而不是新增 MC 层 hook：
  该 pass 已经在用同一条路径发 `.byte` 脏字节，这条路径**确定能落到 object**。
  asm 文本进 MC 的 AsmParser，标签就是真正的 `MCSymbol`，不是伪装的字符串。
- 标签是**非临时**符号（不以 `L` 开头），因此 assembler 保留、ld64 写进 nlist，
  并从 nlist 派生 **LC_FUNCTION_STARTS**（实测：见 §4，27 个函数起点全部来自 nlist）。
- `.no_dead_strip` 是必须的，不是装饰：光写标签会让该块成为独立 atom，
  **`ld -dead_strip` 会把这个"没人引用"的 chunk 整段删掉**，二进制直接段错误。
  实测证据（探针 `q.cpp`，无 `.no_dead_strip`）：链接成功、运行 `Segmentation fault`，
  符号表里只剩 chunk 之前的部分。加上 `.no_dead_strip` 后同一探针正常运行、符号仍在。
- `.alt_entry` 也测了（任务里提到的那种写法）：`r.cpp/s.cpp` 探针里它同样能活过 `-dead_strip`
  并且出现在 nlist + LC_FUNCTION_STARTS 里；但它不产生新 atom，而且这个 ld64 写出的
  `n_desc` 是 `0x0`（与普通 local 符号一致，`N_ALT_ENTRY` 没保留），所以它相对
  `.no_dead_strip`+普通标签没有任何可测优势，反而少了"块=独立 atom"这一层。当前实现用后者。
- **不导出**：chunk 名字只在 nlist 里，export trie 不变（§4 实测 exports 仍只有 3 条原名）。
- 名字是每构建种子化的：`_k` + 12 hex，
  `splitmix64(build_seed, module_id, function_name, chunk_idx, salt)`。
  不含原函数名任何片段；同一次构建里 25/1565 个名字互不相同（实测 25/25、1565/1565 unique）；
  不给 `-mllvm -obf-seed` 时两次构建的 25 个名字**重合 0 个**（seed `1146d1947` vs `107291944`），
  给 seed 则可复现。名字生成不消耗 `nextObfRandom` 流，
  所以**开不开这个 flag，垃圾码布局不变**。

### FDE：没有做，理由

- 本仓库的 arm64 Mach-O 产物里**根本没有 `__eh_frame` 段**（实测 `C_sym`/`W_mir`：
  `__eh_frame` 不存在，只有 `__unwind_info`），所以"给 chunk 补 FDE"等于手工编码
  `__unwind_info` 的 second-level 表项，不是 cheap path。
- 在 inline asm 里嵌 `.cfi_startproc` 与函数自身的 `.cfi_startproc` 冲突（MC 直接报错），
  这条路封死。
- 因此**只发符号，不发 unwind 记录**，这也符合任务给的降级条件：
  一个"有符号、无 FDE"的地址对绝大多数工具仍是候选函数。副作用：ld64 为新增的
  函数起点补了 `__unwind_info` 表项，demo 上 88 → 104 字节（+16 B），代价可忽略。

## 2. 开关与 ground truth

```
-mllvm -split-symbols                       # 总开关，默认 false
-mllvm -split-symbols-sidecar=<path>        # 追加 (function, chunk, symbol) 映射
```

sidecar 是制表符分隔、追加写，多 TU 共用一个文件：

```
polaris-split-symbols	1
seed	3039
fn	_Z12shortestPathPA9_ji	12
chunk	_Z12shortestPathPA9_ji	0	_k3d4da52d28ea	17
chunk	_Z12shortestPathPA9_ji	1	_k52dea7fedaad	18
...
```

第 5 列是 MBB 号（调试用）。**地址**在编译期不存在，所以由
`demos/ios/reports/s1_measure.py` 用 nlist 把 symbol 解析成地址，得到完整的
(function, chunk idx → address) 映射（示例 `demo6-split-symbols.json` 的 `chunk_map`）。

## 3. 被测对象

| 变体 | 源 | 编译 |
|---|---|---|
| A_plain | `demos/ios/demo6_mir_noeh.cpp`（去掉 `asm("backend-obfu")`） | `-O1` |
| B_mir | 同上，带标记（MIR 拆分，**不开新开关**） | `-O1 -mllvm -obf-seed=12345` |
| C_sym | 同上 + 新开关 | `-O1 -mllvm -obf-seed=12345 -mllvm -split-symbols -mllvm -split-symbols-sidecar=…` |
| W_cf | `demos/wbaes/demo_wbaes.cpp tiny_aes.c`（真混淆产物） | `-O2 -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345`（`ARMRC_NO_DATAFLOW=1`，见 §9） |
| W_cf_sym | 同上 + 新开关 | 同上 + `-mllvm -split-symbols -mllvm -split-symbols-sidecar=…` |

## 4. 结果：符号 / LC_FUNCTION_STARTS vs ground truth

`macho_symbols.py` + `s1_measure.py`（ground truth = 同一构建关掉开关时的函数起点数）：

| | A_plain | B_mir | **C_sym** |
|---|---|---|---|
| 文件大小 | 33,640 | 33,640 | **34,440** (+800 B, +2.4%) |
| `__text` | 684 | 3,356 | **3,356**（不变） |
| nlist 条目 | 6 (3 defined) | 6 (3 defined) | **31 (28 defined)** |
| 其中 chunk 符号 | 0 | 0 | **25** |
| LC_FUNCTION_STARTS | 2 | 2 | **27** |
| ground truth（真函数起点） | 2 | 2 | 2 |
| **比值** | 1.0× | 1.0× | **13.5×** |
| 边界准确率（真起点 / 全部起点） | 1.00 | 1.00 | **0.074** |
| sidecar chunk 解析成功 | – | – | **25/25** |

真混淆产物（`wbaes`，2 个带标记的函数、1565 个 chunk）：

| | W_cf | **W_cf_sym** |
|---|---|---|
| 文件大小 | 151,048 | **201,800** (+50,752 B, +33.6%) |
| `__text` | 118,168 | **118,168**（逐字节相同，0 差异） |
| nlist 条目 | 37 (32 defined) | **1,602 (1,597 defined)** |
| chunk 符号 | 0 | **1,565** |
| LC_FUNCTION_STARTS | 19 | **1,584** |
| **比值** | 1.0× | **83.4×** |
| 边界准确率 | 1.00 | 0.012 |

注意 `W_cf_sym` 的 `__text` 与基线**逐字节相同**（118,168/118,168，0 个不同字节），
所以符号完全不改变代码。demo6 的 `__text` 长度也相同，只有 **1 个字节**不同，
位置在 `0x10000086e`、即 `brk #1` 陷阱前那段 `.byte` 随机填充里（反汇编两侧都是
`sri.8b/eon/.long 0xc6bcc435/ror` 这种无意义序列，永远不会执行）。

每条 chunk 符号都落在 4 字节对齐的指令边界上，`n_desc = 0x0`、`N_SECT` local、
不在 export trie 里。

## 5. `macho_symbols.py` 前后对比（函数起点列表差异）

```
B_mir    function starts: 2 total, 0 without a symbol      # 0x1000004e8, 0x100000b30
C_sym    function starts: 27 total, 0 without a symbol     # +25 个 chunk 起点
         0x1000004e8  __Z12shortestPathPA9_ji   size  88   <- 原来是 1608
         0x100000540  _k3d4da52d28ea             size  72
         0x100000588  _k52dea7fedaad             size 276
         0x10000069c  _k153f8d65e847             size 240
         ...
         0x100000b30  _main                     size  88   <- 原来是 1748
```

`__Z12shortestPathPA9_ji` 从 1608 字节的"一个大函数"变成 88 字节，
其后的 25 个 chunk 各自带名字与区间。工具不再需要猜边界——它拿到的是**错的边界**。

## 6. 名字泄漏

| 检查 | 结果 |
|---|---|
| 新增 chunk 名字命中 `WBAES\|hsvm\|hy_vm\|_ZN` | **0**（25 个 demo chunk、1565 个 wbaes chunk 全部不命中） |
| `C_sym` 整binary `macho_symbols.py` 命中 | **0** |
| `W_cf_sym` 整binary 命中 | 15 条（9 个 distinct），**与 `W_cf` 基线完全相同**：`__ZN5WBAES4initEv` / `__ZN5WBAES8enc_core…` / `__ZN9wbaes_key…` 等原名仍在 nlist |
| export trie | 不变（只有 `__Z12shortestPathPA9_ji` / `__mh_execute_header` / `_main`） |

即：**新符号自身 0 泄漏**，但 `WBAES|hsvm|hy_vm|_ZN` 的 0 命中要求在本树**做不到**——
那是 S3（去符号）没做，不是本任务引入的。`demo6`（不含 WBAES 符号）满足 0 命中。

## 7. 体积与耗时（G4）

- 体积：`__text` 不变；增长全在 `__LINKEDIT`（nlist 16 B/条 + 字符串表）。
  demo6 +2.4%；wbaes 151 KB → 202 KB（+33.6%，1565 条符号 × ~32 B）。
  在 70 MB 的正式产物上这 50 KB 是 0.07% 量级。
- 耗时（demo6 + 500 次调用循环，`H_mir` vs `H_sym`，各 3 轮 × 40 次进程）：

  | 轮 | H_mir 中位数 | H_sym 中位数 |
  |---|---|---|
  | 1 | 1.66 ms | 1.54 ms |
  | 2 | 1.46 ms | 1.43 ms |
  | 3 | 1.45 ms | 1.50 ms |
  | 中位数的中位数 | **1.45 ms** | **1.43 ms** |

  差 −1.4%，同轮内标准差 0.05–0.31 ms，方向随机 ⇒ 噪声。**指令级成本为 0**
  （代码逐字节相同，符号不占代码空间），远在 ≤5% 门槛内。
- 功能：`A_plain` 与 `C_sym` 输出逐行相同（Dijkstra 表 `0/4/12/19…`）；
  demo6 的 500 次调用循环两个变体都打印 `sink=7000`。`wbaes` 侧只做静态对比
  （它在本树跑不起来，见 §9.3），但 `__text` 逐字节相同这一点已经排除了语义变化。

## 8. 崩溃回溯 / G1 代理指标（诚实边界）

- 崩溃回溯没坏：同一故障地址（`imageOffset 1500`）在系统 crash report 里
  - `CR_mir`：`sym: f(int)`
  - `CR_sym`：`sym: k0c26a3da9f53`（chunk 名）
  帧形状正常（2 个应用帧 + `dyld start`）。副作用是**崩溃符号也被换成了假函数名**——
  这正是 S1 想要的欺骗效果，但也意味着线上崩溃归因会变难，这是真实成本。
- **G1 是代理**：本机没有 IDA/Ghidra，本文的"函数数"= `LC_FUNCTION_STARTS` 条数
  （以及 nlist 里 `__text` 符号数），比值 13.5× / 83.4× 是**符号层**的虚增倍数，
  不等于 IDA 的自动识别函数数。IDA 会同时用符号、eh_frame/unwind、调用图与代码模式，
  多数情况下会以符号为准建函数，但**这一点没有被验证**，不能写成"IDA 函数数 ×13.5"。
- 同理 G2：真起点仍全部保留（2/2 与 19/19），所以本选项提高的是**假阳性**
  （边界准确率 0.074 / 0.012），不是"藏起真边界"——藏边界要等 S3。

## 9. 已知限制

1. **只做 Mach-O**：非 Mach-O triple 直接跳过并打一行 `[split-symbols] Mach-O only`。
   ELF 上要发的是 `.type f,#function` + 真符号，未测，未做。
2. `-Wl,-dead_strip` 已通过 `.no_dead_strip` 处理：实测 demo6 的 `-Wl,-dead_strip` 构建
   输出与未混淆二进制逐行相同（9 行 Dijkstra 表），符号仍在（27 defined）。
   顺带观察：这种链接方式下**真函数名会被 dead-strip 掉**（nlist 里只剩 chunk 名），
   相当于免费得到一部分 S3 效果——本设计不依赖这一点，也不用它。
   `-Wl,-x`（剥本地符号）会把 chunk 符号整批删掉——那正是 S3 的取舍，两者不冲突。
3. **`wbaes` demo 在本树跑不起来（既有问题，与本改动无关）**：
   `-O2 demo_wbaes.cpp tiny_aes.c -mllvm -passes=sub,bcf,fla` 链接成功但启动即
   `SIGTRAP`（exit 133）。用**未打补丁的 clang**（`git checkout` 后重编）编译同一命令，
   同样 `SIGTRAP`；`ARMRC_NO_SPLIT=1` / `ARMRC_NO_DIRTY=1` / `ARMRC_NO_DATAFLOW=1`
   的构建也都如此。所以 `W_cf*` 只用于**静态**符号测量与逐字节 `__text` 对比，
   不用于运行时/耗时；运行时数据用 demo6。
4. FDE 未合成（§1）。`__unwind_info` 会为新增起点多出表项，体积代价极小。

## 10. 默认行为未变（可复现的证据）

- 关掉开关时 no-op：`git checkout` 掉补丁重编 clang，用同一命令编 demo6，
  两个二进制逐字节比较只有 49 字节不同，全部落在 `LC_UUID`（976–991）与 ad-hoc
  代码签名区；而**同一编译器连编两次**有 304 字节不同（同一区域）⇒ 差异是链接期
  UUID/签名噪声，不是代码。结构化对比（`s1_measure.py`）：`__text` 3356、
  nlist 6、function starts 2、`__sections` 全等 —— 与打补丁后关闭开关完全一致。
- 所以既有的 `exported-binaries/` 产物不需要重编。

## 11. 复现

```sh
CL=src/build/bin/clang++

# 基线（MIR 拆分，不开新开关）
$CL -O1 demos/ios/demo6_mir_noeh.cpp -mllvm -obf-seed=12345 -o B_mir

# S1
$CL -O1 demos/ios/demo6_mir_noeh.cpp -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=/tmp/chunks.tsv -o C_sym

python3 demos/ios/reports/s1_measure.py C_sym \
    --sidecar /tmp/chunks.tsv --baseline B_mir --json /tmp/c.json
python3 demos/wbaes/attacks/residual/macho_symbols.py C_sym | sed -n '/function starts/,$p'

# 真混淆产物（静态；该 demo 在本树启动即 SIGTRAP，既有问题）
ARMRC_NO_DATAFLOW=1 $CL -O2 demos/wbaes/demo_wbaes.cpp demos/wbaes/tiny_aes.c \
    -mllvm -passes=sub,bcf,fla -mllvm -obf-seed=12345 \
    -mllvm -split-symbols -mllvm -split-symbols-sidecar=/tmp/wb.tsv -o W_cf_sym
```

`research/hsvm` ctest：`28/28 Passed`（5.03 s，改动后跑过）。

## 12. 与六个选项的关系

S1 解决"边界从工具手里拿不走"这一条，并且**只**解决这一条：
真符号还在（S3）、块间仍是直接分支/B（S2）、合并没有前置（S4）、没有 decoy（S5）、
调用仍是直接 `bl`（S6）。下一步收益最大的是 S3：chunk 符号现在填满了 nlist，
一旦把真符号与导出清掉，"哪个是真函数"就只剩 S2 的计算分支可依赖。
