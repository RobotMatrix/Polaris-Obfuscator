# dl4 攻击闸门：DCA 与 BGE 类剥离（实测）

> **状态（2026-11-18）**：dl4 上两条攻击都**成功**（下面各节即为那次实测）。
> 当前这一代 `wbaes_nl_*` 已改成跨 lane 非线性重编码，两条攻击在新产物上都**失败**，
> 见文末 [dl5 一节](#dl52026-11-18同一批脚本在新一代产物上都失败)。

这两个脚本是对 `WB-DESIGN-V2.md` §六 攻击表里 `E4b`（BGE 类跨轮还原）和 `E4c`（DCA）
的落地判据。结论先说，数字都在下面各节里，全部来自本机实跑（2026-11-17，macOS arm64）。

| 攻击 | 结论 | 代价 |
|---|---|---|
| DCA（插桩取地址） | **成功**，恢复全部 16 字节主密钥 | 8 条轨迹，0.19 s 分析，0.76 s 全程（含找种子）；不需要读表 |
| BGE 类（静态剥离编码） | **成功**，恢复全部 16 字节主密钥 | 表解掩后 0.01 s；第 1 步 2.58 s（全量校验 2 M 项） |
| 经典单字节 DCA（先试的那条） | 失败且原因明确 | 第 0 轮 lane 表下标是 `P0(pt)`，与密钥无关（16/16 槽位实测） |

也就是说：`dl4` 的"脚本直接读表失效"是真的（`extract_key.py` 仍然失败），但**离线产物本身已经被
两条独立路径拿回主密钥**。这不是"没找到"，是"找到了，而且都比 dl3 更快"。

## 目录

```
attacks/
  wblib.py                 共用：GF(2^8)/AES-128、表几何、地址散布、Mach-O 解析、掩码/轨迹 IO
  dca_attack.py            实验 A（单字节 CPA，负）+ 实验 B（精确下标 + 4 字节 MITM，正）
  bge_attack.py            静态剥离：64K 解码表的 XOR 可分解性 -> lane 双射 -> 第 0 轮密钥
  trace_harness/
    harness.cpp            轨迹记录器（记录 (表偏移, 逻辑下标, 宽度)）
    build_traces.py        在临时目录里生成一份打过 5 个钩子的 wbaes_hybrid.h 副本并编译
```

`demos/wbaes` 的任何文件都不被修改：`build_traces.py` 把 `wbaes_hybrid.h` **复制**到临时目录，
只在副本里插入 `HY_TRACE(...)` 调用，然后编译。轨迹用的表字节来自产物本身（`__DATA,__hytab`），
第 0 轮输入双射来自 `__TEXT,__const`，掩码种子由调度块自校验定位。

## 怎么跑

```sh
cd demos/wbaes/attacks

# 1) DCA，轨迹来自 Python 模型（不需要编译任何东西）
python3 dca_attack.py --cache /tmp/dl4_plain.bin

# 2) DCA，轨迹来自真实运行时的插桩副本（先构建，再跑）
python3 trace_harness/build_traces.py --n 64 --work /tmp/wbaes-traces
python3 dca_attack.py --traces /tmp/wbaes-traces/dl4_traces.bin

# 3) BGE 类静态剥离
python3 bge_attack.py --cache /tmp/dl4_plain.bin
python3 bge_attack.py --sample 0        # 32 张 64K 表全量校验（2 M 项）
```

默认二进制是 `exported-binaries/wbaes-challenge/macos/wbaes_dl4_clean`，默认目标机参数是
`pagesize=16384 ncpu=10 cls=128`（产物构建机的 `sysctl`，也是 `hy_env_mix` 的输入）；
换产物或换目标机时用 `--binary / --pagesize / --ncpu / --cls`。

`wblib.load_plain_table()` 的 Python 掩码走查要 15 s 左右（69 MB × xorshift）；`--cache` 会把
解掩后的表写到磁盘，第二次起 0.02 s。`trace_harness` 的 C 解掩实测：
`./harness ... 0 /tmp/z`（读 69 MB + 解掩 + 写一份解掩副本 + 一次加密）0.189 s，
所以静态攻击的实际成本是"0.19 s 解掩 + 0.01 s 代数"。

## dca_attack.py：地址还漏不漏密钥

**模型**：攻击者在调试器/Frida 下跑产物，记录每个分组加密的表访问序列 `(表内偏移, 宽度)`。
不读表内容、不需要掩码种子——这是 Bos-Hubain-Michiels-Teuwen（CHES 2016 / ePrint 2015-753）
的设定。dl4 额外把"下标 → 地址"打散了（`hy_scatter` 16 位 Feistel / `hy_scatter8` 仿射模 256），
但这两张映射的 key 只有 `(env, tag)`，都是二进制里的内联代码，所以攻击者能反解：
`hy_scatter8` 是仿射（`y = a*x + b mod 256`），`hy_scatter` 是 4 轮 Feistel，两者都可逆。

### 实验 A（负）：经典单字节 CPA 打第 0 轮 lane 表

64 条轨迹、16 个槽位 × 256 个密钥字节假设：

```
max |r| over 16 slots x 256 hypotheses: 0.497
Monte-Carlo null, same statistic (256 random models, 10 reps): 0.414
rank of the true key byte: min 7, median 78, max 248
slots whose index is bit-exactly P0(pt) on every trace: 16/16
```

0.497 与"256 个相关里取最大"的零分布（0.414）同量级，真字节排名 7–248——这是噪声。
原因不是编码，而是**结构**：第 0 轮 lane 表的下标是 `P0(pt)`，`P0` 是公开的输入双射，
所以这条地址与密钥无关（16 个槽位、64/64 条轨迹逐位等于 `P0(pt)`）。dl4 把 `rk0` 放进表**值**里，
经典 1 字节 DCA 因此被关掉。

### 实验 B（正）：第 0 轮边界置换表

`F1/F2/F3` 每列每行有一张 256 项边界置换表，它的**下标**是 `MC(row,:) · S(pt ^ rk0)`——
即 AddRoundKey **之前**的轮输出，正是 DCA 要的那个中间量，而且它是 8 位、能整字节反解
（`hy_scatter8` 仿射，`hit - base` 直接反演）。一条轨迹 = 一个 8 位方程、4 个密钥字节；
用 `(k0,k1) × (k2,k3)` 的 MITM，`min(3, T-1)` 条轨迹做签名、其余轨迹验证：

```
tag F1  (kind  20): candidates per column [1, 1, 1, 1] -> 16/16 key bytes  [0.19s]
col 0:  1 candidate 4-byte key(s) for key bytes ['0x75', '0xff', '0x2c', '0x29']
col 1:  1 candidate 4-byte key(s) for key bytes ['0x1d', '0x55', '0xde', '0x3b']
col 2:  1 candidate 4-byte key(s) for key bytes ['0xef', '0x78', '0x56', '0x49']
col 3:  1 candidate 4-byte key(s) for key bytes ['0xb7', '0x5e', '0xd2', '0x1b']

755e563b1dffd249ef552c1bb778de29   (8 address traces, no table bytes)
AES-128(6bc1...172a) = abe296eea2625f251ba57ed0b408272c
reproduces the shipped ciphertext: YES
```

调度块是封印的，所以脚本对 F1/F2/F3 三种边界表 tag 逐个试，命中的是 F1（产物第 0 轮确实是 F1）。

**轨迹数与候选数的实测曲线**（同一批 harness 轨迹，默认 `--sig-traces 3`，
实际签名条数是 `min(3, T-1)`）：

| 轨迹数 | 每列候选数（col 0/1/2/3） |
|---|---|
| 2 | 66030 / 65628 / 65893 / 65419 |
| 3 | 295 / 233 / 248 / 266 |
| 4 | 2 / 2 / 4 / 2 |
| 5 | 1 / 1 / 1 / 1 |

即 **5 条轨迹**就唯一，8 条是余量。全程（找种子 0.03 s + 读轨迹 0.01 s + 分析 0.19 s）
0.76 s。

### 轨迹的可信度

`trace_harness/` 用产物自己的表节、在 `-O2` 下跑真实运行时代码路径，输出的密文是
`abe296eea2625f251ba57ed0b408272c`（与产物一致），每块 600 次表访问；`dca_attack.py`
的 Python 模型在同一批明文上产生**逐项相同**的 600 条地址序列（`wblib.encrypt` 的
`log` 与 harness 输出逐条比对通过）。所以实验 B 用的不是"我以为的布局"，而是真实路径。

### 为什么第 1 轮以后没有同样的漏

第 1 轮起，每张表的下标都是上一轮的**边界双射** `P[r-1](...)`，即某个未知双射作用在
含密钥的值上；地址只能给出"编码后的值"，攻击者无法把假设的明文域值映到它上面
（任何密钥假设都能用一个自由双射解释）。所以这条链只在**入口轮**断掉——而入口轮正好
就是 `rk0 = 主密钥` 所在的那一轮。

## bge_attack.py：能不能用代数把编码剥掉

**模型**：按 `gen_hybrid.cpp` 的参数重建第 0 轮的表网络

```
lane(row,k)[x] = E[row][k][ MC[row][k] · S(x ^ rk) ]     E 随机双射
pair(row,p)[a,b] = D[row][2p][a] ^ D[row][2p+1][b]       D = E^{-1}
out(row,dst)[u]  = P[r][dst][ u ^ rk_next ]              P 随机双射
```

`AFFINE-ROUNDS.md` §八 的论据是"D 放不进一张 256 项表，只存在于 64K 表里，而那张表是黑的"。
**第 1 步就把这条论据推翻了**：64K 表是 `D0[a] ^ D1[b]`，一个 XOR（秩 1）张量，
读一行加一列就能拟合出两个 256 字节数组。

```
32/32 pair tables decomposed; 2097152 of 2097152 entries reproduced exactly by two
256-byte arrays (2.58s); recovered D is a permutation in 32/32 tables
```

**第 2/3 步**：把 D 取逆得 E（每个 lane 差一个 XOR 常数），于是第 0 轮 lane 表
`enc → a` 结合 D 给出 `MC[row][k] · S(pt ^ key)` 的 256 个值；对每个候选 `key` 检查这个
表达式是否恒定——只有一个候选成立：

```
col k row  lane row is a bijection  distinct key candidates
  0 0   0  yes               1 ['0x75']
  ...
  3 3   0  yes               1 ['0x1b']
all four MC rows agree on the candidate set: True
AES-128 key recovered statically from round-0 tables: 755e563b1dffd249ef552c1bb778de29
reproduces the shipped ciphertext: YES
wall time after the table was unmasked: 0.01s
cross-round algebra rounds needed: 0 -- round 0 alone is the whole key
```

所以 BGE 类攻击在这里**没有跑到跨轮那一步的必要**：第 0 轮已经是全部密钥。诚实地说，
"跨轮线性化"这个未知数仍然没被测量——但设计里假设的障碍（未知 lane 双射）在第一步就不存在了。

**为什么单表读不出来、双表能读出来**：单张 lane 表的 256 项是 256 个互不相同的值，
对任何候选密钥字节都能配一个双射 E 让它成立（`AFFINE-ROUNDS.md` §八 测到的 256/256 自洽，
本次也复核了"lane 行是 256 元双射的像"）。而 64K 解码表把 `D0 ^ D1` 写成了两维，
它的秩 1 结构同时暴露两条 lane 的逆。这不是"表更大所以更弱"，而是**逐 lane 双射 + XOR 重组合
在数学上必然可分解**：混合步骤是 XOR，元素级双射就不构成"混合"。

## 边界与未测

- DCA 实验需要**插桩**（调试器/Frida 级）。远程黑盒、只能看密文的攻击者拿不到这条轨迹；
  这是"研究者级"而非"脚本级"成本的界线，但脚本本身只要 0.76 s。
- 静态剥离需要读表字节，也就需要解掩：种子在产物里（本脚本 0.03 s、20 个候选就命中
  `0xc6f5ef19`），所以掩码不构成障碍（`DATA-LAYER.md` 早已记录）。
- 只打了 `wbaes_dl4_clean`。`dl4_max` 与 `dl2/dl3` 没有跑；不要从本文推断它们的强度。
- 两个攻击都落在**加密入口轮**；解密路径的入口轮（`hy_dec_entry` + 第 0 个 mc 步）结构相同，
  没有单独实现——按同样的表几何推它应当同样可破，但**未测**。
- 没有做"如果改了 X 会怎样"的对照实验。README 末尾只给结构性判断，不给成本数字。

## 结构性结论（不是测量，写清楚免得被当成测量）

1. 只要 8 位 lane 的值经 XOR 重组合、且每条 lane 一个逐元素双射，解码表必然是
   `D0[a] ^ D1[b]` 形式，逐 lane 的逆就一定可分离——换更大的表、加轮、换调度都不改变这一点。
   要避免，必须去掉"逐 lane 编码"，改成宽表（32 位输出）上的 32→32 非线性编码
   （Chow 式宽表融合），代价是表规模，而且那条路上 BGE 类攻击本身就适用。
2. 地址面：任何一张"下标 = 密钥白化后的明文域值"的 256 项表，都会把该值整字节交给
   插桩攻击者。第 0 轮边界置换表就是这种表；把它换成 64K 表（下标是 16 位、需要两条 lane
   的值）会让逐字节反解失效，但同一批地址仍然泄漏两条 lane 的组合——只是把 8 位方程
   换成 16 位方程。真正的关法是让入口轮不存在"明文域下标"的表。

## dl5（2026-11-18）：同一批脚本在新一代产物上都失败

对手换成 `exported-binaries/wbaes-challenge/macos/wbaes_nl_clean`（key `46f6abe5…`，
密文 `80aadc09…`）；`wblib.DEFAULT_BIN` 已指向它。表体积 70,090,816 B（dl5 布局）。

| 攻击 | 命令 | dl5 结果 |
|---|---|---|
| BGE 类静态剥离 | `python3 bge_attack.py` | `incomplete (0/16 bytes)`，rc=1 |
| DCA 地址轨迹 | `python3 dca_attack.py --traces <tr>/dl4_traces.bin` | `incomplete: 0/16 bytes`，rc=1 |
| 经典单字节 CPA | 同上实验 A | 仍然零泄漏（16/16 槽位下标 == `P0(pt)`） |

关键输出（本机实跑）：

```
== 1. peel step 1: is the 64K pair table opaque? ==
   32/32 pair tables fitted; 9646 of 131072 sampled entries reproduced by two
   256-byte arrays (0.19s), but 8672 of those lie on the a=0 row or the b=0
   column that the fit is built from. Off those, 974/122400 = 0.0080 reproduce,
   against 1/256 = 0.0039 for an unrelated table
   -> 0.0080 of the off-axis entries fit, ... Q is not D0[a]^D1[b], so one row plus
      one column does not reproduce it and step 3 has no lane inverse to work with.
== result ==
   incomplete (0/16 bytes): round 0 did not yield the key
```

```
     tag F1  (kind 144) half 0: candidates per column [0, 0, 0, 0] -> 0/16 key bytes
     tag F1  (kind 144) half 1: candidates per column [0, 0, 0, 0] -> 0/16 key bytes
     tag F2  (kind 152) half 0: ... 0/16        tag F2 half 1: ... 0/16
     tag F3  (kind 160) half 0: ... 0/16        tag F3 half 1: ... 0/16
   what the recovered index actually is (round-0 family F1, kind 144):
     col 0: 8 distinct pair sums, 8 index values, conflicts 0, index == pair sum on 0/8 traces
== recovered key ==
   incomplete: 0/16 bytes
```

“函数、0 冲突、0/8 相等”这一行是本代最关键的一条：恢复出的下标仍然是成对和的**函数**
（所以泄漏面没消失），但它被一条**未知**随机双射 `Z` 遮住，密钥假设预测不出它的值。
能打它的只剩“未知双射一致性”统计（约 2^12 条轨迹），本仓库未实现。

### 脚本改了什么（以及为什么不算削弱）

- `wblib.py`：表几何常量改成 dl5 布局（列槽 798720 B、成对解码 `Q_OFF=4096`、
  重编码 `SPN_OFF=528384`、两字节边界 `BDY_OFF=536576`）；`mc_round()`/`encrypt()` 按
  `hy_mc_round` 的新尾巴重写（成对解码读 2 字节下标、边界读 64K 表、每列多记 12 次重编码读
  与 `hy_rec_undo()` 的还原读）；新增 `hy_scatter_inv()`：16 位 Feistel 逐轮反解，
  使攻击者**仍然**能从地址精确还原 64K 表的逻辑下标（不还原就等于送对手一个借口）。
- `dca_attack.py`：实验 B 从“1 字节下标 + MITM”改成“还原 2 字节下标 → 每个半字节各跑一遍
  原来的 4 字节 MITM”，并把测得的结构事实打成一行；实验 A 未改。
- `bge_attack.py`：拟合逻辑一个字没改；只把“a=0 行 / b=0 列是拟合自身构造出来的、
  不能算复现”讲清楚，并把结论改成按实测比例分支（>0.999 才说可分解）。

判定条件两边都没动：要么 16/16 字节密钥 + 复现产物密文，要么失败。难度没有降低——
脚本现在读的是 dl5 的真实形状，仍然拿不到密钥。
