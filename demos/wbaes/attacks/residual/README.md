# dl5 残差攻击：四条未测路径的实测

> **状态（2026-11-18）**：`WB-DESIGN-V2.md` §12.4 列的四条"剩余攻击面"全部落地并实测。
> 其中 (a) 与 (b) **成功**：(a) 静态读表 22 s 取回 16/16 字节主密钥（无轨迹、不对 `Z` 做任何搜索），
> (b) 4096 条地址轨迹（实测 64 条就够）5 s 取回主密钥；(c) 按设计预期**失败**，卡点在 `Z` 而不是重编码；
> (d) 两个同钥异码产物**各自被 (a) 单独打穿**，合并后多泄漏 0 字节。
>
> 这批数字全部来自本机实跑（macOS arm64，Python 3.12.5，纯 stdlib）。
> 对手产物：`exported-binaries/wbaes-challenge/macos/wbaes_nl_clean`
> （sha256 `07670e85…`，key `46f6abe5…`，密文 `80aadc09…`）。

| 攻击 | 需要什么 | 结果 | 实测代价 |
|---|---|---|---|
| (a) 隐藏位移结构化分解 | 解掩后的表字节 | **16/16 字节主密钥，复现密文** | 22.0 s 全程（16.6 s 解掩 + 5.4 s 代数），0 条轨迹 |
| (b) 未知边界双射一致性 | 插桩地址轨迹 + 明文 | **16/16 字节主密钥，复现密文** | 4096 条轨迹 5.1 s；64 条轨迹已 8/8 唯一 |
| (c) 反演重编码后重新剥离 | 解掩后的表字节 | 失败：重编码可逆（864/864 表），但剥离仍卡在 `Z`，0/16 | 0.19 s 读表 |
| (d) 跨实例复用（同钥异码） | 两个产物 | 各自被 (a) 打穿；合并增益 **0 字节** | 2×18 s 解掩 + 2×5.4 s 攻击 |

一句话：**dl5 的 `Z`（成对表输出双射）不构成密钥屏障**。它是输出侧的重标号，
而 `rk0` 是从**输入侧**进表的；密钥判别式只要对输出侧的线性重标号不变，就能绕开 `Z`。

## 目录

```
attacks/residual/
  reslib.py                共用：产物装载、32 张成对表的隐藏位移分解、gauge 不变的密钥判别、轨迹下标反演
  hs_attack.py             (a) 隐藏位移：分解 Q = Z(D0[a] ^ D1[b])，取回 round-0 全部密钥字节
  consistency_attack.py    (b) 未知边界双射的碰撞一致性 + 每半 2^16 的 MITM
  recoding_peel.py         (c) 从产物反演 32 位重编码，再跑 dl4 的 XOR 剥离
  cross_instance.py        (d) 用 gen_hybrid.cpp 生成同钥异码两份产物，分别打 + 合并
  zk_attack.py             (e) rk0 移进输出双射的 zk 变体：按表形状 0.00 s 取回 rk0/rk1
                               （构造、实测与结论见 ZK-EXPERIMENT.md）
  res16.py                 (f) 16 位合并形状的读取器、Decomp16、16 位值的密钥判别
  w16_probe.py             (f) 16 位合并：前置算术、XOR 可分解性、分解、取钥、代价
  w16_traces.py            (f) 16 位合并：地址轨迹侧（pair 表下标 vs P0、解码表 16 位下标）
  w16/F4.patch             (f) 该变体的生成器/头文件补丁（仓库里的两个文件未改）
                               （构造、实测与结论见 W16-EXPERIMENT.md）
```

与 `attacks/` 下已有脚本的关系：这四个脚本**不修改** `wblib.py`、`bge_attack.py`、
`dca_attack.py`，也不修改 `demos/wbaes/` 的任何设计源文件；它们 import `wblib` 只是复用
GF(2^8)/AES/表几何/掩码/轨迹 IO 这些已经公开的基础件。产物也不改动。

## 怎么跑

```sh
cd demos/wbaes/attacks/residual

# (a) 隐藏位移，静态（首次会解掩 70 MB，约 17 s；加 --cache 可复用）
python3 hs_attack.py
python3 hs_attack.py --cache /tmp/nl_plain.bin      # 第二次起 5 s

# (b) 一致性攻击（不给 --traces 时会自己构建 4096 条真实轨迹到 /tmp/wbaes-res/traces）
python3 consistency_attack.py
python3 consistency_attack.py --traces /tmp/wbaes-res/traces/dl4_traces.bin --skip-curve

# (c) 重编码反演 + 重新剥离
python3 recoding_peel.py --cache /tmp/nl_plain.bin

# (d) 跨实例（会编译 gen_hybrid.cpp 到 /tmp/wbaes-res/cross，并在那里生成两份表）
python3 cross_instance.py
```

退出码沿用 `attacks/` 的约定：只有拿到 16/16 字节且复现产物密文才 rc=0。
`recoding_peel.py` 的攻击按设计失败，因此它**恒返回 1**（与 `bge_attack.py` 的 `incomplete` 一致），
这表示"这条路线被挡住"，不表示脚本报错。

依赖：`clang++`（只有 (b) 的轨迹构建与 (d) 的生成器需要）、`/dev/urandom`（生成器的随机源）。
所有产物都写在 `--work` 指定的临时目录，仓库内只新增 `attacks/residual/` 下的文件。

## (a) 隐藏位移：`Q = Z ∘ (D0 ⊕ D1)` 的可解部分

**结构**。每一行 `f_a = Q[a][·]` 都是 256 个输出值上的置换（实测 32/32 张表、行与列都是置换），所以

```
lam_a = f_a ∘ f_0^-1,        lam_a(y) = Z( Z^-1(y) ^ (D0[a] ^ D0[0]) )
```

可以直接算出来；`LAM = {lam_a}` 是 256 个对合组成的群、在值集上正则作用、同构于 `(Z2)^8`。
列方向同样构造给出 `D1` 一侧，而且落在**同一个群**里（实测：所有列映射都能在 `LAM` 里找到）。
于是 `Q` 单凭自己就能定出 `D0[a]^D0[0]`、`D1[b]^D1[0]` 的**群元素**，也就是

```
da[a] = B( D0[a] ^ t )        B ∈ GL(8,2) 未知, t 未知
```

**它能定到哪、剩下多少自由度**（脚本第 1 节原样打印）：

```
2097152/2097152 entries over 32 tables, Z a bijection in 32/32
remaining freedom: |GL(8,2)| * 2^8 = 1369104324918194995200 = 2^70.2
```

即 2,097,152 个表项全部被 `(da, db, Z)` 精确重建成 `Z(da[a]^db[b])`，`Z` 也是双射；
而 `Z` 的**字节标号**（等价地 `D` 的字节标号）留下 2^70.2 的自由度。
这就是 §12.4 第 1 条说的隐藏位移，并且它确实不可唯一确定 —— 任何声称"恢复了 Z"的说法都是错的。

**为什么密钥还是掉了**。round-0 lane 表的第 `r` 个字节是

```
byte_r( lane_k[enc] ) = E_{r,k}[ m_{r,k} · S( P0^-1(enc) ^ rk0 ) ]
```

而 `D_{r,k} = E_{r,k}^-1` 正是上面从 `Q` 恢复出来的 `da/db`。所以 `val = D_{r,k}[byte_r]` 等于
`m·S(·)` 再复合一个**未知线性映射 `B`**。dl4 的判据（"`val` 等于 `m·S(pt^g)` 差一个常数"）因此必然失效
（实测：把 gauge 强制成恒等时 16 个字节 **0 个候选**），但它的 gauge 不变形式成立：

> 是否存在 GF(2) 线性映射 `A`，使 `val = A( m·S(pt^g) ) ^ const`？

真钥取 `A = B` 即成立。错误假设要让 AES 的 S 盒与它自己的某个输入平移**线性等价**，
实测 64 个 (列, lane, 行) 位置 × 256 个假设全部只有一个候选：

```
   col lane row  candidates
     0    0   0  1  ['0x46']
     ...
     3    3   0  1  ['0x1f']
   candidates over all 64 (col,lane,row) byte positions: min 1 median 1 max 1
   the four MC rows agree on the candidate set for 16/16 (column, lane) pairs
== 3. result ==
   recovered key: 46f6abe52990556a6713141f65fed9a5
   reproduces the shipped ciphertext: YES
   work factor: 16384 affine-consistency tests (64 byte positions x 256 guesses), 32 group recoveries
   no search over Z, no search over D0/D1, no traces; 21.99s total (5.37s algebra)
```

**代价**：32 次群恢复（每张 64K 表 ~0.17 s）+ 16384 次仿射一致性检验（~0.3 s），
加 16.6 s 的 Python 解掩（C 解掩 0.19 s，`DATA-LAYER.md` 早有实测）。
没有对 `Z` 的搜索、没有对 `D0/D1` 的搜索、没有轨迹。这是**离线静态**攻击（要读表字节），
与 `bge_attack.py` 同一威胁模型。

## (b) 未知边界双射：碰撞一致性 + MITM

`dca_attack.py` 的实测结构事实是：还原出来的边界下标是成对和的**函数**（0 冲突），
但不等于成对和（0/8）。本脚本把它变成攻击：

```
u_t = Zl( x_t ),  x_t = MC[row][0]·S(pt0^k0) ^ MC[row][1]·S(pt1^k1)
v_t = Zr( y_t ),  y_t = MC[row][2]·S(pt2^k2) ^ MC[row][3]·S(pt3^k3)
```

`Zl/Zr` 未知但**固定**，所以任意两条 `u` 相等的轨迹必有 `x_t = x_t'`。4096 条轨迹让 `u` 的 256 个值
各出现约 16 次，得到 ~32k 个碰撞对（脚本按固定步长取 2000 个）。对每个假设 `(k0,k1)`，
在这些对上的签名是

```
sig_k0 = ( m0·( S(pt0_a^k0) ^ S(pt0_b^k0) ) )_{pairs},   sig_k1 同理
```

真钥就是 `sig_k0 == sig_k1` 的那一对；把 256 个 `sig_k0` 哈希起来与 256 个 `sig_k1` 求交，
就把每半 2^32 的候选空间压成 2×256 次签名计算。

```
     col 0 half 0:  2000 collision pairs -> 1 candidate 2-byte key(s)  ['0x460x90']
     ...
     col 3 half 1:  2000 collision pairs -> 1 candidate 2-byte key(s)  ['0x550x1f']
   recovered key: 46f6abe52990556a6713141f65fed9a5
   reproduces the shipped ciphertext: YES
   traces used: 4096; candidate 2-byte sets per half: [1, 1, 1, 1, 1, 1, 1, 1] (max 1)
   MITM cost: 512 signature evaluations per half, 8 halves, 1.03s; 5.11s end to end
```

**轨迹数曲线**（同一批真实轨迹，`--skip-curve` 可跳过）：

```
        32 traces: 0..4 collision pairs/half -> halves with exactly 1 candidate: 4/8, widest 256, empty 1
        64 traces: 4..11 collision pairs/half -> halves with exactly 1 candidate: 8/8, widest 1, empty 0
       128 traces: 30..42 collision pairs/half -> halves with exactly 1 candidate: 8/8, widest 1, empty 0
      4096 traces: 2000..2000 collision pairs/half -> halves with exactly 1 candidate: 8/8, widest 1, empty 0
```

即 §12.4 第 2 条估计的"约 2^12 条轨迹"偏保守：**64 条真实轨迹**（4–11 个碰撞对）已经 8/8 唯一。
脚本用它要 4096 条只是为了给出 2000 对签名的余量。

**代价**：轨迹构建 1.3 s（`trace_harness/`，`-O2`，产物自己的表节），读轨迹 1.8 s，
MITM 1.03 s，总计 5.1 s。**不需要读表字节**，只看地址 + 明文 —— 这是 Bos-Hubain-Michiels-Teuwen 的设定。

## (c) 反演重编码，再跑剥离：失败，而且卡点不是重编码

脚本按 §12.2 的说法把 `R` 完整反演出来：

```
   72 instances (2 directions x 9 rounds x 4 columns); 589824 B of recoding tables
   stored inverse S-tables that are exactly the inverse of the stored forward S-table: 864/864
   R^-1(R(x)) == x on 1152/1152 random 32-bit words over all 72 instances (0.04s)
```

也就是说 `__hytab` 里存的 12 张逆向 S 表就是 12 张正向 S 表的逆（864/864），
配合公开的 `MDS^-1 (11,11,9,8)` 和 12 个常量，`R^-1` 不需要任何搜索 —— 重编码对攻击者是**完全透明**的
（这正是 §12.2 自己写的"状态编码，不是代数屏障"）。它还带来一个可测的好处：

```
   single-byte fault at the round output -> changed bytes out: {3: 3, 4: 285}
```

即轮输出上一个字节的故障会扩散到 4 个字节（288 个样本里 285 个），V5 的"垃圾输出仍是垃圾"成立。

反演之后剩下的形状正是 dl4 的（用已知密钥核对：轮 0 输出的 16 个字节各是真实 AES 状态字节的**逐字节双射**）：

```
   -> conflicts 0 over 512 plaintexts; distinct AES values seen per byte: min 213 median 220
   i.e. exactly dl4's shape: a per-byte bijection in front of the true state
```

再跑 dl4 的剥离（一行 + 一列拟合 `D0[a]^D1[b]`）：

```
   pair table fit D0[a]^D1[b] from one row + one column: 16338/2080800 = 0.0079 off-axis
   (a=0/b=0 axes are built by the fit: 16352/16352; random table would give ~0.0039)
   -> Q is not XOR-separable ... the peel yields 0/16 key bytes here.
```

**结论**：这条路线 0/16 字节，卡点是 `Z`（`Q` 不可 XOR 分解），**不是重编码**。
重编码反演给攻击者 0 个密钥比特，只花了 0.19 s 读表。
诚实地说：`recoding_peel.py` 之所以失败，恰恰因为它是按 dl4 的代数继续做的；
(a) 之所以成功，是因为它换掉了那条代数（见上）。这两条并不矛盾：`R` 在 `Z` 的下游。

## (d) 跨实例复用：同钥异码两份产物

脚本编译 `demos/wbaes/gen_hybrid.cpp`（只读，输出写到临时目录），用同一个密钥源
（`wbaes_key.h`）生成两份**编码全不同**的表（随机性来自 `/dev/urandom`）：

```
   A: /tmp/wbaes-res/cross/gen1/table.bin  seal: 0xadd2dade
   B: /tmp/wbaes-res/cross/gen2/table.bin  seal: 0x9b13b496
   identical tables: False (must be False); generated in 2.10s
   both unmasked with their own seeds: 0x2653f978 / 0x9153aad1, same P0: False
   A: 46f6abe52990556a6713141f65fed9a5   candidates max 1/position   5.38s   ... YES
   B: 46f6abe52990556a6713141f65fed9a5   candidates max 1/position   5.44s   ... YES
```

合并是否多泄漏（脚本第 3 节）：

```
   Q_A[a][b] ^ Q_B[a][b] fitted as D0[a]^D1[b]: 493/130560 sampled = 0.0038 (random 0.0039)
   D-labels byte-identical between A and B: 263/8192 a-values (32 tables x 256)
   A's labelling is an affine image of B's: 0/64 axes (32 tables x 2 axes)
   widest candidate set for any byte, either instance: 1; bytes where both instances agree on a single candidate: 16/16
   combining adds 0 key bytes: each instance alone already pins all 16
```

**结论**：同钥异码**不会**让攻击者多得东西，因为单个实例已经全取回；两表的字节差是随机的
（0.0038 ≈ 1/256），两个实例的 `D` 标号互不相关（0/64 轴仿射相关），因为每份产物的 lane 编码是独立随机的。
反过来说，(d) 的真正含义是：dl5 的"一份产物一个编码"没有复用风险，但也**没有**任何冗余保护 ——
一份被读表就等于全部。

## 这批脚本**没有**证明什么

- (a)(c)(d) 都需要**解掩后的表字节**（离线静态）。纯远程黑盒（只有密文）不适用。
  掩码不构成障碍（种子 0.07 s、21 个候选命中；`DATA-LAYER.md` 早已记录）。
- (b) 需要**插桩**（调试器/Frida 级）。这是"研究者级"成本线，但脚本本身 5 s。
- 只打了 `wbaes_nl_clean`。`wbaes_nl_max`、解密路径入口轮、`wbaes_vm_*` 未测，不要外推。
- (a) 的失败面没有被测量：如果 lane 表的下标不是 `P0(pt)`（即入口有更强的输入编码），
  或者成对组合不是"两个逐 lane 双射的 XOR"，本脚本的群结构就不成立。这两条只是结构性判断，
  本目录没有做对照实验。
- 没有修任何设计：`demos/wbaes/` 下的源文件、已有的攻击脚本、导出的二进制都没动。

## 复现记录（本机实跑）

| 命令 | 结果 | 墙钟 |
|---|---|---|
| `python3 hs_attack.py` | key `46f6abe5…`，密文复现 YES | 22.0 s（含 16.6 s 解掩） |
| `python3 hs_attack.py --cache /tmp/nl_plain.bin` | 同上 | 3.2 s |
| `python3 consistency_attack.py` | key 同，4096 轨迹 | 5.1 s（含建轨迹 1.3 s） |
| `python3 recoding_peel.py --cache …` | `recoding inverted: YES`，`0/16` | 3.0 s（不含解掩） |
| `python3 cross_instance.py` | A/B 均为 `46f6abe5…`，合并增益 0 | 59 s（含 2×18 s 解掩） |
