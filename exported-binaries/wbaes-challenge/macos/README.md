# 白盒 AES 二进制（逆向练习目标）

本目录 20 个 macOS arm64 可执行文件，几代构建（`*_f4` 是当前一代）：

| 文件 | 构建 | 第 0 轮输入编码 | 密钥 | 自检密文 |
|---|---|---|---|---|
| `wbaes_clean` | `-O2` | 无 | 62bc…（未公开） | `e6f48459…` |
| `wbaes_max` | `-O2` + 8 pass | 无 | 62bc…（未公开） | `e6f48459…` |
| `wbaes_clean_in` | `-O2` | 有 | **ec32…（仓库公开键）** | `24a06689…` |
| `wbaes_max_in` | `-O2` + 8 pass | 有 | **ec32…（仓库公开键）** | `24a06689…` |

| `wbaes_dl_clean` | `-O2`，表已掩码 | 有 | `98d2…`（**已提取**） | `bb28990b…` |
| `wbaes_dl_max` | `-O2` + 8 pass，表已掩码 | 有 | `98d2…`（**已提取**） | `bb28990b…` |

| `wbaes_dl2_clean` | `-O2`，随机种子掩码 | 有 | `98d2…`（**已提取**） | `bb28990b…` |
| `wbaes_dl2_max` | `-O2` + 8 pass，随机种子掩码 | 有 | `98d2…`（**已提取**） | `bb28990b…` |

| `wbaes_dl3_clean` | `-O2`，每轮异构表 + 掩码 | 有 | `fd85…`（**已提取**） | `e5a25174…` |
| `wbaes_dl3_max` | `-O2` + 8 pass，同上 | 有 | `fd85…`（**已提取**） | `e5a25174…` |

| `wbaes_dl4_clean` | `-O2`，异构表 + 每表内部编码 + 掩码 | 有 | `755e…`（**脚本提取失败**） | `abe296ee…` |
| `wbaes_dl4_max` | `-O2` + 8 pass，同上 | 有 | `755e…`（**脚本提取失败**） | `abe296ee…` |

| `wbaes_vm_clean` | `-O2`，dl4 全部 + **HSV 字节码算每轮表偏移** | 有 | `07d9…`（未公开） | `29d00ce8…` |
| `wbaes_vm_max` | `-O2` + 8 pass，同上 | 有 | `07d9…`（未公开） | `29d00ce8…` |

| `wbaes_nl_clean` | `-O2`，dl5 跨 lane 非线性重编码 + VM | 有 | `46f6…`（**已提取**，hs_attack） | `80aadc09…` |
| `wbaes_nl_max` | `-O2` + 8 pass，同上 | 有 | `46f6…`（**已提取**，hs_attack） | `80aadc09…` |

| `wbaes_vm2_clean` | `-O2`，dl5 + **一次 VM 调用算完整张偏移表，宿主从 `@hsvm_mem` 读回** | 有 | `4f06…`（**已提取**，`attacks/residual/hs_attack.py`） | `7672415a…` |
| `wbaes_vm2_max` | `-O2` + 8 pass，同上 | 有 | `4f06…`（**已提取**，同上） | `7672415a…` |

| `wbaes_f4_clean` | `-O2`，**16 位列合并** + dl5 的 32 位重编码 + VM | 有 | `3acb…`（**已提取**，`attacks/residual/w16_probe.py`） | `2c0b8f87…` |
| `wbaes_f4_max` | `-O2` + 8 pass，同上 | 有 | `3acb…`（**已提取**，同上） | `2c0b8f87…` |

**`*_f4` 是当前一代**（2026-11-18，`demos/wbaes` HEAD 构建）。一句话说清它的三种性质：

1. **它的保证是"密文等于 AES"**：`6bc1bee22e409f96e93d7e117393172a` → `2c0b8f87b6aa8d4a8c7b12d8d2227c8d`，
   与 `openssl enc -aes-128-ecb -K 3acb…` 逐字节一致，解回明文一致。
2. **它比 `*_vm2` 快 20 %，表体积一模一样**：表 70,090,816 B（不变），每列查表 28 → 20；
   同机交错 `bench_wbaes 3000`：加密 16.94 → 13.24 µs、解密 16.21 → 13.53 µs。
3. **它的取钥强度比 `*_nl` / `*_vm2` 低**：16 位 pair 表精确 XOR 可分，密钥在
   **4,096 次廉价检验、0.08 s 代数**内取回（`w16_probe.py`，`reproduces the shipped
   ciphertext: YES`）。所以这一代是**性能代，不是加固代**。

构造：MixColumns 线性 ⇒ 四个 lane 两两成对、四个输出行也两两成对，半列部分和是 16 位；
两张 2^16 项 × 16 位输出的 pair 表在一次 16 位 XOR 里相遇，四张 2^16 项解码表去掉仿射编码、
加列常量、过输出双射。列槽仍是 798,720 B（4×128 KiB pair + 8 KiB 重编码 + 4×64 KiB 解码），
所以调度块 64 B、VM 的 288 个偏移、每构建掩码种子、封印、DFA 双算全部沿用上一代，
`wbaes_vm.cpp` 一个字节没改。这一代只有一种形状：F0..F3 四族被删（它们在同一步长下把部分和
放在 8 位表里），`gen_hybrid --fam 0..3` 直接 rc 2。

预期输出：

```
plaintext : 6bc1bee22e409f96e93d7e117393172a
ciphertext: 2c0b8f87b6aa8d4a8c7b12d8d2227c8d
expected  : 2c0b8f87b6aa8d4a8c7b12d8d2227c8d
roundtrip : 6bc1bee22e409f96e93d7e117393172a
vector-match: PASS
roundtrip   : PASS
```

**`*_vm2` 是上一代**（`demos/wbaes` 的 HEAD 构建，2026-11-18）。构造与 `*_nl` 完全相同
（dl5 跨 lane 非线性重编码、异构四族、掩码 + 封印 + DFA 双算），差别只有 VM 层：

- 偏移表从“每块 288 次 `hsvm_entry`”改成“**一次调用算完 288 个偏移**”：字节码自己走
  2 方向 × 9 轮 × 16 字节，用 `St` 把结果写进 VM 内存（ISA v2，61 条指令 / 488 B，6 条 `Tld`、1 条 `St`）；
- 结果怎么出 VM：pass 发现模块里有 `unsigned char hsvm_mem[4096]` 就把它当 VM 内存面（没有则退回 alloca），
  所以宿主在调用返回后直接读这 4 KiB —— **没有新增指令**，`HSVMOpcodes.def` / 解释器 / oracle 未动；
- 计划在第一次加解密时算一次并缓存（`hy_vm_off[2][9][16]`，1152 B）；之后每块只比一次 64 B 调度块快照，
  不一样就重新走一次 VM。所以“改调度块一个字节 → 密文变”这条判据仍然成立。

实测（同机同表，`bench_wbaes 3000`，3 次运行取最小值）：

```
改前  288 次调用/块   加密 23.34 µs   解密 23.15 µs
改后  1 次调用/整表   加密 16.93 µs   解密 16.85 µs      （关 VM 的下界 17.23 / 16.68）
整张表一次调用 0.86 µs；切成 18 次 (dir,round) 调用要 15.2 µs
```

`nm` 里多一个 `_hsvm_mem`；`_hsvm_entry` 仍是直接分支（间接 `br x*` 计数 0），`bzero` 的目标就是
`_hsvm_mem`。剥离后 70,707,168 / 70,707,184 B。

**这一代的密钥已被 residual 攻击取回（同一台机器实测）**：`attacks/residual/hs_attack.py` 在
`wbaes_vm2_clean` 上 3.16 s 拿到 `4f065a03…`，AES 结果与产物密文一致（`reproduces the shipped
ciphertext: YES`）。也就是说 VM 这两条 P0 是**性能**改动，不是新的静态屏障——它把每块 288 次
VM 调用降到 1 次、耗时从 23.34 降到 16.93 µs，但表结构与 dl5 相同，dl5 的结构性攻击照旧适用。
见 `demos/wbaes/WB-DESIGN-V2.md` §十四。

**`*_vm` 是含 VM 的一代。** 与 dl4 同一套表（异构族 + lane 内部编码 + 掩码 + 封印 + DFA 双算），
差别在热路径上多了一段真在跑的 HSV 字节码（ISA v2，`Tld`）：

- 字节码部分：**每轮、每个状态字节的表偏移**。程序 43 条指令 / 344 字节，16 寄存器、
  4 KiB 内存；用 `Tld` 从表尾调度块（偏移 32/36、40/44、48、52、56）读出
  `base / round_stride / col_stride / lane_stride / pair_stride`，算出
  `base + round*stride + col*col_stride + lane_stride(fam,k)`，`St` 回 VM 内存并返回 `r0`。
  C++ 侧 `hy_mc_round` 的每个表地址都取自这个返回值。
- **不是**字节码的部分：69 MB 表数据本身（`Tld` 只读，ISA 没有"写宿主内存"的指令），
  以及配对表（`hy_pair_map`）的地址。
- 编译器只对 `wbaes_vm.cpp` 加 `-mllvm -passes=hsvm`，把 `@hsvm_bytecode` 降低成
  `@hsvm_entry` 的原生代码；其余 TU 保持 8 pass。产物里因此有 4 个符号：

  ```
  nm wbaes_vm_clean | grep hsvm
  _hsvm_bytecode  _hsvm_entry  _hsvm_table  _hsvm_table_len
  otool -s __DATA __hsvm wbaes_vm_clean    # 43 条 8 字节指令，6 条 0x10 = tld
  ```
  `_hsvm_entry` 内部没有任何间接跳转（`br x*` 计数 0）—— lowering 后是直接分支，
  不是解释器。`strip -S` 后大小 69,798,704 / 69,815,232 B（比 dl4 多 400 B）。
- **实测成本**（`bench_wbaes 3000`，同一张表，关/开 VM 两档）：

  ```
  关闭 VM：加密 4.11 µs/块   解密 4.83 µs/块
  开启 VM：加密 10.56 µs/块  解密 11.33 µs/块      (×2.6 / ×2.3)
  ```
  原因是每个块要 288 次 `hsvm_entry`（16 偏移 × 9 轮 × 2 方向），每次 40.5 ns，
  其中大部分是 pass 每次调用清零 4 KiB VM 内存。**这一代比 dl4 慢一倍多，不是免费的。**
- 这一代的值在"热路径确实由字节码驱动"，不在"表更难读"：表还是那 69 MB，
  静态提取路径与 dl4 相同。实测（同一脚本）：

  ```
  python3 demos/wbaes/extract_key.py wbaes_vm_clean --verify
    section : __DATA,__hytab fileoff=32784 size=69206080
    env     : pagesize=16384 ncpu=10 cls=128 -> 0x25c99707
    round-0 input bijections found: [11216]
    candidate mask seeds: ['0x19b53639']
    recovery failed: no candidate key           (29.0 s)
  ```
  失败原因与 dl4 相同（每格是 `E[MC·S(x)]`，随机 256 元素双射），不是 VM 的功劳。

`*_nl` 是 **dl5**：把 `demos/wbaes/attacks/` 里那两条**已经成功**的攻击（BGE 类静态剥离、
DCA 地址轨迹）挡住的一代。它不改函数（密文与旧钥逐字节对应），只改两处结构：

- 64K 成对解码表的**输出**多一层随机双射：`Q[a][b] = Z(D0[a] ^ D1[b])`。表不再是秩 1 张量，
  "一行 + 一列"拟合不出它，所以拿不到 lane 的逆；边界也从 256 项换成 **64K 两字节表**，
  值 `P[Zl⁻¹(u) ^ Zr⁻¹(v) ^ rk]`，`Zl⁻¹/Zr⁻¹` 不作为独立表存在；
- 一列的四个输出字节当作一个 32 位字，过三轮可逆**非线性重编码**
  （每轮：异或常量 → 逐字节随机双射 → 固定 4×4 MDS `(1,4,3,7)`，逆 `(11,11,9,8)`），
  下一轮边界用存的逆向 S 表还原。所以轮边界内存里没有单字节明文域状态。
- F0 也丢掉原来两张 256 项逆表，和 F1/F2/F3 共用同一张两字节边界表。

列槽因此从 768 KiB 涨到 780 KiB（表总长 **70,090,816 B**，+1.28%），每块耗时翻倍
（10.02 → 22.29 µs 加密、10.66 → 22.21 µs 解密，同钥同 VM 配置实测）。

**两条攻击在这个产物上的实测结果（本机实跑）**：

```
python3 demos/wbaes/attacks/bge_attack.py
  32/32 pair tables fitted; 9646 of 131072 sampled entries reproduced by two
  256-byte arrays, but 8672 of those lie on the a=0 row or the b=0 column that
  the fit is built from. Off those, 974/122400 = 0.0080 reproduce, against
  1/256 = 0.0039 for an unrelated table
  incomplete (0/16 bytes): round 0 did not yield the key          (rc=1)

python3 demos/wbaes/attacks/dca_attack.py --traces <harness>/dl4_traces.bin
  tag F1 (kind 144) half 0: candidates per column [0, 0, 0, 0] -> 0/16 key bytes
  tag F1 (kind 144) half 1: ... 0/16     tag F2 half 0/1: ... 0/16
  tag F3 (kind 160) half 0: ... 0/16     tag F3 half 1: ... 0/16
  iso: 8 distinct pair sums, 8 index values, conflicts 0, index == pair sum 0/8
  incomplete: 0/16 bytes                                          (rc=1)
```

**别把"这两条脚本失败"读成"抗提取"**：恢复出的边界下标仍然是成对和的**函数**（实测 0 冲突），
只是被一条未知随机双射遮住；`Q = Z∘(D0⊕D1)` 是隐藏位移问题；重编码的逆在解掩后可由
12 张逆向 S 表 + 公开 MDS 求出。这三条都没有脚本，也都没测——`demos/wbaes/WB-DESIGN-V2.md`
§十二 把它们列成"剩余攻击面"。

`*_dl4` 在 dl3 的异构之上把内部编码补齐：每条 lane 一个随机 256 元素双射，
每行两张 64K 表把两条 lane 的逆取回来，明文部分和 XOR 后再走 256 项随机边界置换
（F3 也一样，所以它的轮边界不再是仿射）。表总长仍是 69,206,080 B，调度同上。
**`extract_key.py` 在这两个文件上失败**（27.2 s / 27.4 s，`no candidate key`）——那 27 s 是
解掩 keystream 走 69 MB 的开销，不是攻击成本。这一代到底算不算更难，本节末尾如实写。

`*_dl3` 是**异构轮**一代：九轮不再共用一种表形状。生成端为每轮从四个实现族里挑一个
（F0：双 64K 表 + Q 网络；F1：四张 256×32bit 宽表；F2：十六张 MC 系数字节表；
F3：把列密钥字并进某张宽表的 32 位输出），族字节写在表尾 64 B 调度块里、随表一起掩码并封印，
运行时按这个字节分派——读表代码里没有"九轮同形"的假设。调度：

```
enc F1 F2 F3 F0 F1 F2 F0 F3 F1
dec F0 F1 F2 F0 F3 F1 F2 F0 F3
```

**这一代不提高提取成本，反而降低**：F1/F2/F3 的宽表/系数表存的就是 `MC[row][k]·S(x^k)`，
没有 F0 那层 Q 网络随机双射；MixColumns 每行都有系数 1，取一行即得 `S(x^k)`，反 S 盒就是密钥字节。
`extract_key.py`（已支持这三种形状）28 s 出钥：

```
extract_key.py wbaes_dl3_clean --verify
  mode    : mask seed 0x4ca55ca1 + input bijection @8864, round 0 family 1
  schedule: enc F1 F2 F3 F0 F1 F2 F0 F3 F1
            dec F0 F1 F2 F0 F3 F1 F2 F0 F3
  AES-128 key: fd85cd856e314ea791a828d5dab81d06
  key reproduces the shipped binary: YES          (28 s)
```

比 dl2 慢的那 20 多秒是掩码 keystream 要走 69 MB 才读到表尾调度块，不是难度。
异构买到的是"同一种形状的匹配器只认得一两种轮"，不是抗提取；理由写在
`demos/wbaes/DATA-LAYER.md` 第七节。旧的 dl / dl2 八个产物保留不动，作为同形表（F0）的历史对照。


`*_dl2` 把种子改成与密钥无关的随机值、并以 4 个字（volatile）存盘。**也已实测攻破**（5.0 s）：

```
extract_key.py wbaes_dl2_max --verify
  candidate mask seeds: ['0xf32a8adc']
  mode    : mask seed 0xf32a8adc + input bijection @11480
  AES-128 key: 98d272d16d6cc9d6ecd48a26c0ca69d3
  key reproduces the shipped binary: YES
```

定位方式不靠猜：解掩循环里四行 `ldr wX,[xN,#0/4/8/12]` 加两条 `eor` 就是
`f0^f1^f2^f3`，往前回溯 `add`/`adrp` 还原地址（本文件 0x2cb8），读 4 个字 XOR 即得种子。
因为种子与密钥无关，这一代**不再有**"FNV 验钥"那条捷径，验证只能靠结构 + 自检密文。

如实说：`dl2` 的种子仍然在产物里，只是从"一条立即数"变成"四个字 + 一次 XOR"；
攻击成本 4.9 s → 5.0 s。这条路的真正上限在 DATA-LAYER.md 第六节已经写清楚。

`*_dl` 两代是**数据层加密**版本：表在二进制里是密文，运行时验封印后解掩到私有缓冲。
**这套防护已实测攻破**（约 4.9 s，`extract_key.py` 现在自带）：

```
extract_key.py wbaes_dl_max --verify
  candidate mask seeds (MOVZ/MOVK in __text): ['0x31d80fe2']
  mode    : mask seed 0x31d80fe2 + input bijection @11663
  mask seed vs FNV-1a(key): 0x31d80fe2 -> match
  AES-128 key: 98d272d16d6cc9d6ecd48a26c0ca69d3
  key reproduces the shipped binary: YES
```

攻击面是三件事叠在一起失效的：

1. 掩码本身是 `xorshift32` 的 XOR 流，种子 `HY_MASK_SEED` 以 `MOVZ/MOVK`
   立即数形式躺在 `__text`（本文件 0x100001858），顺着 xorshift 指令三连
   （`lsl #13` / `lsr #17` / `lsl #5`）往前找 11 条指令就能捞出来。
2. 种子就是 `FNV-1a(密钥)`——**它是密钥的函数**，一旦拿到就等于给密钥留了个
   32 位校验位（提取结果与它一致即为独立验证）。
3. 解掩后仍是同一套表结构，双射取逆 + 64K 表一致性检查照旧。

结论：数据层掩码在"密钥派生种子 + 常量留在代码里"的组合下只是把攻击从 3.7 s
拖到 4.9 s。真正要提高成本，掩码种子必须与密钥无关且不可由二进制推出
（例如外部提供、或每次会话协商），否则它只是又一层混淆。

**注意（此前的文档错误，已更正）**：`*_in` 两个文件生成时用的是仓库里的 `ec32…` 密钥
（自检密文 `24a06689…`），不是 `62bc…`。原 README 把 `*_in` 的 expected 写成了 `e6f48459…`，
那一行是错的。也正因如此，**`*_in` 不适合作为挑战目标**——密钥在仓库里公开；
它们只用于演示"输入双射能挡住朴素提取器"。

两个都已 `strip -S`（无调试信息；本地符号仍在——`nm -a` 可见 37 个，如 `hy_mc_round`；
前几代同样如此，此前文档写"无符号表"不准确）。校验和见 `sha256.txt`。

## 运行

```bash
./wbaes_max
```
预期输出（内容固定，两个文件相同）：
```
plaintext : 6bc1bee22e409f96e93d7e117393172a
ciphertext: e6f48459ad3535934f51eded1c32a2a7
expected  : e6f48459ad3535934f51eded1c32a2a7
roundtrip : 6bc1bee22e409f96e93d7e117393172a
vector-match: PASS
roundtrip   : PASS
```

自检明文 16 字节、AES-128-ECB。**密钥没有随二进制一起公开**，也不在本仓库里。

`*_dl3` 两个的预期输出（密钥已换，密文随之改变）：
```
ciphertext: e5a25174e8b329127bcaac8f3297e16e
vector-match: PASS
roundtrip   : PASS
```

`*_vm` 两个的预期输出（又换了一把钥）：
```
plaintext : 6bc1bee22e409f96e93d7e117393172a
ciphertext: 29d00ce827afdb377671f07402cda1f5
vector-match: PASS
roundtrip   : PASS
```

`*_dl4` 两个的预期输出（又换了一把钥）：
```
ciphertext: abe296eea2625f251ba57ed0b408272c
vector-match: PASS
roundtrip   : PASS
```

`*_nl` 两个的预期输出（dl5 换钥后）：
```
plaintext : 6bc1bee22e409f96e93d7e117393172a
ciphertext: 80aadc09777696c9d492a7e53b3b15b0
vector-match: PASS
roundtrip   : PASS
```

## 结构提示（不做隐瞒，这些是你该自己验证的）

- `*_vm` 多一个 `__DATA,__hsvm` 节（344 字节字节码）和 `_hsvm_entry` 函数；
  调度块尾部（偏移 32..59）多出 7 个布局字（base/round_stride/col_stride/lane_stride/
  pair_stride），它们和族字节一起被掩码、被封印，读它们的是 VM 而不是 C++。
- 表区在 `__DATA,__hytab`，长度 69,206,080 字节（dl3/dl4/vm；dl/dl2 是 69,206,016）：9 加密轮 + 末轮
  的配对表 + 9 步逆向路径 + 表尾 64 B 调度块。每轮/每列的表槽大小相同，槽内按族的形状铺表。
- 每轮的实现族写在表尾调度块（`dir*16 + round`，第 10 个字节是校验），随表一起掩码和封印；
  所以"数表槽形状推轮数"不再成立，但调度块本身在解掩后是明文可读的。
- dl4 的列槽里多了 8 张 64K 表（512 KiB，槽是 768 KiB）：两条 lane 的随机双射就在这 8 张表里
  被取逆，另外 4 张 256 项表是轮边界；宽表/系数表只存 `E[MC[row][k]·S(x)]`。
- `*_nl` 的列槽是 798,720 B：`[0,4096)` lane/系数表（F0 是两张 512 KiB 前置表，与其它族区段
  重叠但互不读取）、`[4096,528384)` 八张 64K 成对解码表、`[528384,536576)` 3 轮重编码的
  12 张正向 S 表 + 12 张逆向 S 表 + 12 个常量、`[536576,798720)` 四张 64K 两字节边界表。
- `kHyTab` 是 `private_extern` 符号；strip 之后仍可从节表定位。
- 没有 S 盒、没有轮密钥异或：所有轮函数都在表里。
- 解密路径与加密路径共用同表区。

## 已知弱点（先说清楚，免得误判难度）

0. **当前一代 `*_f4` 在取钥强度上比 `*_nl` / `*_vm2` 弱**：它的 16 位 pair 表精确 XOR 可分，
   4096 次仿射一致性检验（0.08 s 代数，全程 32 s 含解掩）就能取回 `3acb…` 并复现密文。
   这一代出货的理由是性能（快 20 %、体积不变）与"密文等于 AES"，不是加固。
   它仍然挡住的是**改表/改调度块**（封印 + DFA 双算 + VM 数据驱动），不是**读表**。
1. **表级密钥提取：旧构建可行，新构建在朴素攻击下失效（实测）。**
   ```
   extract_key.py wbaes_max      → AES-128 key: 62bce36db18696c154751334adb74da7   (约 2 s)
   extract_key.py wbaes_max_in   → recovery failed: no candidate pair
   ```
   `*_in` 给第 0 轮加了输入侧双射：表项不再按明文下标排列，索引映射写在
   `hy_in.h`（16×256 表）里并烘进二进制。**这只挡朴素提取器**——读出那张双射表
   再取逆，攻击路径就恢复。**已实测**（`extract_key.py` 现在自动识别）：

   ```
   extract_key.py wbaes_max_in   → mode: round-0 input bijection @file offset 11471
                                   AES-128 key: ec326393a354ed3ee5d1735964fd8a32   (约 3.7 s)
   extract_key.py wbaes_clean_in → mode: round-0 input bijection @file offset 7184
                                   AES-128 key: ec326393a354ed3ee5d1735964fd8a32   (约 3.7 s)
   ```

   `HY_P0` 在 `__TEXT,__const`（该节从 424 B 涨到 4,520 B 即是它），16×256 逐行是
   置换；把它取反后按 `P0[hy_sr_src(dst)]` 重标定表项，照旧每个 64K 表 256×256
   搜索即可。**代价**：攻击从 2 s 变成 3.7 s，仅此而已。

   注意：`*_in` 这对产物实际是用仓库里那把 `ec32…` 生成的（输出 24a06689…，
   与 `wbaes_max` 的 e6f48459… 不同），并非"同一把钥只加输入编码"。

1b. **`*_dl4`：脚本提取失败，但别把它当"抗提取"。**
   ```
   extract_key.py wbaes_dl4_clean → recovery failed: no candidate key   (27.2 s)
   extract_key.py wbaes_dl4_max   → recovery failed: no candidate key   (27.4 s)
   extract_key.py wbaes_dl3_clean → AES-128 key: fd85…                  (27.7 s，对照)
   ```
   dl4 的每一格是 `E[MC[row][k]·S(x)]`（`E` 是随机 256 元素双射），
   `recover_key_tbox()` 认的"某一行等于 `MC·S(x^k)`"这条等式第一次就不成立。
   实测第 0 轮单表对密钥**零信息**：把一行看成任意双射的输出，256/256 个候选字节都能自洽
   （dl3 是 1024/1024 逐格吻合、只剩唯一解）。但那 27 s 是解掩 keystream 走 69 MB 的开销，
   没有任何有意义的计算发生；跨轮攻击（BGE 类）、解掩后内存差分、多故障 DFA 都**没有做也没有测**。
   所以正确的说法是"朴素路径已关，成本未知"，不是"提取不了"。
   `demos/wbaes/DATA-LAYER.md` 第八节有实测记录。

1c. **`*_nl`：仓库里那两条攻击脚本都失败，但残留路径未测。**
   现状（实测）：`bge_attack.py` 0/16 字节、`dca_attack.py` 0/16 字节，原因见上一节的输出；
   经典单字节 CPA 依旧零泄漏（16/16 槽位的 lane 表下标逐位等于公开的 `P0(pt)`）。
   未做：`Q = Z(D0⊕D1)` 的隐藏位移求解、基于"未知双射一致性"的边界下标统计
   （需要 ~2^12 条轨迹）、解掩后对重编码求逆再剥表。所以正确的说法是
   "这两条脚本关了"，不是"提取不了"。

   **2026-11-18 复测（`demos/wbaes/attacks/wblib.py` 读表，`wbaes_nl_max`）**：
   `extract_key.py` 在 nl 上按尺寸直接拒绝（blob 70,090,816 B，是 dl4/dl5 几何），
   所以下面是手工探针的实测结论：

   | 检查 | 结果 | 含义 |
   |---|---|---|
   | 解掩 + 调度块 | 种子定位成功，enc `F1 F2 F3 F0 F1 F2 F0 F3 F1` | 表区可完整读出 |
   | 第 0 轮 Q 表（64K×8）秩 1 检验 | 违例 **64,500 / 65,025**（另一张 64,530） | `Q = Z(D0⊕D1)` 不能按行/列分解，静态 XOR 剥离确实关闭 |
   | 重编码 12 正 + 12 逆表 | 24 张全是置换，且 `si[s[x]]==x` 全部成立 | 三轮重编码**可以离线精确求逆**，它不是障碍 |
   | 边界 64K 表的行比集合 | 256 个、**在复合下封闭 100/100** | 边界表是 `(Z₂)⁸` 的**群同位**：隐藏位移结构真实存在、可恢复 |
   | Q 表行比集合 | 256 个、封闭 100/100 | 同上 |
   | Q 与 BDY 行比集合交集 | **1**（只有恒等） | 两者的外层双射 `Z` 与 `ρ` 是不同标定，不能直接对齐 |

   **A/B 两路都做了（2026-11-18）**，都没有拿到密钥，但卡点已经定位到具体机制：

   - **A（静态：同位 + 仿射等价）**：Q 表与边界表的行比群阶都是 256，但抽 40 个群元素
     只有 1 个是仿射的（恒等）——说明 lane 编码是**非线性随机置换**，BGE 那条
     “把编码当仿射恢复”的路在这里不成立。
     新发现一条**可读数但无用**的点：最后一轮 8 张 pair 表是 16-bit 打包
     `outv[i0][a] | (outv[i1][b] << 8)`，按字节可分离，所以 16 张 `outv[256]` 能直接读出
     （每张都是置换）。但 `outv[dst][a] = S(Pi8[a]) ^ rk10[dst]`，输入重标定 `Pi8` 未知，
     实测没有任何 `(k, c)` 能让 `outv == S(a^k) ^ c`。同样地，加密末表与解密入口表复合
     `F[E[a]] = D9(Pi8[a])` 会把 `rk10` 完全消掉——两张表之间只剩纯编码关系。
   - **B（动态：轨迹 + DCA/BGE 脚本）**：`bge_attack.py` 0/16、`dca_attack.py` 0/16
     （2.85 s）。关键诊断：**16/16 槽位的 lane 表下标逐位等于公开的 `P0(pt)`**，
     即地址不携带密钥；边界表 4 字节 MITM 每列 0 候选。Q 表的“一行+一列”拟合在
     轴外只有 0.0080 命中（随机期望 0.0039），确证它不是 `D0⊕D1`。

   **A 已经成功（2026-11-18 实测）**：`demos/wbaes/attacks/residual/hs_attack.py`
   把上面这条“结构层已拆开、密码层没有”的判断走完了最后一步——
   同位求解拿到 `D0[a]^D0[0]`、`D1[b]^D1[0]` 的**群元素**，剩下的
   `|GL(8,2)|·2^8 = 2^70.2` 规范自由度用一个**规范不变的仿射一致性检验**消掉
   （64 个字节位置 × 256 猜测 = 16,384 次检验，每位置唯一候选）：

   ```
   hs_attack.py --binary wbaes_nl_max --cache /tmp/nl_plain.bin
     32 张 pair-decode 表全部分解：2097152/2097152 项，Z 在 32/32 表里是双射
     recovered key: 46f6abe52990556a6713141f65fed9a5
     AES-128(6bc1bee2…) = 80aadc09777696c9d492a7e53b3b15b0 = shipped ct
     reproduces the shipped ciphertext: YES      （5.58 s，静态，无轨迹）
   ```

   独立复核（openssl + 二进制自检）：`openssl enc -aes-128-ecb -K 46f6…` 对
   `6bc1bee2…` 得 `80aadc09…`，与 `wbaes_nl_max` 输出一致。

   另外一条对照：`recoding_peel.py` 证明重编码可无成本求逆（864/864 逆表、
   1152/1152 实例验证），剥完后就是 dl4 形状（每字节一个任意双射），
   再走 `D0⊕D1` 拟合仍然只有 0.79% 轴外命中 → 0/16；也就是说
   **重编码一分钱没花掉攻击者的时间，真正挡路的是 Q 的输出双射 Z**，
   而 Z 恰好被规范自由度吸收掉了。

   **B 也成功（轨迹路）**：`residual/consistency_attack.py` 用 256 条真实轨迹
   （`trace_harness` 插桩副本，不改仓库文件）把 16-bit Feistel 散布反解出边界表下标两半，
   再用碰撞对做 2 字节 MITM：

   ```
   consistency_attack.py --binary wbaes_nl_max --n 256
     64 条轨迹起，8 个 half 全部收敛到唯一 2 字节候选；256 条时每 half 109–139 对碰撞
     recovered key: 46f6abe52990556a6713141f65fed9a5
     reproduces the shipped ciphertext: YES
     分析 1.02 s（MITM 0.06 s），含建轨迹约 2 s
   ```

   所以这一代的正确定位是：**“朴素路径已关，但结构性攻击 5.6 秒、轨迹攻击 1 秒就出钥”**，
   不是“抗提取”。老的两条脚本（DCA/BGE）仍是 0/16，它们只覆盖了地址维度的泄漏，
   没有处理“输出双射吸收密钥”这一层。

2. **DFA（故障注入）已被检测。** 加密与解密都做两遍独立遍历并比对，
   不一致时输出随机垃圾（不给故障密文），所以经典 DFA 拿不到差分样本。
   想绕需要多故障/共模故障或直接 patch 校验。
3. **表完整性有封印。** 首次调用做一次全表 FNV-1a 校验，之后每次调用做抽样校验；
   改表会得到随机输出而不是错密文。
4. 上述三条本身也可被逆向对抗（patch 校验、找抽样盲点）。

## 有价值的观察点

- 取回密钥需要多久？`wbaes_max` 的混淆把时间拉长了多少？
- 能否在不 patch 校验的前提下让 DFA 重新可行（双故障 / 共模）？
- 抽样校验（stride 4096）的盲区能否被利用？
- 能不能定位并绕过 `hy_table_intact()` 的全表校验？

## 纪律

- 这个二进制里的密钥在交付给任何人之后即视为**已泄露**，只能当教学样本，不能用于真实数据。
- 复现构建需要仓库里的 `gen_hybrid.cpp` 与同一把密钥；本目录只放产物，不放源码与密钥。
- 构建方式（供你核对平台差异，不是给你的提示）：
  ```
  # wbaes_vm_*/wbaes_nl_* 还需要 -DWBAES_HAVE_VM，且 wbaes_vm.cpp 单独走 hsvm pass：
  clang++ -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR [-DWBAES_HAVE_VM] -I. -I<repo>/demos/wbaes \
          demo_wbaes.cpp hy_tab.S [wbaes_vm.o] \
          [-mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla] -o <out>
  ```
