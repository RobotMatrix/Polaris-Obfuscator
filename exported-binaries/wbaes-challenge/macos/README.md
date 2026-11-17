# 白盒 AES 二进制（逆向练习目标）

四个 macOS arm64 可执行文件，两代构建：

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
- `kHyTab` 是 `private_extern` 符号；strip 之后仍可从节表定位。
- 没有 S 盒、没有轮密钥异或：所有轮函数都在表里。
- 解密路径与加密路径共用同表区。

## 已知弱点（先说清楚，免得误判难度）

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
  clang++ -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -I. -I<repo>/demos/wbaes \
          demo_wbaes.cpp hy_tab.S [-mllvm -passes=alias,gvenc,indcall,indbr,mba,sub,bcf,fla] -o <out>
  ```
