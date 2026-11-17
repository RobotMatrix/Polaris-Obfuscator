# 白盒 AES 换钥与重新构建（2026-11-17）

## 1. 产物路径

| 用途 | 路径 |
|---|---|
| **换钥后新构建的可执行文件** | `demos/wbaes/exported-binaries/final-max-10pass/hybrid-baked/macos/wbaes_baked_keyrot_ec326393` |
| 构建时的工作副本（含 69 MB 表） | `/tmp/wbaes-keyrot/wbaes_baked_keyrot`、`/tmp/wbaes-keyrot/hy_table.bin` |
| 换钥前既有二进制（旧钥） | `.../hybrid-baked/macos/wbaes_baked_hybrid_10pass` |
| 换钥工具 | `demos/wbaes/rotate_key.py` |
| 自检向量（单一来源） | `demos/wbaes/wbaes_testvec.h` |

新二进制 SHA256（前 16）：`6336604ece6eda73`；表文件：`23271bc6bc616d47`。

## 2. 本次使用的密钥

| 项 | 值 |
|---|---|
| AES-128 密钥 | `ec326393a354ed3ee5d1735964fd8a32` |
| 自检明文 (NIST SP800-38A ECB-AES128) | `6bc1bee22e409f96e93d7e117393172a` |
| 自检密文 | `24a06689d532680695416c13b93c7405` |
| 分片偏移 K / C / CH | `{26,48,11,35}` / `{17,38,50,60}` / `{37,32,56,31}` |

分片结构保持原设计：`key_byte(i) = KBLK[i>>2][KOFF+(i&3)] ^ CBLK[i>>2][COFF+(i&3)]`，
每片 4 字节 FNV-1a 校验值写入 `CHBLK`。`part` 为随机 4 字节，
`cover = part ^ key_chunk`，因此两块都不呈现密钥形态。

上一把钥 `d796fc6e…` 仍可从 git 历史取回；旧二进制保持可用。

## 3. 换钥步骤

```bash
W=/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/demos/wbaes
cd $W

# 1) 改写密钥分片 + 自检向量（不给 --key 则用系统熵源生成）
python3 rotate_key.py                      # 或 --key <32 hex> --seed N 复现

# 2) 重新生成编码表（表即密钥；读 key_byte()）
mkdir -p /tmp/wbaes-keyrot && cd /tmp/wbaes-keyrot
clang++ -O2 -std=c++17 -I$W $W/gen_hybrid.cpp -o gen_hybrid
./gen_hybrid hy_table.bin          # 打印 table-check / seal-check PASS

# 3) 进链接并重新编译白盒可执行文件
cp $W/hy_tab.S .
clang++ -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -I. -I$W \
        $W/demo_wbaes.cpp hy_tab.S -o wbaes_baked_keyrot   # -I. 用于生成出的 hy_seal.h

# 4) 运行自检
./wbaes_baked_keyrot
```

## 4. 本次执行结果

```
env: pagesize=16384 ncpu=10 cls=128
table-check PASS
seal-check PASS
wrote hy_table.bin (69206016 bytes)
```

新二进制：

```
plaintext : 6bc1bee22e409f96e93d7e117393172a
ciphertext: 24a06689d532680695416c13b93c7405
expected  : 24a06689d532680695416c13b93c7405
roundtrip : 6bc1bee22e409f96e93d7e117393172a
vector-match: PASS
roundtrip   : PASS
```

旧二进制（对照，未改动）：

```
ciphertext: de23992aa3c7427f3ad40fda83730d07
vector-match: PASS
```

openssl 独立复核（不经过本项目代码）：

```bash
printf '6bc1bee22e409f96e93d7e117393172a' | xxd -r -p \
  | openssl enc -aes-128-ecb -K ec326393a354ed3ee5d1735964fd8a32 -nopad | xxd -p
# 24a06689d532680695416c13b93c7405   ← 与新二进制输出一致
```

## 5. 换钥过程中发现并修复的缺陷

**自检向量被硬编码在两处。** `wbaes_key.h` 与 `demo_wbaes.cpp`（BAKED 分支）
各存了一份 `test_pt`/`test_ct`。换钥时只更新前者，发布版自检仍比对旧密文：

```
ciphertext: 24a06689…   expected: de23992a…   vector-match: FAIL   ← 换钥后首轮
```

这不是 AES 算错（密文与 openssl 一致、回环 PASS），而是自检基准过期。
修复：新增 `wbaes_testvec.h` 作为唯一来源，两个文件都改为 include；
`rotate_key.py` 现在同时写 `wbaes_key.h` 与 `wbaes_testvec.h`。

为什么不能直接让 `demo_wbaes.cpp` include `wbaes_key.h`：那会把密钥分片链进发布
二进制，违反"发布二进制不链接密钥分片"的设计前提。向量本身不是密钥，可以外置。

## 6. 注意事项

- **表与环境绑定**：散布密钥 = `mix(pagesize, ncpu, cachelinesize)`。本次表按
  本机 `16384/10/128` 生成；换到别的设备类必须用
  `--pagesize/--ncpu/--cls` 重新生成，否则下标错位、输出垃圾（这是设计行为）。
- **表即密钥**：只改 `wbaes_key.h` 不重新生成 `hy_table.bin`，二进制仍是旧钥。
- **69 MB 表**：每次换钥都要重新生成并重新链接，产物 +69 MB；不要把表放进 git。
- **旧钥仍在历史里**：换钥不等于吊销；若该钥曾用于真实数据，需按泄露处理。
- **本次操作涉及 `demo_wbaes.cpp` 的恢复**：编辑过程中一段代码被误删，已从 HEAD
  逐段恢复（S 盒打散块、`struct Affine`、`extern "C"` 声明、`#endif`）。
  当前文件 1402 行，相对 HEAD 的差异为：`wbaes_testvec.h` 引用、`kHyTab` 外部声明，
  以及换钥前的未提交改动。**恢复部分取自 HEAD 版本，若该段内原有未提交修改，
  已被 HEAD 内容覆盖，请用 `git diff demos/wbaes/demo_wbaes.cpp` 复核。**

## 7. 表级密钥提取复核（extract_key.py）

`extract_key.py` 只读二进制本身（`__DATA,__hytab` 段），不读 `wbaes_key.h`，
用来回答"这张表还藏不藏得住密钥"。

```bash
python3 extract_key.py .../hybrid-baked/macos/wbaes_baked_keyrot_ec326393 --verify
```

结果（2026-11-17 复核）：

```
section : __DATA,__hytab fileoff=32768 size=69206016
env     : pagesize=16384 ncpu=10 cls=128 -> 0x25c99707
AES-128 key: ec326393a354ed3ee5d1735964fd8a32
local AES-128 ECB: 24a06689d532680695416c13b93c7405   == 二进制自检密文
key reproduces the shipped binary: YES
```

原理：第 0 轮用主密钥且**没有输入编码**（`gen_hybrid` 对 `r==0` 传
`InPinv=nullptr`），表项即 `Q(col,row,side)[ S(x^k0) ^ S(y^k1) ]`。按
`S(x^k0)^S(y^k1)` 分组必须同值，这个一致性把每 64K 表变成 256×256 的候选搜索，
8 张表（4 列 × 2 侧）在数秒内还原 16 字节。分片散置、decoy、FNV 校验都不参与
这条路径。

**加固建议**：给第 0 轮也加输入侧编码（像非 baked 路径 `wb_idx`/`nl_byte` 那样
打散下标，或在 sbox 前套双射），使表项不再等于 `S(x^k0)^S(y^k1)`；否则拿到二进制
即可复现上述提取。

**同一工具在旧表上的对照**：用仓库当前的 `hy_table.bin`（旧钥表）重建的 demo
提取出 `d796fc6e49595e5f366a5e55744431be`，其本机 AES 结果与二进制输出的
`de23992aa3c7427f3ad40fda83730d07` 一致——说明提取的是"这张表实际用的密钥"，
与自检向量里的新钥无关。也说明当前工作树的 `hy_table.bin` 仍是换钥前的表，
重建产物会 `vector-match: FAIL`。


## 8. DFA 加固（2026-11-17，`wbaes_hybrid.inc`）

烘焙路径原先只有单次遍历、无输出校验，这正是外部 DFA 报告能用"1 条正确 + 8 条故障密文"
取回密钥的原因。现在 `hy_encrypt` 与 `hy_decrypt` 都拆成 `*_once` + 外层双次遍历：

- 两份密文（明文）比对不同 → 置 `g_key_tampered |= 0x8000` 并输出随机垃圾，
  **不输出任何一份**，切断差分样本；
- 代价：2× 表访存；
- 测试钩子 `-DWBAES_DFA_SELFTEST` 只在测试构建里翻转一个状态比特，
  用来证明检测确实生效（该构建下 `vector-match: FAIL` 且输出为随机值）。

正常构建自检仍为 `vector-match: PASS` / `roundtrip: PASS`，产物 `wbaes_baked_dfa`（69,781,520 B）。

细节与剩余风险见 `DFA-ANALYSIS.md`。**注意**：本文 §7 的表级提取短板**没有修**——
第 0 轮缺输入侧编码的问题依旧，`extract_key.py` 仍可在数秒内取回密钥；
做了 DFA 双算不等于解决了静态提取，两者是不同攻击面。

## 9. 表完整性与 DFA 双算（2026-11-17）

- `gen_hybrid` 现在同时写出 `hy_seal.h`（全表 FNV-1a + stride 4096 抽样值），
  编译时需加 `-I.` 指向生成本目录；缺这个文件会编译失败（不给"静默用旧表"的机会）。
- 运行时首次调用做一次全表校验（69 MB，约数十毫秒），之后每次调用做抽样校验。
- 实测翻转表区一个字节：输出变随机垃圾，`vector-match: FAIL`。
- 已知边界：校验代码本身可被 patch；抽样只覆盖 stride 4096 上的位置。

**注意**：`gen_hybrid` 每跑一次都会生成不同的表（内部随机置换），
所以 `hy_table.bin` 与 `hy_seal.h` 必须来自同一次生成，二进制也必须用这一次的表重编。

## 10. 第 0 轮输入侧双射（2026-11-17，实测前后对照）

§7 的短板是第 0 轮直接把明文当表下标，于是表项等于 `S(pt^k0)`。现在 `gen_hybrid`
给第 0 轮也加了一层输入双射：表按下标 `P0(pt)` 排列，运行时在第一次查表前套一次 `P0`
（`hy_in.h`，16×256 表，随表一起烘进二进制）。内部语义不变，第 0 轮仍然看到明文，
所以解密路径不需要额外变换。

前后对照（同一把钥 `62bc…`，同一 `extract_key.py`）：
```
旧构建 wbaes_max      → AES-128 key: 62bce36db18696c154751334adb74da7  （约 2 s）
新构建 wbaes_max_in   → recovery failed: no candidate pair
新构建 wbaes_clean_in → recovery failed: no candidate pair
build 自检            → vector-match PASS / roundtrip PASS（两代都过）
```
**边界**：这只挡住"按明文下标直接搜"的提取器。双射表是二进制里的数据，
读出来取逆之后同一攻击应当复活——这一点尚未用改造过的提取器实测，属于预期而非结论。

## 11. dl4 的换钥（2026-11-17，实测）

换钥流程本身没变（§3 的 1–4 步），只是新一代的表形状（每个 lane 一层随机双射 +
每行两张 64K 组合表 + 256 项随机边界，见 `AFFINE-ROUNDS.md` 第八节）。本次：

```
$ python3 rotate_key.py
key      : 755e563b1dffd249ef552c1bb778de29
test_pt  : 6bc1bee22e409f96e93d7e117393172a
test_ct  : abe296eea2625f251ba57ed0b408272c
offsets  : K=[49, 7, 27, 16] C=[45, 45, 35, 56] CH=[23, 54, 53, 12]

$ ./gen_hybrid hy_table.bin
env: pagesize=16384 ncpu=10 cls=128
table-check PASS / seal-check PASS
wrote hy_table.bin (69206080 bytes)          # 0.92 s

$ ./wbaes_dl4_clean   # 和 wbaes_dl4_max
vector-match: PASS / roundtrip: PASS
```

`openssl enc -aes-128-ecb -K 755e… -nopad` 独立复核得到同一密文。
产物：`exported-binaries/wbaes-challenge/macos/wbaes_dl4_{clean,max}`，`strip -S` 后
69,798,304 / 69,814,832 B，校验和进 `sha256.txt`。

