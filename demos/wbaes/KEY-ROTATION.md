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
clang++ -O2 -std=c++17 -DWBAES_BAKED -DWBAES_NO_MIR -I$W \
        $W/demo_wbaes.cpp hy_tab.S -o wbaes_baked_keyrot

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
