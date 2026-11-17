# 白盒 AES 二进制（逆向练习目标）

两个 macOS arm64 可执行文件，功能相同、构建不同：

| 文件 | 构建 | 大小 |
|---|---|---|
| `wbaes_clean` | `-O2`，无混淆 | 69,781,560 B |
| `wbaes_max` | `-O2` + Polaris 8 pass（`alias,gvenc,indcall,indbr,mba,sub,bcf,fla`） | 69,798,104 B |

两个都已 `strip -S`（无符号表、无调试信息）。校验和见 `sha256.txt`。

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

## 结构提示（不做隐瞒，这些是你该自己验证的）

- 表区在 `__DATA,__hytab`，磁盘偏移 32768，长度 69,206,016 字节（= 10 轮 + 逆向路径的 64 KiB 表）。
- `kHyTab` 是 `private_extern` 符号；strip 之后仍可从节表定位。
- 没有 S 盒、没有轮密钥异或：所有轮函数都在表里。
- 解密路径与加密路径共用同表区。

## 已知弱点（先说清楚，免得误判难度）

1. **表级密钥提取是可行的，而且很快。** 第 0 轮的表项直接暴露结构，
   `demos/wbaes/extract_key.py` 这类方法能在数秒内取回密钥。
   所以"能不能拿到密钥"不是这道题的价值所在。
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
