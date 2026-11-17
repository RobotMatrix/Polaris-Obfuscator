# 数据段：混淆器确实够不着（实测）

## 一、结论

8 个 Polaris pass 只改代码，**表区一个字节都没动**。

```
exported-binaries/wbaes-challenge/macos/wbaes_max_in   (8 pass 构建)
  与 gen_hybrid 生成的 hy_table.bin 逐字节比较:
    区域相同:      True
    69,206,016 B   抽样 16,896 / 16,896 个 4 KiB 块完全相同
```

这与外部逆向者的计时一致：clean 1.93 s、max 1.95 s —— 读表路径不受混淆影响。

## 二、为什么 pass 够不着：两层限制

**第一层：`gvenc` 要求全局量在 IR 里有 initializer。**
`hy_tab.S` 用 `.incbin` 把 69 MB 表放进 `__DATA,__hytab`，C++ 侧只看到声明：

```
$ clang++ -S -emit-llvm demo_wbaes.cpp | grep kHyTab
@kHyTab = external constant [0 x i8], align 1        <-- 无 initializer，长度 0
```

`GlobalsEncryption.cpp:81` 的条件是
`GV->isConstant() && GV->hasInitializer() && (isIntegerTy || isArrayTy)`，
装饰一个没有 initializer 的声明无从下手，直接跳过。

**第二层：linkage 门。** 同一个 pass 只处理 internal / private linkage
（`GlobalsEncryption.cpp:85-86`）。我试过把 hidden-visibility 的 external 也放进来，
重新编译 clang 后实测：表区仍是原文（在 32768 处找到完整明文表）。
所以 linkage 不是唯一门，第一层才是根本原因 —— 该改动已回退，不留无效代码。

## 三、这意味着什么

- 编译器侧的混淆器按设计只处理**指令**；对「数据从哪来」一无所知。
  任何以 `.incbin` / 资源文件 / dylib 形式进二进制的数据，都绕过了它。
- 对手拿到的白盒二进制里，表就是明文：逆向者的 8 张第 0 轮表还原就是这个前提。
  8 pass 的代价全花在代码上，对静态读表零作用。

## 四、要真的做数据层，只有一条路：在生成端加密

`gen_hybrid` 是唯一知道表结构的地方，所以加密必须发生在这里，而不是编译器：

1. 生成表后按页（例如 4 KiB）用 keystream 加密，key 由主密钥派生；
2. 运行时首次使用某页时解密到私有缓冲，或启动时整体解密一次；
3. 索引散布已经和 `env` 绑定，可把页密钥派生也挂上去，让「拷到别的机器就能解」失效。

**买到的**：静态读表失效——对手必须先实现解密器，`extract_key.py` 这类脚本直接读表会拿到密文，
第 0 轮表项不再是 `S(pt^k)`。
**买不到的**：调试器在解密后 dump 内存一样能拿到明文表；自解密器本身在二进制里。
所以这是抬高静态分析成本，不是防止提取。

**成本**：启动时全表解密 69 MB 约数毫秒；按页惰性解密则几乎没有常驻开销，但每个查表要加一次
「页已解密？」判断。

## 五、生成端加密：已实现并验证（2026-11-17）

`gen_hybrid` 在写文件前用 key 派生的 xorshift 流掩掉全表，并输出 `HY_MASK_SEED`；
运行时第一次调用时验封印（密文全表 + 密文抽样），然后一次性解掩到私有缓冲，
之后所有查表走 `hy_tab_ptr`。

**踩到的坑（值得记）**：第一版是原地解掩 `const_cast<uint8_t*>(kHyTab)`，
`-O0` 完全正确、`-O2` 稳定输出错密文（两次运行结果相同，所以不是毒化路径）。
根因是往 `const` 对象里写属 UB，优化器据此假定表内容不变。
改成 `static uint8_t hy_tab_buf[HY_TABLE_BYTES]` + 指针间接后，`-O2` 通过。
`HY_DEBUG` 下可直接对照：解掩后前 4 KiB 的 FNV 与生成端明文一致（`8102236c`）。

实测（key 未公开的那一代）：
```
wbaes_dl_clean / wbaes_dl_max   vector-match PASS, roundtrip PASS
extract_key.py wbaes_dl_clean   → recovery failed: no candidate key
                                  （0.79 s，连输入双射都找到了，仍解不出）
```

**买到的**：静态读表失效——表区是密文，提取器连第 0 轮表结构都拼不出来。
**已被攻破（2026-11-17，同一份 extract_key.py 的更新版）**：
  `extract_key.py wbaes_dl_clean → AES-128 key: 98d272d16d6cc9d6ecd48a26c0ca69d3`
  因为 `HY_MASK_SEED` 就烘在二进制里，提取器读到它、生成同一串 keystream、解掩后再跑原算法即可。
  换句话说：**静态掩码只挡住了"没有更新脚本"的那一版攻击者**，成本约等于写 15 行代码。

**买不到的**：解密到私有缓冲后，调试器 dump 内存照样拿到明文表；
`HY_MASK_SEED` 就在二进制里，写个 15 行解掩器即可绕过静态防护。
这是抬高静态分析成本，不是防提取。
