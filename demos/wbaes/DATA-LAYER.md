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
