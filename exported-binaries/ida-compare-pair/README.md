# IDA 对照包——shortestPath (ex3_noeh.cpp, Dijkstra)

同一源码、同一函数、三种编译，运行输出完全一致。用 IDA 9.3 逐个 F5 对比。

## 文件

| 文件 | 编译方式 | F5 预期 |
|---|---|---|
| `M3_shortestPath_PLAIN`  | polaris clang，源码无 asm 标记，无 -mllvm | **45 行**干净伪代码，Dijkstra 三段循环直接可读 |
| `M3_shortestPath_IRONLY` | 源码无 asm 标记 + `-mllvm -passes=sub,bcf,fla` | IR 混淆：平坦化 switch + bcf 垃圾块，结构变复杂但数据流仍可追踪 |
| `M3_shortestPath_MIR`    | 源码含 `asm("backend-obfu")` + `-mllvm -passes=sub,bcf,fla` | **347 行**（7.7x），75 个寄存器变量，开头 20+ 行无意义算术链，真实逻辑被埋 |
| `M3_shortestPath_ALLPASS` | asm 标记 + **全部 8 pass** `gvenc,indcall,indbr,alias,mba,sub,bcf,fla` + MIR | **352 行**，在 MIR 基础上叠加：字符串加密、间接调用/跳转、MBA 位运算替换、寄存器双视图混用——字符串/调用点也全部变形 |
| `WBAES_PLAIN` | 白盒 AES-128（T-table 320KB）无混淆 | encrypt 282 行 |
| `WBAES_MIR`   | 白盒 AES + `sub,bcf,fla` + MIR | encrypt **439 行**（1.6x），134 个寄存器变量，查表逻辑被垃圾打散 |

### 白盒 AES demo（`demos/wbaes/`）

Chow-style T-table 白盒 AES-128：加密 160KB + 解密 176KB 共 **336KB** 查找表，
单随机密钥（`3ae9dfcb...`，见 `demos/wbaes/README.md` §0）全部烘焙进表内——
ARK(0) 烘进首轮表 SBox 输入侧，ARK(1..10) 烘在 MC/InvMC 输出侧，
运行时无任何轮密钥变量，表内完整 16B 密钥序列出现 0 次（已验证）。
通过预计算向量比对 + 加解密回环 + 32 组随机明文 vs tiny-AES ECB 交叉验证。
IDA F5 对比 `f5_wbaes_plain_encrypt.c` vs `f5_wbaes_mir_encrypt.c`。

**可选工具**：`demos/wbaes/fake_symbols.py` 可对 MIR 产物注入伪函数符号
（IDA 实测函数 13 → 387），当前产物**未应用**，保持编译器原始输出。
需要时：`python3 demos/wbaes/fake_symbols.py <mir_binary> && codesign -f -s - <mir_binary>`

注意：旧版产物含 NIST 测试密钥 `2b7e1516...` 与全局 `g_wb_ark0/g_wb_ark10` 常量，
2026-10-29 起已废弃，改为单密钥全烘焙版。

## F5 实测数据（IDA 9.3 Hex-Rays）

```
PLAIN:   45 行伪代码, weird_ops=0
MIR:    347 行伪代码, 函数签名被撑成 8 参数, 变量 v8~v83 全部来自垃圾指令
```

样本伪代码见同目录 `f5_plain.c` / `f5_allpass.c` / `f5_mir.c`。

## 注意

- 源码含 `asm("backend-obfu")` 时 polaris clang **无论加不加 `-mllvm` 都会跑 MIR**（后端扫描标记触发），所以做 plain 对照必须删掉 asm 语句
- MIR 垃圾指令写的是死寄存器，F5 后呈无意义算术链但不影响真实数据流
