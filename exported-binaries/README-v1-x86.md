# Polaris x86_64 混淆产物导出

来源：OrbStack x86_64 Ubuntu 22.04 VM `polaris-x86`（Rosetta 加速）
编译器：Polaris (LLVM 16.0.6)，Target: `x86_64-unknown-linux-gnu`
构建配置：`-O0`（除注明外）、Release LLVM、`-DLLVM_ENABLE_ASSERTIONS=Off`

`mac-native/` 子目录：本机 M4 原生构建产物（arm64 Mach-O + x86_64 Mach-O），编译器
`src/build/bin/clang`（已配 AArch64+X86 双后端、macOS triple、默认 sysroot）。

命名规则：`e{example}-{optlevel}-{passes}`

## example1/（凯撒变体加密，`asm("backend-obfu")` 标记）

| 文件 | 编译命令 |
|---|---|
| `e1a-O0-all+backend` | `-O0 -mllvm -passes=gvenc,indcall,indbr,alias,mba,sub,bcf,fla` + backend |
| `e1b-O2-all+backend` | 同上，`-O2` |

## example2/（TEA 加解密）

| 文件 | 编译命令 |
|---|---|
| `e2a-O0-orig` | `-O0`，无混淆 |
| `e2b-O0-sub,bcf,fla` | `-O0`，IR 混淆 + backend |
| `e2c-O2-sub,bcf,fla` | `-O2`，IR 混淆 + backend |
| `e2d-O0-all+backend` | `-O0`，全 pass + backend |
| `e2e-O2-all+backend` | `-O2`，全 pass + backend |
| `e2f-O2-fla-only` | `-O2`，仅 fla |

## example3/（Dijkstra 最短路，含 priority_queue/异常）

| 文件 | 编译命令 |
|---|---|
| `e3a-O0-sub,bcf,fla+backend` | `-O0`，IR 混淆 + backend |
| `e3b-O2-sub,bcf,fla+backend` | `-O2`，IR 混淆 + backend |
| `e3c-O0-all+backend` | `-O0`，全 pass + backend |
| `e3d-O2-all+backend` | `-O2`，全 pass + backend |
| `e3e-O0-fla-only` | `-O0`，仅 fla |
| `e3f-O1-all+backend` | `-O1`，全 pass + backend |
| `ex3_plain_O2` | `-O2` 无混淆（对照） |

注：`sub,bcf,fla+backend` 等表示源码带 `#define BACKEND_OBFU`（backend 混淆启用）；
`gvenc,indcall,indbr,alias,mba,sub,bcf,fla` 为全部 8 种 pass 组合。

## 运行验证结论（VM 内已验证）

- example2 全部变体输出一致：`Original: 12345678 9abcdef0 / Encrypted: 6a8e48cf f90f785f / Decrypted: 12345678 9abcdef0`
- example1（输入 `abcdef`）全部输出 `loruxa`
- example3 全部变体与原版 Dijkstra 距离表逐字节一致

## 观察要点（用 IDA/Ghidra 打开对比）

- `*all+backend` 变体：MIR 级混淆生效——函数边界破碎、脏字节插入、垃圾指令流
- 对照：`ex3_plain_O2` 0 处 `(bad)` 反汇编错误，`e3d` 517 处
- `.text` 膨胀：example3 无混淆 8KB vs 全混淆 113KB（13.8x）

## mac-native/（本机 M4 原生）

| 文件 | 说明 |
|---|---|
| `example1/e1a-arm64-O0-all` | arm64 Mach-O，全 IR pass |
| `example1/e1b-arm64-O2-all` | 同上 -O2 |
| `example1/e1x-x86_64-O2-all+backend` | x86_64 Mach-O（Rosetta 运行），全 pass + MIR 混淆 |
| `example2/e2-O0-orig-arm64` | 无混淆对照 |
| `example2/e2-O0-sub,bcf,fla-arm64` 等 | arm64 各混淆组合 |
| `example2/e2-x86_64-all+backend` | x86_64 + MIR 混淆 |
| `example3/e3-*` | 同上模式 |

**架构限制**：MIR（backend）混淆只实现了 X86 后端（`X86RubbishCode.cpp`）。
arm64 目标可用全部 IR 级 pass；需要 MIR 混淆时用 `-arch x86_64`。
注意 example1 原版有 `enc[len]='\0'` 缺失 + `scanf("%s", &data)` 两处源码 bug，
已在本仓库修复（`examples/1/example1.cpp`），导出的 example1 产物均基于修复版。
