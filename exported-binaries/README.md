# Polaris 混淆产物导出（最终版，供 IDA 验证）

三个平台的产物全部用**最终版 Polaris clang**（arm64 含 ARMRubbishCode MIR 混淆）编译，运行语义已逐个验证。

## 目录结构

```
exported-binaries/
├── x86_64-linux/          Linux x86_64 ELF（OrbStack VM 内编译）
│   ├── example1/          X1_plain, X1_subbcffla+MIR
│   ├── example2/          X2_plain, X2_8p+MIR
│   └── example3/          X3_subbcf_nobk, X3_bkonly+MIR
├── mac-native/            macOS arm64 Mach-O + iOS
│   ├── example1/          M1_plain / M1_8p+MIR（全8pass+MIR）等
│   ├── example2/          M2_plain / M2_8p+MIR 等
│   ├── example3/          M3_plain / M3_8p_nobk（无 EH 冲突组合）
│   ├── ios-sim/           D1_obf / D5_mir+MIR（iOS 模拟器, platform 7）
│   └── ios-device/        D1_obf / D5_mir+MIR（iOS 真机, platform 2, minOS 13）
├── README-v1-x86.md       早期 x86 产物说明（存档）
└── ios demo 源码在 demos/ios/
```

## IDA 验证要点

| 目标 | 预期表现 |
|---|---|
| **x86_64 `*+MIR`** | F5 出 JAMPOUT，伪代码难读——call/ret 返回地址运行时改写，设计特性 |
| **arm64 `*+MIR`（M1/M2/M3_8p, D5）** | F5 可出伪代码，但函数体内大量无来源寄存器垃圾操作（asr/udiv/sdiv 等），函数开头即垃圾指令流；脏字节在不可达块（`.byte` 区段） |

### 关于"函数切割"（Function Splitting）

Mach-O 的函数边界由符号表决定，块乱序/拆分全部发生在符号区间内部，因此 **IDA 函数数量与混淆前一致**——这是 Mach-O 符号机制的必然，任何 MIR 方案（含 x86）都相同。切割的实际效果是：

- 函数逻辑被物理打散到符号区间内多个不连续位置（otool 可见大量 `b 0x...` 跨区跳转，单函数可达 800+ 条分支）
- 块之间夹杂脏字节块与垃圾指令流，线性反汇编被打断
- x86 版额外用 call/ret 让反编译器无法建模返回路径（JAMPOUT）

若需要 IDA 函数数量虚增，需要在 ASM 层为拆出块伪造函数符号——独立工作量，当前版本未实现。

### M3 系列的正确打开方式

`M3_8p_nobk`（example3 原 STL 版）只有 IR 混淆——它的函数带 EH（STL 容器 invoke），而 **MIR 由 `asm("backend-obfu")` 触发**，该版本刻意去掉了 asm 标记（EH+MIR 编译死循环限制），所以 M3_plain 与 M3_8p_nobk 在 IDA 里差异确实小（IR 混淆仅 .text +22%）。

**要看 arm64 MIR 的函数切割效果，用 `M3_mir_noeh`**（同 Dijkstra 算法，手写数组去 STL/EH，带 asm 标记）：

- 函数开头即垃圾指令流（`ands/adds/asr/ubfiz` 无来源寄存器操作）
- `.text` 7KB，函数内 686 处脏字节/除法垃圾
- IDA F5 后伪代码可读性显著劣化

iOS 对应产物：`ios-sim/D3_mir_noeh`、`ios-device/D3_mir_noeh`。
| `*_plain` | 无混淆对照——F5 干净 |

## 运行验证基线（混淆前后输出必须一致）

| Demo | 输入 | 期望输出 |
|---|---|---|
| example1 | `abcdef`（stdin） | `loruxa` |
| example2 | 无 | Original 12345678 / Encrypted 6a8e48cf / Decrypted 还原 |
| example3 | 无 | Dijkstra 距离表 0/4/12/19... |
| ios demo1 | 无 | hash(...)=5d237353 restore_ok=yes |
| ios demo5 | 无 | crc=6b35869a stable=yes |

iOS 模拟器二进制运行方式：
```bash
UDID=$(xcrun simctl list devices available | grep -m1 "iPhone" | grep -oE "[0-9A-F-]{36}")
xcrun simctl boot $UDID
xcrun simctl spawn $UDID mac-native/ios-sim/D5_mir+MIR
```

## 编译命令（复现用）

```bash
CL=src/build/bin/clang++
# macOS arm64 + MIR
$CL example2.cpp -mllvm -passes=gvenc,indcall,indbr,alias,mba,sub,bcf,fla -o out
# iOS 真机 + MIR
$CL -arch arm64 -target arm64-apple-ios13.0.0 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    demo5_mir.cpp -mllvm -passes=sub,bcf,fla -o out
```

## 已知限制

- **EH（invoke）函数 + `asm("backend-obfu")` + MIR（arm64）**：编译期死循环——example3 带 asm 标记版即此场景，已用无 asm 的 M3_8p_nobk 代替
- fla + 多 pass + EH + asm 在 darwin arm64 codegen -O1+ 有上游 LLVM16 bug
- x86 MIR 的 JAMPOUT 依赖 call/ret 技巧，是设计行为（曾试过结构化改造，会引入运行时崩溃，已回退）
