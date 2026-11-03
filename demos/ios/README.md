# Polaris iOS 目标测试集 (demos/ios)

编译器：Polaris clang 16.0.6（`src/build/bin/clang`），AArch64 后端含 ARMRubbishCode MIR 混淆。

## Demo 一览

| 文件 | 特征 | 混淆 pass |
|---|---|---|
| `demo1_strings.cpp` | 全局字符串、多函数、位运算 | `gvenc,aliasaccess,substitution,boguscfg` |
| `demo2_eh.cpp` | 异常处理、vector/STL（invoke/EH） | `flatten,boguscfg`（勿加 MIR） |
| `demo3_templates.cpp` | 模板、间接调用/跳转 | `linearmba,indcall,indbr` |
| `demo4_recursive.cpp` | 递归、多函数合并 | `mergefunction,flatten,substitution` |
| `demo5_mir.cpp` | **MIR backend 混淆主测**（asm 标记，非 EH 函数） | `sub,bcf,fla` + backend |

## 产物

```
out/sim/     arm64 iOS 模拟器（platform 7）—— 本机 mac 直接跑需 simctl
out/device/  arm64 iOS 真机（platform 2, minOS 13.0, ad-hoc 签名）
```

## 编译命令

```bash
CL=src/build/bin/clang++
# 模拟器
$CL -arch arm64 -target arm64-apple-ios13.0.0-simulator \
    -isysroot $(xcrun --sdk iphonesimulator --show-sdk-path) \
    demo5_mir.cpp -mllvm -passes=sub,bcf,fla -o out/sim/demo5_mir
# 真机
$CL -arch arm64 -target arm64-apple-ios13.0.0 \
    -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
    demo5_mir.cpp -mllvm -passes=sub,bcf,fla -o out/device/demo5_mir
```

## 运行（模拟器）

模拟器二进制不能在 macOS shell 直接跑（`DYLD_ROOT_PATH` 检查），用 simctl：

```bash
UDID=$(xcrun simctl list devices available | grep -m1 "iPhone" | grep -oE "[0-9A-F-]{36}")
xcrun simctl boot $UDID
xcrun simctl spawn $UDID out/sim/demo5_mir
```

## 验证结论（2026-10-29）

- 10/10 编译（sim + device 各 10 个）
- 5 组 plain vs obf 运行输出**逐字节一致**
- MIR 效果：demo5 checksum 函数开头即垃圾指令流 + 块拆分（otool 可见 udiv/sdiv/asr 等无来源寄存器操作）
- 真机产物 platform=2/minOS13 已生成，设备端需开发者证书重签（ad-hoc 已打）

## 已知限制（继承自 ARMRubbishCode 调试记录）

- **EH（invoke）函数 + `asm("backend-obfu")` + MIR**：编译期死循环——EH 函数不要加 MIR 标记（demo2 即此设计）
- fla + 多 pass 组合 + EH + asm 在 darwin arm64 codegen 有上游 LLVM16 bug（InlineSpiller 域），与 x86 VM 侧同类

## IDA 反编译表现差异（x86 vs arm64）

| 架构 | IDA 表现 | 原因 |
|---|---|---|
| x86_64 MIR | F5 出现多处 **JAMPOUT**，伪代码难读 | 控制流用 `CALL Body / ADD [rsp],skew / RET`——返回地址运行时改写，反编译器无法建模 RET 目标 |
| arm64 MIR | F5 正常出伪代码 | 结构化 `B Body / B End` 块边界 + 独立脏字节块，CFG 完整静态可析 |

这是**设计差异而非缺陷**：两版都保留了垃圾指令、脏字节、块乱序三类对抗。x86 版牺牲伪代码可读性换取更强的控制流伪装；arm64 版 F5 出的伪代码里仍充满无来源寄存器操作（垃圾指令副作用），可读性同样大幅劣化。若需要 arm64 也输出 JAMPOUT 风格，需引入运行时改写跳转目标的等价机制（如 X30 寄存器间接跳转），代价是引入与 FrameDestroy 的 LR 冲突问题。
