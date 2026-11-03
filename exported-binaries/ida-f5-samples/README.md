# IDA 9.3 F5 对比样本 (ex3_noeh.cpp shortestPath 函数)

| 文件 | 编译 | F5 结果 |
|---|---|---|
| M3_noasm_plain_shortestPath.c | polaris clang, 无 asm 标记无 -mllvm | 45 行，逻辑完整可读 |
| M3_mir_noeh_shortestPath.c   | polaris clang, asm 标记 + sub,bcf,fla + MIR | **347 行，75 个未定义寄存器变量，开头即 20+ 行无意义算术链** |

## 关键发现（修正之前结论）

1. **polaris clang 只要源码含 `asm("backend-obfu")`，无论加不加 `-mllvm` 都会跑 MIR 混淆**
   （AArch64TargetMachine 无条件挂 ARMRubbishCodePass，checkShouldProcess 扫描到标记即触发）
2. 之前 M3_plain 与 M3_8p_nobk "无区别"是因为：两者源码都无 asm 标记 → MIR 都没跑，只有 IR 混淆差异
3. F5 对比数据（shortestPath）：
   - 无混淆：45 行，0 weird ops
   - MIR 混淆：347 行（7.7x），垃圾算术链 `v25 = (v13+1056) & ~v18` 等，真实逻辑（while 循环/距离更新）被埋在垃圾中

## 复测命令

```bash
"/Applications/IDA Professional 9.3.app/Contents/MacOS/idat" -A \
  -S/tmp/ida_analyze.py -o/tmp/x.i64 <binary>
```
