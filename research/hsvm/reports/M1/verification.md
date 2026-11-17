# M1 验证记录（阶段 0：线性层证伪）

- 日期：2026-11-17
- 提交：`10394237732a666f0a097611b90c7e193ca1e478`
- 复现：`bash research/hsvm/scripts/run_g0.sh`

## 交付

| 任务 | 文件 |
|---|---|
| ISA 单一真源 + 镜像 | `src/llvm/include/llvm/Transforms/Obfuscation/HSVMOpcodes.def`、`research/hsvm/include/hsvm/isa.h`、`tools/sync_isa.py` |
| 指令编码/反汇编 | `include/hsvm/instr.h`、`src/instr.cpp` |
| 双模 VM（Plain/Linear） | `include/hsvm/machine.h`、`src/machine.cpp` |
| 三个测试程序 + 原生参考 | `include/hsvm/programs.h`、`src/programs.cpp` |
| A1 攻击 | `attacks/a1_trace_diff.py` |
| A2 攻击 | `attacks/a2_memread.py` |
| G0 判定与报告 | `tools/judge_g0.py`、`tools/make_report.py`、`scripts/run_g0.sh` |

## 测试

```
ctest: 13/13 passed
isa 7 · machine 11 · linear 11 · psi 15 · model 14 · gf2 116 · params 33
```

关键断言：
- `machine`：sum/crc/copy_xor 三程序各 100 组随机输入与原生参考逐位一致；
  越界/非对齐/未知操作码/超步数全部按预期失败。
- `linear`：每步 `x_after == x_before ⊕ H·v(pc)`；掩码互异；换内存输入轨迹完全不变；
  状态转储相邻差恰为槽掩码（A2 前提）。
- `isa`：16 个操作码唯一、编解码往返、反汇编格式。
- `isa_sync`：镜像头与 `.def` 真源一致（漂移即 ctest 红）。

## G0 结果（脚本生成）

| 指标 | A1 | A2 |
|---|---:|---:|
| 覆盖 | 16/16 | 16/16 |
| mismatch | 0 | 0 |
| 查询 | 32（两次运行） | 16 |
| 墙钟 | 0.0001 s | 0.0001 s |
| 跨运行一致性 | 0 处不一致 | — |

`verdict.json`：`{"gate":"G0","pass":true,"slots":16}`

## 过程中发现并修复的真实缺陷

1. **sum 程序 n=0 下溢死循环**：循环体先加后减，n=0 时 0−1 回绕。修复为入口先判零。
2. **crc/copy 循环把 `MOV r2, r0` 放在循环体内**：每次回跳重置长度 → 死循环。已将该指令移出循环。
3. **A1 只拟合单条轨迹的风险**：增加第二次运行（不同初始状态）做跨运行对照，
   `cross_run_mismatch` 必须为 0，`judge_g0` 强制检查。

第 1、2 项是测试（100 组随机输入 + 原生差分）抓出来的；第 3 项是评审攻击脚本时补的。
三处都记录在此，避免把"实现 bug"与"测试 bug"混为一谈。

## 边界

- Linear 模式**不能执行算术**：转移只做 `s ⊕ v(i)`。这是零保护的直接体现，
  不是实现缺陷；真实执行只在 Plain 模式存在。
- A2 的"内存直读"用进程内状态转储代替调试器读内存，等价于 A2 的读写权限，
  但没有覆盖"外部 attach"路径；该差异在报告中显式记录。
