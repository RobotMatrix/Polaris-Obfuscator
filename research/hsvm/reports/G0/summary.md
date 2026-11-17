# G0 判定：线性层证伪（阶段 0）

- 生成：`bash research/hsvm/scripts/run_g0.sh`（可复现，SEED 可覆写）
- 参数点：n=512, m=256, w=8, c=8, r_bar=2, table, seed=12345
- `params_hash`：`c5724bc3cf403a42`
- 协议哈希：`f964755dcd2587ee0772d210fd1597024f40bbba20c7c194c02c991983515c1f`
- 攻击者等级：A2

## 结果（来自 a1.json / a2.json，非手填）

| 指标 | A1（trace 差分） | A2（状态直读） |
|---|---:|---:|
| 指令槽 | 16 | 16 |
| 恢复覆盖 | 16/16 | 16/16 |
| mismatch | 0 | 0 |
| 查询数 | 32（两次运行各 16 步） | 16 |
| 墙钟 | 0.0001 s | 0.0001 s |
| 跨运行一致性 | 0 处不一致 | — |

`verdict.json`：`{"gate":"G0","pass":true,"reason":"ok","slots":16}`

## 这意味着什么

V0.1 的转移 `F(s,i) = s ⊕ v(i)` 让外部投影满足
`x_{t+1} = x_t ⊕ H·v(i_t)`，与隐藏状态无关。因此：

1. **A1**：两次不同初始状态的运行给出**完全相同**的 H·v 表（`cross_run_mismatch=0`），
   说明攻击恢复的是机器本身，而不是某条轨迹的拟合。
2. **A2**：相邻两步状态异或一次即得 `v(i)`，全表 16 个槽位零成本恢复。
3. **输入无关性**（`test_linear`）：同一初始寄存器、不同内存内容的两条轨迹逐位相同 —
   线性消融下"输入"根本不进入状态。

## 必须写明的边界

- 这个消融**不能执行算术**：若转移只做 `s ⊕ v(i)`，指令就没有数据相关效果；
  要"计算"只能把每个输入的行为预先烘进常量。这正是零保护的另一种表述，不是实现缺陷。
  真实的字节码执行只在 Plain 模式（`VmMode::Plain`）存在，它是后续 R_plain 的基线。
- 本门禁证明的是"C1 是必要条件"，不证明任何 C1 构造的安全性；后者是 M2/M3 的工作。

## 判定

G0 通过 ⇒ 按文档 §10 阶段 0 的约定，确认 C1 是必需条件而非可选加固，
进入阶段 1（模型层 C1 构造与 Γ 测量）。

## 产物

```
reports/G0/
  run_summary.json  run_summary2.json   # hsvm_run 两行摘要
  trace.jsonl  trace2.jsonl             # 每步 t/pc/op/x_before/x_after
  truth.json                            # v[] 与 hv[] 真值
  states.bin                            # 每步边界的 512 位状态
  a1.json  a1_recovered.json            # A1 指标与恢复表
  a2.json                               # A2 指标
  run.json                              # 门禁报告（report.py 校验通过）
  verdict.json                          # judge_g0 判定
```
