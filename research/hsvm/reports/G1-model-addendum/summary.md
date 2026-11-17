# G1-模型层补充实验（ADR-006 方案 B：ARX ψ）

- 生成：`python3 scripts/run_g1_addendum.py --out reports/G1-model-addendum`
- 判定：`python3 tools/judge_g1_model.py --grid reports/G1-model-addendum/grid.json --out reports/G1-model-addendum/verdict.json`
- 性质：**补充实验，不属于 `protocol.json` 登记的 48 点网格**；登记网格的结论仍是失败（`reports/G1-model/`）

## 结果

| 点 | Γ p5 | 非仿射 | 单步代价 | ratio |
|---|---:|---:|---:|---:|
| w32_c8_r2_arx_4 | 0.994 | 16/16 | 44.2 ns | 10.51 |
| **w48_c8_r2_arx_4** | 0.993 | 16/16 | 48.6 ns | **10.85** |
| w64_c8_r2_arx_4 | 0.992 | 16/16 | 53.4 ns | 12.85 |
| w48_c16_r2_arx_4 | 1.000 | 16/16 | 73.1 ns | 15.97 |
| w64_c16_r2_arx_8 | 1.000 | 16/16 | 83.7 ns | 18.76 |

基线 `bench_plain_ns` 全程 4.2–4.4 ns/指令。

`verdict.json`：`{"pass":false,"best_ratio":10.51,"reason":"no point satisfies step_cost_ratio <= 3; no point satisfies coverage, non-affine, performance and non-enumerability together"}`

## 与 SPN 对比

| 参数 | SPN | ARX | 改善 |
|---|---:|---:|---:|
| w=48, c=8, r̄=2, 4 轮 | 22.11 | 10.85 | 2.0× |
| w=64, c=8, r̄=2, 4 轮 | 27.78 | 12.85 | 2.2× |

ARX 把 ψ 的成本砍掉一半左右——符合预期，但仍离 3× 有 3.6 倍。

## 关键发现：瓶颈已经转移到窗口读取

w=48 的 ARX 点约 48.6 ns，按构成估算：
- 窗口读取 48 位：~48 次位提取 —— **现在的主项**
- ψ（4 轮 ARX，≈12 次算术/旋转）：~4–6 ns
- 散布 c·r̄ = 16 次位翻转：~4 ns
- v 全状态异或 8 字：~2 ns
- 调用/调度：~3 ns

也就是说：**即便把 ψ 做到零成本，w=48 也仍需 ~40 ns（≈9×）**，因为文档 §5.3 的成本模型里窗口读取是 O(w)，
而 w≥48 是为了让 2^w 查询不可行所必需的。两个要求在同一基线下互相矛盾。

这不是"实现还不够快"能解决的问题：把窗口读取优化到接近 1 次 pext 级别的硬件指令，
也只能省掉一半左右，仍在 4–5×。

## 结论与建议

- 方案 B 已执行：ARX 变体在同网格条件下把最好的"不可枚举"点从 22.1× 降到 10.9×，**仍不满足 ≤3×**。
- 主因从 ψ 转移到 O(w) 的窗口读取，属构造性成本，不是实现瑕疵。
- 建议：**执行方案 A（按 §10.1.1 终止 C1/C2 路线并归档）**；
  若仍要继续，只剩方案 C（C2 先行、重定义工作点），那需要新协议版本，不能沿用当前预注册。

## 产物

```
reports/G1-model-addendum/
  grid.json      # 12 个 ARX 点
  verdict.json   # 判定（失败）
  run.json       # 绑定 commit/协议哈希/参数哈希的报告
  raw/*.json     # 每点完整输出
```
