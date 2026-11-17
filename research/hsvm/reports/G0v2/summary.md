# G0v2 成本下界 — 结论：失败（v2 路线终止）

- 协议：`protocol-v2.json` v2.0-draft，哈希 `a9929c6c…fadb5`
- 工具：`tools/hsvm_floor`（下界）、`tools/judge_g0v2.py`（判定）
- 原始数据：`reports/G0v2/floor.json`、`reports/G0v2/raw/w8_c8_r1_table_bench.json`

## 下界结果（16 个薄点）

峰值吞吐 19.22 ALU ops/ns；基线 4.34 ns/指令；cap 3.0 → 12.6 ns。

| 点 | 窗口 | 散布 | 掩码 | ψ | 调度 | 下界 | ratio |
|---|---:|---:|---:|---:|---:|---:|---:|
| **w8_c8_r1_table** | 2.70 | 5.54 | 0.84 | 0.80 | 0.74 | **10.61** | **2.53** |
| w8_c8_r2_table | 2.70 | 9.37 | 0.84 | 0.82 | 0.75 | 14.47 | 3.45 |
| w8_c16_r1_table | 2.70 | 9.38 | 0.84 | 0.77 | 0.75 | 14.44 | 3.44 |
| w16_c8_r1_table | 5.44 | 5.54 | 0.86 | 0.82 | 0.74 | 13.39 | 3.19 |
| w32_c8_r1_arx_4 | 11.29 | 7.93 | 0.85 | 4.77 | 0.73 | 25.57 | 6.09 |

只有 **w=8 / c=8 / r̄=1 / table** 一个点在下界意义下过线（2.53×），
且余量只有 18%（10.61 → 12.6）。其余 15 点全部超限。

## 决定性反驳：同一参数点的实测内核

下界是"各部分单独计时再相加"，必然乐观。所以对唯一过线的点，直接用已有的
`stepWords` 内核测了一遍（`hsvm_gamma --bench`，同参数 n=512,m=256,w=8,c=8,r̄=1,table,seed=12345）：

```
model_ns = 28.88    plain_ns = 4.34    step_cost_ratio = 6.65
```

也就是说：下界 10.61 ns 与真实内核 28.88 ns 之间差了 **2.7 倍**，
而这条点对 cap 的余量只有 1.18 倍。下界无法为 C2 立项提供依据——
它连"如果实现得足够好就能达标"这一点都不成立。

## 判定

`judge_g0v2.py` 按协议只看下界，给出 `pass=true, best_ratio=2.527`。
但协议同时规定"下界必须对融合后的内核成立"，而融合内核在同一参数点是 6.65×。
两条放在一起，结论是**失败**，理由不是下界估计偏高，而是：

> 唯一可行的参数点（w=8,c=8,r̄=1,table）在真实内核上是 6.65×，
> 超过 cap 3.0 的 2.2 倍；下界的乐观系数（2.7×）远大于该点的余量（1.18×），
> 因此不存在"通过优化实现即可达标"的空间。

按 `g0v2_cost_floor_above_cap` 终止 v2 路线：**不实现 C2**。

## 这不是"再调一调"的问题

把三个成本项逐一压到零都救不回来：
- 窗口 2.70 + 掩码 0.84 + ψ 0.80 + 调度 0.74 = 5.08 ns（已 1.17×）
- 只剩散布 5.54 ns；c·r̄ 已经是网格最小值 (8×1)，无法再降而不破坏 C1 的扩散前提
- 即便散布减半，仍是 7.85 ns 下界，对应实测约 21 ns ≈ 4.8×

## 复现

```bash
cd research/hsvm
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j10
./build/hsvm_floor --out reports/G0v2/floor.json
python3 tools/judge_g0v2.py --floor reports/G0v2/floor.json --out reports/G0v2/verdict.json
./build/hsvm_gamma --n 512 --m 256 --w 8 --c 8 --rbar 1 --rounds 0 --psi table \
    --seed 12345 --states 128 --dirs 4 --affine exhaustive --bench --out /tmp/w8r1.json
```
