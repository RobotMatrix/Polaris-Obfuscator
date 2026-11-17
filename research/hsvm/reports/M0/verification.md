# M0 验证记录（M0-1 … M0-5）

- 日期：2026-11-17
- 仓库提交：`10394237732a666f0a097611b90c7e193ca1e478`
- 计划：`.hermes/plans/2026-11-17_1508-hsvm-polaris-implementation.md`
- 构建：`cmake -S research/hsvm -B research/hsvm/build -DCMAKE_BUILD_TYPE=Release`

## 交付内容

| 任务 | 文件 | 状态 |
|---|---|---|
| M0-1 骨架 | `CMakeLists.txt`、`README.md`、`.gitignore`、`include/src/tests/tools/attacks/reports` | 完成 |
| M0-2 GF(2) 库 | `include/hsvm/gf2.h`、`src/gf2.cpp`、`tests/test_gf2.cpp` | 完成 |
| M0-3 参数与溯源 | `include/hsvm/params.h`、`src/params.cpp`、`tools/hsvm_params.cpp`、`tests/test_params.cpp`、`tests/test_params_json.py` | 完成 |
| M0-4 协议预注册 | `PROTOCOL.md`、`protocol.json`、`tools/check_protocol.py`、`tests/test_protocol.py` | 完成 |
| M0-5 报告 schema | `reports/schema.json`、`tools/report.py`、`tests/test_report.py` | 完成 |
| 决策记录 | `DECISIONS.md`（ADR-001…005 + D-01…D-11 状态） | 完成 |

## 验证结果（本次真实输出）

```
$ ctest --test-dir research/hsvm/build --output-on-failure
    Start 1: smoke ............... Passed
    Start 2: gf2 ................. Passed
    Start 3: params .............. Passed
    Start 4: params_json ......... Passed
    Start 5: protocol ............ Passed
    Start 6: protocol_mutations .. Passed
    Start 7: report .............. Passed
100% tests passed, 0 tests failed out of 7
Total Test time (real) = 1.03 sec
```

断言数量（各套件末尾汇总行）：

| 套件 | 断言 | 覆盖 |
|---|---:|---|
| gf2 | 116 | rank / 核基 / 解 / 乘积 / 512 位目标尺寸 / 尾字 |
| params | 33 | 合法点、13 类非法点、派生量、哈希与 JSON |
| params_json | 16 | JSON 可解析、同点字节一致、退出码 2/3、provenance |
| protocol_mutations | 32 | 12 类协议破坏 + 哈希稳定性/格式化无关性 |
| report | 28 | 8 类报告拒收 + 统计/置信区间 |

## 协议冻结

```
$ python3 research/hsvm/tools/check_protocol.py research/hsvm/protocol.json
protocol: ok (v1.0, chosen_point=unset)
  grid: 360 points, 153 legal (18 table, 135 spn)
  seeds: 16 | workload entries: 5 | instances: 16
protocol_sha256=f964755dcd2587ee0772d210fd1597024f40bbba20c7c194c02c991983515c1f
```

参数点示例（`hsvm_params`，同一输出同时带哈希与溯源）：

```
$ ./research/hsvm/build/hsvm_params --n 512 --m 256 --w 8 --c 8 --rbar 2 \
    --rounds 0 --psi table --workload crc32 --seed 12345
{"params":{"c":8,"m":256,"n":512,"psi":"table","r_bar":2,"rounds":0,
 "seed":12345,"w":8,"workload":"crc32"},
 "params_hash":"c5724bc3cf403a42",
 "provenance":{"build_time":"2026-11-17T07:16:01Z",
 "git_commit":"10394237732a666f0a097611b90c7e193ca1e478",
 "kernel_version":"hsvm-core-0.2"}}
```

## 变异测试（"测试不是空转"）

| 变异 | 改动 | 结果 |
|---|---|---|
| GF(2)-1 | `kernelBasis` 主元分量恒置 0 | 退出码 1，74 条 `[FAIL]` |
| GF(2)-2 | `solve` 行交换不再同步翻转 rhs | 退出码 1，3 条 `[FAIL]` |
| 协议检查器（开发期） | 首版把 `rounds=0` 判为非法 | `protocol` 测试立刻失败；修正检查器（rounds 允许 0），协议本身未改 |

前两项是**故意**注入的库变异，跑完即还原；第三项是检查器自身的 bug 被测试抓住，
记录在此以区分"实现 bug"与"测试 bug"。最终 `gf2 116/0`、`params 33/0`、7/7 ctest。

## 已知限制（必须写进后续报告）

1. Release 下 `assert` 被 `NDEBUG` 关闭，`BitMatrix::get/set` 的越界检查只在 Debug 生效。
   对外 CLI 入口（M1 起）需显式校验维度。
2. `randomFullRowRank`/`randomInvertible` 是"重试直到满秩"，最坏情况无上界证明；
   目标尺寸（m=256, N=512）实测无重试压力。
3. `rref` 是 O(rows²·words) 的 Gauss-Jordan；Γ 百万级采样前需评估增量消元。
4. `report.py` 的指标只接受标量；逐实例数组放 `raw_log`/附件，聚合由脚本计算。
5. `params_hash` 是 FNV-1a 身份标签（ADR-003），不是密码学哈希。
6. 协议里的 `commercial_baseline` 仍是 `"undecided"`，M5-6 只能出 `R_plain` 列。

## 下一步

M1-1…M1-7（ISA v0、键控 v(i)、线性 VM、trace、A1/A2 攻击、G0 报告）。
前置条件已满足：GF(2) 库、参数校验、协议哈希、报告 schema 全部可用。
