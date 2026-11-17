# 白盒工程测试报告（2026-11-17）

目的：`ctest` 只证明"测试自己认为对"，不证明证据链、判定器和数字本身经得起审查。
本报告是对 `research/hsvm` 的白盒审查结果，检查项已固化为 `ctest whitebox_audit`。

## 方法与结果

| # | 检查 | 方法 | 结果 |
|---|---|---|---|
| 1 | 协议哈希可重算 | 独立实现 canonical JSON + 与 `check_protocol.py` 输出对照 | 通过（v1/v2 双哈希一致） |
| 2 | 报告绑定可解析 | 5 个 run.json：字段完整、hash 格式、commit 是 HEAD 祖先、raw_log/evidence 文件真实存在 | 通过（修复 1 处，见 D1） |
| 3 | 聚合数字可追溯到原始数据 | 60 个网格点逐字段比对 `grid.json` vs `raw/*.json` | 通过（逐位相等，无手填） |
| 4 | 判定器抗退化输入 | 构造 instructions=0、bench_plain_ns=1.0、谎报不可枚举的点喂给判定器 | 修复前**被接受**（D2），修复后拒绝 |
| 5 | 右删失口径 | 构造 censored=true 且带 recover_success_rate 的报告 | 通过（`report.py` 拒绝） |
| 6 | 测试是否有牙（变异测试） | 3 处定向变异，见下表 | 全部被抓 |
| 7 | 未定义行为 | UBSan 全量 ctest | 通过 13/13 |
| 8 | 内存安全 | ASan 全量 ctest | **不可用**（见 D5） |

## 变异测试（本轮新增 3 处）

| 变异 | 位置 | 预期 | 实际 |
|---|---|---|---|
| 删掉散布循环 | `src/model.cpp` stepWords | test_model 失败 | 13 pass / **1 fail** |
| ARX 恒等化 | `src/psi.cpp` PsiArx::applyU64 | test_psi 失败 | 18 pass / **4 fail** |
| 放宽 gate 正则 | `tools/report.py` | test_report 失败 | **FAILURES** |

三处均已还原，还原后 14/14 通过。退出码验证：失败时测试二进制返回 1，
ctest 判定 Failed（不是靠打印文字）。

## 发现的缺陷与修复

**D1 报告绑错协议版本。** `reports/G0v2/run.json` 是 v2 实验，却绑定了 v1 协议哈希，
且 gate 写成 `G1`（因为 schema 只允许 `G[0-5][AB]?`，`G0v2` 根本写不进去）。
修复：`report.py` / `schema.json` 的 gate 正则改为允许 `v2` 后缀；
`make_report.py --protocol protocol-v2.json` 重新生成，gate=`G0v2`，
params_hash=`e1f18ca5bec2db5f`（w8/c8/r̄1/table 的实际哈希）。
若无此项检查，一份 v2 结论会顶着 v1 的哈希发布。

**D2 判定器接受退化点。** `judge_g1_model.py` 用
`affine_nonaffine == instructions` 判非仿射，`instructions=0` 时**恒真**；
`step_cost_ratio` 也能被 `bench_plain_ns=1.0` 之类的手工数据压到 0。
另外"是否可枚举"直接取自 sweep 脚本写入的 `enumerable_below_48` 字段，
而该字段和测量数据出自同一个脚本——等于自己给自己发证。
修复：判定器现在要求 `instructions > 0` 且 `bench_plain_ns > 0`，
并**自行从 (psi, w) 推导**可枚举性，与网格自报值不一致即判失败。
修复后原有两份网格的结论不变（仍为 fail），说明这是加固而非改判。

**D3 证据不在版本库里。** `.gitignore` 里有 `reports/**/raw/`，
而 `raw/` 正是每个数字的原始来源；重新 clone 后审计必然失败。
修复：移除该规则（合计 240 KB），并把 `build-*/` 加入忽略。

**D4 审计脚本自身的阈值错误。** 断言"至少 5 份门禁报告"，实际 4 份。
属工具 bug，已改为 4 并保留字段级检查。

**D5 ASan 在本机不可用。** `-fsanitize=address` 构建产物连
`hsvm_params`（纯计算 CLI）都会挂死，release 同参数瞬时返回，
判断为宿主 ASan 运行时问题而非代码缺陷。**因此内存安全本轮未经验证**，
只验证了 UB（UBSan 13/13）。这是明确的未覆盖项，不当成通过。

## 工具卫生

`./build/test_model | tail -2` 会把退出码换成 `tail` 的 0。本轮所有失败判定都另取
`$?` 或走 ctest 复核，避免"管道把红灯看绿"。

## 复现

```bash
cd research/hsvm
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j10
ctest --test-dir build                 # 14/14，含 whitebox_audit
python3 scripts/whitebox_audit.py      # 单独跑审计
cmake -S . -B build-ubsan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=undefined -fno-sanitize-recover=all -O1"
cmake --build build-ubsan -j10 && ctest --test-dir build-ubsan
```
