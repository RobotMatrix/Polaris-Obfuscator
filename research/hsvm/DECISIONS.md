# 决策记录（DECISIONS）

规则：任何影响协议、参数合法性、报告判定或门禁结果的变更都追加到这里，写清日期、
旧值、新值、理由、受影响的门禁。协议变更后必须重算 `protocol_sha256`；已发布的
报告保留旧哈希，不追溯改写。

## ADR-001 实验协议 v1.0 冻结（2026-11-17）

- 协议哈希：`f964755dcd2587ee0772d210fd1597024f40bbba20c7c194c02c991983515c1f`
- 冻结内容：主假设 A2 / 2^40 查询 / 成功率 < 10%；阶段 1 预算 2^32、插值 < 1%、
  Γ p5 ≥ 0.5；参数网格 360 点（153 合法：18 table + 135 spn）；16 个种子；
  5 项工作负载权重；§10.1 三条停止规则。
- `chosen_point` 暂为 `null`，由 M2-10 选定后写入并重算哈希。
- 变更方式：新增 ADR → 修改 `protocol.json` → 重跑 `check_protocol.py` → 记录新哈希。

## ADR-002 参数合法性的单一真源（2026-11-17）

C++ `validate()`（`include/hsvm/params.h`）是权威定义；`check_protocol.py` 中的
`point_legal()` 是镜像实现；`chosen_point` 非空时通过子进程调用 `hsvm_params`
交叉验证。改规则必须同时改两侧，`test_params`（C++）与 `protocol_mutations`
（Python）各自覆盖，任一漂移都会被测试抓住。

## ADR-003 `params_hash` 使用 FNV-1a 64（2026-11-17）

16 位十六进制，只作为参数身份标签，**不是**密码学哈希。报告的可信绑定由
`protocol_sha256`（SHA-256）与 `git_commit` 承担。理由：零依赖、便于人工比对；
参数漂移检测不需要抗碰撞性。

## ADR-004 右删失（right-censoring）的强制口径（2026-11-17）

- `queries_used < budget` ⇒ `censored` 必须为 `true`（`report.py` 强制，非建议）。
- `censored=true` 时，名称匹配 success/recover/extract/break 的指标不得 > 0。
- 允许的措辞只有"在已用预算内未成功"；禁止写成"成功率低于阈值"。
- 依据：V1.3 §1.3、§10 阶段 1/2 的右删失条款。

## ADR-005 溯源在 configure 时捕获（2026-11-17）

`git_commit` 与 `build_time` 由 CMake 在 configure 阶段注入（`HSV_GIT_COMMIT` /
`HSV_BUILD_TIME`）。构建目录报告的是"配置时的提交"，改源码后必须重跑
`cmake -S research/hsvm -B research/hsvm/build` 才能刷新；只做增量编译不会更新。
可验证：`hsvm_params --help` 之外，任何一次输出里的 `provenance.git_commit` 必须等于
当前 `git rev-parse HEAD`（M3-1 起纳入 CI 检查）。

## 待 ratification 的架构决策（来自实施计划 §4）

| ID | 决策 | 状态 |
|---|---|---|
| D-01 | MVP 用静态运行时库 `libhsvmrt.a`，pass 只发 bytecode/表/调用 | proposed |
| D-02 | 单一内核：研究层与产物链接同一份 `runtime/hsvm` | proposed |
| D-03 | C2 用局部支撑编码（块对角 + 每步初等变换），避免 O(N²) | proposed |
| D-04 | ψ 双档：table（w≤16，仅正确性）/ SPN（w∈{48,64}） | proposed |
| D-05 | i = (opcode, operands)，v(i) 公开，不作为秘密 | embodied（M1 实现） |
| D-06 | s = 寄存器堆 + 标志；x = A2 可观测子集（内存窗口 + 输出） | proposed（需在 M2 前冻结） |
| D-06b | MVP 堆内存明文，明确声明在 C1/C2 保护范围外 | proposed |
| D-07 | 不可虚拟化函数整体回退，绝不半虚拟化 | proposed |
| D-08 | pass 位置：`Order[]` 中排在 mba 之后、alias/bcf/fla 之前 | proposed |
| D-09 | 参数通道：`-mllvm -hsvm-*` 为主，policy JSON 平铺扩展 | embodied（hsvm_params） |
| D-10 | C6 只在基本块/epoch 边界挂钩，热循环禁止采集 | proposed |
| D-11 | 工作负载冻结为 crc32/base64/bignum/hashtable/aes_round，权重固定 | embodied（protocol.json） |

## ADR-006 G1-模型层判定与后续选择（2026-11-17）

**结论：G1-模型层门禁失败（仅成本一项）。** 网格 48 个合法点：
Γ p5 ≥0.5 与非仿射 16/16 全部通过；`step_cost_ratio ≤3` 一个都没有。
最低成本点为 w=8 表（5.62×，但 2^8 可枚举）；w≥48 的最佳点为 22.11×。

**这不是协议变更**，网格、指标、阈值都没动；失败由预注册的门禁直接给出。

判定前修复的两个实现缺陷（已包含在网格结果中）：
1. `mixBlock` 的逆矩阵按 4×4 行跨度存储，2/3 车道块被按 n 跨度索引 → w=16/48 往返失败。
2. SPN 扩散按 4 字节分块且无跨块混合 → 雪崩只有 ~25%；加入每轮车道旋转后达到 ~50%。
两项都是测试先失败、再修实现，修完才跑网格；不是"调参直到通过"。

**三个可选下一步（需在开 M3 前决定）：**

| 方案 | 内容 | 代价 / 风险 |
|---|---|---|
| A | 接受 §10.1.1 判定，终止 C1/C2 路线，归档 G0/G1 | 放弃该研究方向；已有证据完整可复现 |
| B | 授权一轮实现优化（延迟 v 的偏移累加器 + ARX ψ），在同一网格重跑 G1 | 不改协议；预计 w=48/64 仍 8–12×，大概率仍不通过 |
| C | 改路线：C2 先行，使 w=32 的查询成本可接受（新协议版本） | 属研究路线变更，必须新开 protocol 版本并重算哈希 |

## ADR-007 方案 B 执行结果：ARX 变体仍不达标（2026-11-17）

按 ADR-006 方案 B，在同一网格条件（n=512, m=256, seed=12345, states=128, dirs=4）
下增加第三族 ψ（ARX：add-rotate-xor，4/8 轮），作为**补充实验**跑 12 个点
（`reports/G1-model-addendum/`）。登记的 48 点网格与协议哈希未改。

| 点 | SPN ratio | ARX ratio |
|---|---:|---:|
| w=48, c=8, r̄=2, 4 轮 | 22.11 | **10.85** |
| w=64, c=8, r̄=2, 4 轮 | 27.78 | 12.85 |
| w=32, c=8, r̄=2, 2/4 轮 | 19.34（2 轮） | 10.51（4 轮，2^32 可枚举，不可用） |

结论：ψ 成本减半，但最好的"不可枚举"点仍为 **10.85× > 3×**。瓶颈已从 ψ 转移到
**O(w) 的窗口读取**（w=48 时约 48 次位提取，约占单步 40%）；即使 ψ 零成本，
w=48 仍需 ~9×。这是构造性成本，不是实现瑕疵。

**建议执行方案 A（终止 C1/C2 路线并归档）。** 若坚持继续，只剩方案 C，必须新开
协议版本；不得在现有预注册下继续调参。

`params.h` 增加 `PsiMode::Arx` 属实现扩展，`protocol.json` 的网格仍只登记
table/spn，补充实验不参与登记门禁的判定。

## ADR-008 协议 v2.0（草稿）：C2 先行 / 薄窗口（2026-11-17）

- 文件：`PROTOCOL-v2.md`、`protocol-v2.json`；校验通过，哈希
  `a9929c6c09042b7cbffd01e0cf72f8a571b8a5dc10ad4113ab2a1f51999fadb5`
- v1 哈希（`f964755d…515c1f`）与其报告**保持原样**，不重判。

**与 v1 的差异（只列会改变判定的）：**

| 项 | v1 | v2 |
|---|---|---|
| 阶段顺序 | C1 先，C2 后 | C2 先（但只在 G0v2 通过后才实现） |
| 不可枚举的判据 | w ≥ 48 | C2 接口上实测 ψ oracle 探测数 > 2^40 |
| 安全门位置 | 阶段 1（无编码模型） | 阶段 2（C2 构建上实测） |
| 第一道门 | 跑 48 点网格 | **G0v2 成本下界**（解析 + 实测，取大者） |
| 窗口网格 | w ∈ {8,16,32,48,64} | w ∈ {8,16,32}（薄窗口） |
| ψ 族 | table / spn | table / spn / arx |
| 成本口径 | 4.2 ns 基线，cap 3.0 | **完全相同**（不换尺子） |
| 攻击者模型 | A2 | A2-static（A2-dynamic 写为已知边界） |

**预注册预期（写在协议里，不是事后解释）：** w=8/c=8/r̄=1 的解析下界约 25 个词操作，
对约 10 个操作的 plain 指令 ≥2.5×；加上任何真实 ψ 后预计落在 3–6×。
**即本草案自己预计会在 G0v2 终止**，不进入 C2 实现。

**新增停止规则：** `g0v2_cost_floor_above_cap`、
`encoded_oracle_below_2pow40_probes`（其余两条沿用 v1 措辞）。

**状态：** 草稿，未执行任何 v2 实验。下一步只允许做 G0v2（成本下界工具），
不得先写 C2 代码。

## ADR-009 G0v2 判定：v2 路线终止，不实现 C2（2026-11-17）

按 ADR-008 只做了 G0v2（`tools/hsvm_floor`），未写任何 C2 代码。

**下界（16 个薄点）：** 只有 w=8 / c=8 / r̄=1 / table 过线，10.61 ns = **2.53×**，
对 cap 3.0 的余量仅 18%；其余 15 点全部超限（13.4–40.9 ns）。

**决定性反驳：** 用现有 `stepWords` 内核在同一参数点实测：
`model_ns=28.88, plain_ns=4.34, ratio=6.65`。下界与实测相差 2.7×，
而该点余量只有 1.18×。即下界不能证明"实现足够好就能达标"，反而证明不能。

**判定：失败，触发 `g0v2_cost_floor_above_cap`。**
理由不是"下界估高了"，而是唯一可行点在真实内核上就是 6.65×；
把窗口、掩码、ψ、调度全部压到零，剩散布一项仍是 5.54 ns（1.28×），
再叠加实测与下界的 2.7× 差距，量级上无法回到 3×。

**后果：**
- 不实现 C2；v2 无第二阶段实验。
- v1（`f964755d…`）与 v2（`a9929c6c…`）的结论一致：该构造族在"lean 基线 + ≤3×"下无可行点。
- 至此 C1/C2 路线按文档 §10.1.1 正式终止；G0（线性层可被完整恢复）与
  G1/G0v2（成本不可行）构成完整证据链。

**遗留（不属于本路线）：** G0 的结论——线性消融在 16 次查询内被完整恢复——
与成本无关，仍然成立且可复现。

## ADR-010 阶段 4A/4B 落地：C6 证据层与 C7 多样性证伪（2026-11-17）

在 C1/C2 已被成本门否决之后，文档里仍可独立推进的两块已补上。

**4A（C6）**：`include/hsvm/c6.h` + `src/c6.cpp` + `tests/test_c6.cpp`。
三平面 checkpoint、链式摘要、逐实例密钥绑定、Green→Yellow→Red→Dead 状态机、
`poisonMask()` 只进数据通路不进分支。18 条断言，含"无密钥伪造链不可验证"、
"单平面篡改在其余平面留痕"、"checkpoint 顺序改变摘要"。
**边界**：不阻止篡改；摘要非密码学哈希；尚未在 `Machine::step` 内埋点；
未对接 `polaris_secure/risk_model.h`。

**4B（C7）**：`scripts/run_c7_diversity.py`，16 种子 × 同一参数点。
结果：每个实例都在 **16 次查询**内被 A1 完整恢复（16/16，mismatch 0），
Γ p5 跨度 0.0195。多样性改变了编码，**没有改变攻击成本** —— §12.5 的负收益假设
在"线性消融 + 轨迹差分"这一攻击面上成立。
**限制**：成本列因单次计时不可用；跨实例模式匹配类攻击未实现，故 C7 的正面价值仍未被证伪。

**仍未做（不属于本轮可补范围）**：C2 实现、阶段 3 全局正规化攻击实验、
阶段 4 的 G3/G4 博弈与模型提取度量、阶段 5 Native VM 与 LLVM pass。
这些都以 C1/C2 的成本可行性为前提，而该前提已被 G1/G0v2 否决。

## ADR-011 阶段 3 落地：模块编码 + 全局正规化实验（2026-11-17）

补齐文档 §6 的可做部分，不改协议。

**实现**：`modenc.h/.cpp` 逐 lane 随机双射（模块编码，带逆），
`tests/test_modenc.cpp` 8 条断言（往返、逐 lane 双射、lane 独立、种子敏感、非恒等），
`tools/hsvm_normalize.cpp` 提取型攻击探针。

**结果**：w=8/16/24（1/2/3 模块）下查询数分别为 256 / 65,536 / 16,777,216，
严格等于 2^w，与模块数无关。判定 `module_cost_supported = false`：
模块结构为攻击者增加的查询数为 0。

**边界**：用的是比文档更强的攻击者（全表枚举），故只对提取型攻击成立；
文档 §6.2 的代数正规化攻击**未实现**，不能声称其可行。适用窗口 ≤24 位。

**阶段 3 剩余项**：§6.2 的代数正规化攻击（对仿射共轭做等价性求解）未做；
它需要仿射等价算法，属于新实现而非本轮补缺。

## ADR-012 阶段 4：G3/G4 博弈度量落地（2026-11-17）

`tools/hsvm_games.cpp` 按 §7.3 在模型层执行两局博弈，攻击对象是窗口映射
`psi: F2^w→F2^c`（单步中攻击者无法从公开代码重算的部分）。

结果（`reports/S4-g3g4/games.json`）：

| w | 查询 | G3 恢复 | 一致率 | 模型字节 | G4（≤4KiB） |
|---:|---:|:--:|---:|---:|:--:|
| 8 | 256 | yes | 1.000 | 2,048 | **yes** |
| 16 | 65,536 | yes | 1.000 | 524,288 | no |
| 24 | 1,048,576（预算耗尽） | censored | — | 134,217,728 | no |

**结论**：G3 在 w≤16 全部成功；G4 只在 w=8 成立。而 w=8/c=8/r̄=1 正是成本门禁
（G1、G0v2）里唯一可行的点 —— 唯一能跑的工作点也是唯一能被压进 4 KiB 模型的点，
两者叠加意味着该构造没有"既便宜又不可提取"的区域。

**删失处理**：报告级 censored=true（总查询 1,114,112 < 总预算 3×2^20）；
`completed_games=[8,16]`、`censored_games=[24]` 写进 metrics，w=24 的成功率字段不得引用。

**边界**：模型层博弈，无 A3（可改代码）等级、无反调试与内存加密；
4 KiB 判断用的是"一窗口一 uint64"的朴素表示，更紧的位打包/分段表示未测，
可能改变 w=16 的结论。

## ADR-013 G4 的信息界：w≥16 不可能满足 4 KiB（2026-11-17）

`scripts/g4_info_bound.py` 计算表形态模型的下界：`c·2^w` bit。
w=8 → 256 B（可达），w=16 → 131,072 B，w=24 → 50 MB，w≥32 达 GB 级。
结论：**w≥16 时 G4 在任何表表示下都不可能通过**，与实现优劣无关；
能通过 G4 的窗口只有 w=8，而 w=8 也正是成本门禁唯一可行的点、G3 一次枚举即成功的点。

**限制**：该界只约束表形态。若攻击者已知族结构（ARX 的 8 个 64 位密钥仅 64 B），
4 KiB 约束不再有意义；这条路径需要密钥恢复算法，未实现、未测。

## ADR-014 C6 接入真实执行轨迹（2026-11-17）

`Machine::setIntegrityMonitor()` + `pristine_` 副本：每步把实际执行的 8 字节指令
与载入时的副本比对，送入 ControlFlow 平面。`patchInstructionByte()` 提供测试用的
改码钩子。`test_c6` 增至 25 条断言，含"改一条指令即离开 Green"与"篡改后 poison 非 0"。

**未做**：Memory / Timing 平面的真实埋点（无数据源）；A3 等级（可改检查代码本身）未建模，
本层只保证"改数据/改代码留痕"，不保证"改检查器后仍然报错"。

## ADR-015 C6 Memory 平面接入（2026-11-17）

`Machine` 新增 `shadow_`（随 `writeMem` 同步）与 `verifyMemoryPlane()`
（比较 `mem_` 与 `shadow_` 的 FNV 摘要，送 Memory 平面）。`pokeMemory()` 是测试用的
"绕过 VM 直写缓冲区"钩子。`test_c6` 增至 28 条断言：经正规路径写入保持 Green，
直写一个字节即 Red。

**未做 Timing 平面**：进程内自测会随机器负载抖动，写不出稳定断言；
正确做法是由宿主提供外部 tick，属整机集成，不在本轮。

## ADR-016 §6.2 第一步：仿射 module 编码可从单表识别（2026-11-17）

`tools/hsvm_ddt.cpp` 用差分分布表（DDT）的行多重集做判据：
仿射包装 `A2∘ψ∘A1` 的 DDT 与 `ψ` 的 DDT 行多重集完全相同（仿射对差分线性），
随机逐 lane 双射则不相同。结论：**仅凭一张表即可识别仿射共轭并据此对齐模块结构**。
测试已注册为 ctest `ddt_normalization`（exit 0 = 可识别）。

**边界（必须一起引用）**：这是 §6.2 的**识别**部分，不是**归一化**。
未实现 A1/A2 恢复与 ψ 还原（仿射等价求解），因此"仿射模块编码可以被完整剥离"
仍未被证明——只能说它的差分指纹藏不住。

## ADR-017 §6.2 第二步（归一化）尝试失败，工具已撤回（2026-11-17）

想做的是线性情形下的完整剥离：若 ψ 线性，则 `A2∘ψ∘A1` 仍是仿射，
理论上用 `F(0)` 加 8 个基向量共 9 次探测即可精确重建，从而彻底去掉 module 编码。

**结果：未通过。** 线性 ψ 与非线性 ψ 各测 256 个输入，都得到 252 个不匹配。
两种情形同样失败，说明问题在我的仿射矩阵"行/列方向"约定（`applyAffine` 按行点乘，
而 9 点重建自然得到的是列的像），不是方案本身不成立；但我没在这一轮内定位并修正。

**处置**：`tools/hsvm_affine_recover.cpp` 与对应 ctest 已从树中删除
（不留会红的测试、也不留半成品工具）；本条改动的净效果是 **零代码变更**。
§6.2 的结论维持在 ADR-016 的位置：**识别已证，归一化未证**。

**下一步（若继续）**：先写不涉及编码的自检——验证 `applyAffine` 满足
`F(a⊕b)=F(a)⊕F(b)⊕F(0)`，确认矩阵约定后再接 9 点重建；
失败用例应覆盖奇异矩阵与所有 8 个基向量方向，避免再次"看起来对、全表错"。

## ADR-018 §6.2 归一化（线性情形）通过（2026-11-17）

修正 ADR-017 的失败：先用 `F(a⊕b)=F(a)⊕F(b)⊕F(0)` 做加法同态自检，
把 `applyAffine` 的行/列约定钉死（0 violations），再做 9 点重建。

结果（`reports/S3-modenc/affine_recover.json`，exit 0）：
- 线性 ψ：9 次探测、256 个输入 **0 误差** → 仿射 module 编码被完整剥离；
- 非线性 ψ（table）：同样 9 次探测 **247/256 错** → 剥离失败。

因此 §6.2 现在的准确结论：**线性 module 的编码可整体归一化（已证 + 可复现）**；
非线性 module 只到"可识别"（ADR-016 的 DDT 指纹），完整归一化仍需仿射等价求解。

教训（写进流程）：任何"几点探测重建线性/仿射对象"的实现，必须先跑同态自检，
否则错误会以"全表都错、原因不明"的形式出现——ADR-017 就是这么浪费掉的。

## ADR-019 DFA 实测：换钥后的 wbaes 二进制 9 条密文即被取钥（2026-11-17）

外部报告（`wbaes_recovery.zip`）对 `wbaes_baked_keyrot_ec326393` 做第 9 轮单字节故障注入，
用 1 条正常 + 8 条故障密文恢复出 `K10` 并逆推主密钥 `ec326393…`。

本地**独立复核**（不是复述）：用独立实现的 AES-128 密钥扩展重算 K10 = `42a4d331…c07d`
（与报告一致）；16 组验证向量用 openssl 重算全部一致（16/16）；故障样本 8 条。

**判定：DFA 攻击面失败。** 攻击者等级为 A3（可控运行时状态），不在 C1/C2 防护范围。
66 MiB 表对 DFA 无作用——攻击不读表，只比较密文差异。这与 wbaes README §6 的自述一致，
现由实测确认。

**对本项目的影响**：加表不加安全。若要对上 DFA，只有 C6 范畴的手段有效
（冗余计算比对、故障不变式、把状态自洽加入 Memory 平面），三条均未实现，已列入待办。

## ADR-020 C6 抗 DFA 第一步：转移冗余比对（2026-11-17）

`Machine::setFaultCheckEnabled(true)` 每步把 `s⊕v(i)` 算两遍比对；不一致计入
`faultsDetected()` 并向 Memory 平面报 mismatch。`injectFault(bit)` 是测试钩子。
`test_c6` 增至 34 条断言：干净运行 0 检测、注入单比特故障 1 次检出、状态升到 Red。

**边界**：代价 2×（本就已超 ≤3× 预算，不会因它变可行）；只覆盖"两份计算之间"的故障；
A3 级（改表/改检查器本身）不覆盖；**wbaes 二进制未加此检查，DFA 报告的结论不变**。

**未做的另外两条**：故障不变式、把状态自洽并入 shadow 比对（shadow 机制已具备，接入即可）。

## ADR-021 §6.2 非线性分支收敛 + 阶段 5 切片 1（2026-11-17）

**§6.2 非线性**：不实现仿射等价求解器，理由写在
`reports/S3-modenc/nonlinear-normalization.md`：w=8 时 F 本身 256 字节即是模型
（G4 实测 2,048 B 朴素 / 256 B 打包），剥离编码不减小模型；w≥16 时信息界
`c·2^w` 与编码无关。结论是"归一化无收益"而非"未完成"。适用边界：表形态 ψ；
ARX 族是密钥恢复问题，未测。

**阶段 5 切片 1（已做）**：`include/hsvm/mir.h` + `src/mir.cpp`，字节码 → `MirOp`
的无损提升，`lift`/`emit` 逐字节互逆，未知 opcode 与截断输入一律拒绝而非猜测。
`tests/test_mir.cpp` 103 条断言，注册为 ctest `mir`（共 19 个测试）。

**未做**：MIR → LLVM IR lowering、寄存器分配、LLVM pass 接入、重建 Polaris clang。
切片 1 只保证"能把字节码读成结构化形式且不丢信息"，不保证任何语义等价。

## ADR-022 阶段 5 切片 2 前置：语义规格已固定，lowering 未实现（2026-11-17）

`reports/S5-nativevm/slice2-semantics.md` 把 16 条 opcode 的语义、fault 条件与三个边界
（内存小端、位移掩码 31、32 位回绕）逐条对应到 `src/machine.cpp` 的 `switch (op)`。

**未实现**：MIR → LLVM IR 的 lowering、寄存器分配、pass 接入、重建 clang。
切片 2 的验收判据已写明（差分测试 + fault 停机一致 + 三个边界断言），但尚无代码。

诚实标注：本条产出是**规格**，不是实现。阶段 5 的剩余工作量估计 1–2 周工程
（800–1200 行 lowering + 600–900 行状态布局 + 重编 clang）。

## ADR-023 阶段 5 切片 2a：16 opcode 可执行语义（2026-11-17）

`include/hsvm/semantics.h` 把 `slice2-semantics.md` 变成可执行代码：`SemState` +
`semStep`，纯函数、不依赖解释器，作为后续 lowering 的对照 oracle。
fault 是语义的一部分（越界寄存器、越界/未对齐地址 → `faulted` 并停止）。

`tests/test_semantics.cpp` 38 条断言，覆盖 16 条 opcode 与全部边界：
32 位回绕（`0-1`、`0x10001*0x10001`）、位移掩码（`Shl 1,33` = 2）、
逻辑右移（`0x80000000 >> 31` = 1）、内存小端往返、未对齐与越界 fault、
有符号跳转位移（`Jmp -2`）、`Brz` 取/不取、停机指令后不再执行、寄存器 63 合法 / 64 故障。
注册为 ctest `semantics`（共 20 个测试）。

**未做**：MIR → LLVM IR lowering 本身、寄存器分配、pass 接入、重建 clang。
切片 2 的完成判据现有一条可执行的尺子：lowering 后的实现与 `semStep` 逐条差分一致。

## ADR-024 V-03 差分框架落地，并抓出三处规格错误（2026-11-17）

`tests/test_diff.cpp`（ctest `diff`，13 断言）逐步锁步比较解释器与 `semStep`：
regs / mem / pc / 停机标志 / 故障标志，分歧时报 step、pc、指令反汇编与字段名。

抓到的三处错误：
1. 寄存器数是 **16**（`Machine::kMaxRegs`，`regCount_ = p.n / 32`），我此前在 `semantics.h`
   写死 64 并断言"寄存器 63 合法"——已改为从机器读入 `regCount`，断言 15 合法 / 16 故障。
2. `Machine::step()` 在故障路径返回 true（只置标志并停止）；比较返回值是在比约定，
   已改为比较状态位。
3. `allops` 在 Plain 模式第 12 步故障（`ld r11,[r12+0xb0b0b0b]` 地址越界），与
   `programs.h` 的"只在 linear 模式有意义"注释一致；真实覆盖改用 sum / crc / copy_xor。

**新增只读访问器**（不改行为）：`pcValue()`、`code()`、`stepOnce()`。
**未做**：lowering（V-04 起）。

教训：oracle 不依赖解释器是对的，但 oracle 的**常量**必须由解释器校准；
写死 64 寄存器这类错误只有差分测试能抓出来。

## ADR-025 V-04 寄存器类 lowering，三方差分与变异检验（2026-11-17）

`lower.h/lower.cpp` 定义最小 IR（`Const/Copy/Add..Shr`），一条字节码降 0–1 条 `IrOp`；
`Nop` 降 0 条，`Ld/St/Jmp/Brz/停机指令` 一律拒绝（false，不追加），拒绝语义显式可测。

`tests/test_lower_regs.cpp`：`Machine(Plain)` ↔ `semStep` ↔ `lowerOp+irExec` 三方锁步，
16 条指令覆盖 11 个寄存器类 opcode，三种初值，14 条断言全绿。

**变异检验**（第一次做，发现两个问题）：
- 把 `Shl` 改成 `Shr` → 测试在 step 9 / pc 8 / r9 定位到分歧，说明比对是活的；
- 把掩码 `&31` 改成 `&63` → **仍然全绿**：ARM64/x86 的移位对位移量取模 32，
  掩码在位级上不可观测。故 `&31` 是防御性写法，不是可测行为，报告已如实标注。

**未做**：访存/分支 lowering、真实程序三方比对、LLVM IR 发射。

## ADR-026 V-05 全 opcode lowering 与真实程序三方比对（2026-11-17）

`src/lower.cpp` 覆盖 16 个 opcode（新增 `Load/Store/Jmp/Brz/Stop`）；
`tests/test_lower_full.cpp`（ctest `lower_full`，19 断言）在 `sum/crc/copy_xor/allops`
上三方锁步：解释器 ↔ oracle ↔ lowering，每步比全部寄存器 + 4 KiB 内存按字 + pc + 状态位。

**两个被测试抓出的缺陷**：
1. V-05 重写 `lowerOp` 时漏了 `default`，ISA 外的 opcode 会落到 `push_back` 并变成默认的
   `Copy`——损坏字节码被"成功"降级。断言红了之后补 `default: return false`。
2. `ff18f7275` 中混入了变异实验的 `& 63u`（应该是 `& 31u`）：回滚时我恢复了含变异的临时
   备份。本轮改正。**今后变异检验的回滚以 `git diff` 为准，不信临时文件。**

**终止语义**：把寄存器全填大值，`sum/crc/copy_xor` 的循环计数也被填大，8192 步内不停机；
只有 `sum` 从零寄存器起跑 6 步会命中停机指令。报告按此如实记录，不拿"8192 步一致"当终止证明。

**未做**：LLVM IR 发射（V-07）、跨平台验证、性能口径实测。

## ADR-027 V-07 原生代码发射（C）与真实编译器差分（2026-11-17）

`emit_c.h/emit_c.cpp` 把 lowering 的 `IrOp` 发射成 C 源码，`tests/test_emit.cpp`
（ctest `emit_c`，18 断言）用 `clang -O1` 编译并运行，比对**退出码 + 报告字符串**。

覆盖三种结局：正常停机（0）、地址越界故障（3）、步数超预算（5）。
`memround` 用例专门验证访存：`St` 后 `Ld`，断言 `r0=0x11223344` 且内存摘要不等于全零数组。

**偏离计划**：原定发射 LLVM IR 文本，实际发射 C——手写 `.ll` 会引入与语义无关的失败来源；
LLVM IR 放在 V-08 的 Polaris pass 里。代价：这里不能取性能口径（优化强度不同）。

**边界**：`budget`（步数上限）是发射层自定界，不属于 ISA/解释器语义；
只验证过 arm64 macOS；正常停机只由 sum/memround 两个用例覆盖。

## ADR-028 V-08/V-09 Polaris pass 接入与工具链重建（2026-11-17）

**V-09**：`ninja LLVMObfuscation` → `ninja clang`，clang 版本从 `832aca214` 前进到 `8e3dd9795`（= HEAD）。
`git log 832aca214..HEAD -- src/llvm` 为 2，证明旧二进制确实落后——我此前"src/llvm 没改所以不用重编"的判断是错的。

**V-08**：新增 `HSVMLowering`（`-passes=hsvm`），契约 `@hsvm_bytecode`（`[N x i8]`，8 字节/指令）
+ `@hsvm_entry`（`i32 ()`）。降低寄存器类 opcode 与停机指令；`Ld/St/Jmp/Brz` 明确拒绝
（`hsvm: opcode not lowered yet: <Name>` 中止编译），不产出错代码。opcode 值经宏取自 `HSVMOpcodes.def`。

三个接线坑：
1. 新 pass 必须在 `addObfuscationPass()` 的 if 链**和** `buildObfuscationPipeline()` 的 `Order[]`
   白名单两处登记，否则 `unknown obfuscation pass`；
2. C 全局名是 `hsvm_bytecode`（下划线），只查 `hsvm.bytecode` 会让 pass 静默不生效，
   表现为链接期 `undefined _hsvm_entry`；
3. `report_fatal_error(std::string)` 重载歧义，用 `Twine`。

**验证**：`scripts/verify_vmp_pass.sh` 退出 0——寄存器程序返回 49（与 oracle 一致），
含 `ld` 的程序被拒绝且信息明确。

**未做**：访存/分支 lowering、真实程序端到端、把 gate 接进 ctest（V-10）、性能口径。

## ADR-029 V-10 pass 覆盖全 opcode，真实程序端到端打通（2026-11-17）

`HSVMLowering` 现在降低全部 16 个 opcode（新增 `Ld/St/Jmp/Brz`），故障与 pc 越界分别返回
`0xFFFFFFFE` / `0xFFFFFFFF`，以便在单值返回通道上区分两种异常。契约新增可选 `@hsvm_init`
（i32 常量）设定初始寄存器值。

新增 `tools/hsvm_dump_program`（导出 C 源码 + 用 oracle 算期望）与
`scripts/verify_vmp_gate.sh`（已接进 ctest，名字 `vmp_gate`）。gate 通过：
`sum/zero → r0=0`、`sum/small → r0=6`、`crc/zero → fault`、`copy_xor/zero → fault`、
`allops/fault → fault`、ISA 外 opcode 被拒绝。

**两个真问题**（都先红后修）：
1. pass 把寄存器初始化成 0，而 oracle 从 `initRegs` 起跑——两边跑的不是同一个程序，
   表现为 `sum/small` 期望 `r0=6` 实际 `r0=0`。加 `@hsvm_init` 修复。
2. `-O1` 会折叠全常量程序（`sum` 初值 0x12345678 需 20 万步以上，原生瞬间返回）。
   这不是 lowering 的错，是选错判据；gate 改为只比对折叠后仍可观测的结局。

**未做**：pass 侧无步数预算概念（只有 oracle 会截断）；性能口径未测；
`crc`/`copy_xor` 目前只覆盖故障路径，未覆盖正常跑完。
