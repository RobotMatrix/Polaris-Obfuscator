# 阶段 4A：C6 执行完整性证据层（实现记录）

对应文档 §12.2（多平面检查与可伪造性）、§12.3（证据结构与风险状态机）、§12.4（检测位不得成为分支控制杆）。

## 交付

| 文件 | 内容 |
|---|---|
| `include/hsvm/c6.h` | `EvidencePlane`、`RiskState`、`Checkpoint`、`EvidenceChain`、`IntegrityMonitor` |
| `src/c6.cpp` | 链式摘要、每实例密钥绑定、状态机、`poisonMask()` |
| `tests/test_c6.cpp` | 18 条断言，覆盖 7 组场景 |

## 设计要点（逐条对应文档）

1. **多平面**：`ControlFlow / Memory / Timing` 三平面各自独立 checkpoint；
   单平面被改，其余平面仍会给出不一致（`testSinglePlaneTamper`）。
2. **链式证据**：`tag_i = mix(tag_{i-1}, plane, observed, expected, key)`。
   改一个 checkpoint 必须重算其后全部 tag；顺序也会改变摘要值
   （`checkpoint order changes the chain digest`）。
3. **按实例密钥绑定**：不知道 key 就无法构造可验证的链
   （`chain rebuilt without the key does not verify`、
   `chain does not verify under a different instance key`）。
4. **状态机**：Green → Yellow（漏报平面）→ Red（不一致）→ Dead（重复不一致，阈值 3）。
5. **不作为分支杆**：检测结果只以 `poisonMask()` 的形式进入数据通路，
   Green 时为 0、其余状态非 0 且对固定链稳定
   （`poison distinguishes clean from tampered without branching`）。

## 整机集成（本轮补上）

`Machine` 现在有 `setIntegrityMonitor()`：每步把**正在执行的 8 字节指令**与
`loadProgram` 时保存的 pristine 副本比对，作为 ControlFlow 平面送入监控器；
`patchInstructionByte()` 是测试用的"攻击者改代码"钩子。

`testMachineIntegration` 的三条断言：
- 未篡改时状态保持 Green、mismatch 0、每步都有 checkpoint；
- 改掉一条指令的操作数字节后，状态离开 Green；
- 篡改后 `poisonMask() != 0`。

这让 C6 从"单元层组件"变成"接在真实执行轨迹上"的检查层。
仍未做：Memory / Timing 两个平面的真实埋点（目前只有 ControlFlow 有数据源）。

## 边界（必须一起读）

- 本层**不能**阻止篡改。攻击者拥有进程，就能连检查一起改。可测的性质只有两条：
  无密钥的伪造链不能通过校验；单平面修改在其余平面留痕。
- 摘要用的是 64 位非密码学混合函数，**不是** MAC/签名。它的作用是"没有 key 需要猜 64 位/链节"，
  不是可证明安全。
- 只有 ControlFlow 平面接入了真实轨迹；Memory/Timing 两平面仍只有接口与单元测试。
- 文档 §12.9 的跨平台接口（`polaris_secure/risk_model.h`）未改，也未与本层对接。

## 复现

```bash
cd research/hsvm && cmake --build build -j10 && ./build/test_c6
# == c6: 18 pass, 0 fail ==
```
