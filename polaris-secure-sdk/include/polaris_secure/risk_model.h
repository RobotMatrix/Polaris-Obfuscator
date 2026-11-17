// polaris_secure/risk_model.h — 风险分析层: 特征 / 传感器 / 模型 / 策略控制器
// 对应参考架构 §8:
//   - 小模型只输出风险信号, 不直接决定授权/释放密钥 (§8.2)
//   - 模型文件签名 + 版本校验; 失败时降级规则引擎, 确定性策略不受影响
//   - 决策链: 信号 → 特征 → 模型 → 策略控制器(独立确定性检查) → 最终策略
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "bytes.h"

namespace polaris_secure {

// ---- 特征集 (12 维, 归一化 [0,1]) ----
enum RiskFeature : int {
    kFtIntegrityMismatch = 0,  // 完整性校验不一致 (硬性)
    kFtDebugger = 1,           // 调试器附加
    kFtHook = 2,               // Hook 检测 (inline/fishhook/plthook)
    kFtInjection = 3,          // 注入 / 异常模块
    kFtRootJailbreak = 4,      // Root/越狱
    kFtEmulator = 5,           // 模拟器
    kFtTimingAnomaly = 6,      // 关键路径时序偏离基线
    kFtCallSeqDeviation = 7,   // 调用序列偏差
    kFtMemoryTamper = 8,       // 关键内存篡改
    kFtStorageTamper = 9,      // 受保护存储篡改
    kFtAttestationFail = 10,   // 设备证明失败 (硬性)
    kFtPolicyStale = 11,       // 策略/模型版本过期
    kFeatureCount = 12,
};

using FeatureVector = float[kFeatureCount];

// 传感器接口: 平台实现注入; 默认全零 (无信号)。
// 参考 §2.1: 传感器在普通 App 环境, 属"不可信信号源"。
class SecuritySensors {
public:
    virtual ~SecuritySensors() = default;
    virtual void collect(FeatureVector out) const;
};

// ---- 模型包格式 ----
// PRM1 | version u32 | feats u32 | hid u32 |
// w1(feats*hid int8) | b1(hid int8) | w2(hid int8) | b2(int8) |
// s_w1 f32 | s_b1 f32 | s_w2 f32 | s_b2 f32     [以上为待签正文]
// | sig(64)   [签名 = Ed25519(model_key, 正文)]
// 量化策略: 每张量独立对称 int8 尺度; 推理时反量化为 float 计算
struct RiskModel {
    uint32_t version = 0;
    uint32_t feats = 0;
    uint32_t hid = 0;
    std::vector<int8_t> w1, b1, w2;
    int8_t b2 = 0;
    float s_w1 = 0, s_b1 = 0, s_w2 = 0, s_b2 = 0;
    bool has_signature = false;
    uint8_t sig[64] = {0};
    std::vector<uint8_t> body() const;  // 待签正文
};

enum class ModelStatus { Ok, BadFormat, BadSignature, Unsupported };

// 装载并验签模型 (model_key: Ed25519 公钥)
ModelStatus loadRiskModel(const uint8_t* blob, size_t n, const uint8_t model_key[32],
                          RiskModel& out);

// 推理: 返回风险分 [0,1] (仅风险信号, §8.2)
float riskInference(const RiskModel& m, const FeatureVector x);

// 规则引擎基线 (模型不可用时的确定性降级): 硬性因子加权
float ruleEngineRisk(const FeatureVector x);

// ---- 策略控制器 ----
// 确定性门 (不可妥协): 全部通过才可能 Allow; 风险分只影响降级/拒绝。
struct DeterministicGates {
    bool license_valid = false;    // 授权验证通过 (签名/时间/绑定/防回滚)
    bool integrity_ok = false;     // 自身完整性检查通过
    bool protocol_fresh = false;   // 无重放 (nonce/挑战校验通过)
    bool model_authentic = false;  // 模型签名验证通过 (false → 降级规则引擎)
};

enum class Decision : uint8_t { Allow = 0, AllowDegraded = 1, Deny = 2 };

struct PolicyDecision {
    Decision decision = Decision::Deny;
    float risk = 0.0f;               // 最终采用的风险分
    bool used_rule_engine = false;   // 模型不可用 → 规则引擎兜底
    std::string reason;
};

struct PolicyParams {
    float degrade_threshold = 0.5f;  // >= 该值降级运行
    float block_threshold = 0.8f;    // >= 该值拒绝
};

// 核心决策函数 (§8.3 决策链的最后一环)
//  - 任何确定性门失败 → Deny (与风险分无关: 模型被篡改也救不回)
//  - 风险分仅由 模型(或规则引擎) 输出, 只能让 Allow 变差, 不能变好
PolicyDecision policyDecide(const DeterministicGates& gates, float model_risk,
                            float rule_risk, const PolicyParams& p = PolicyParams());

}  // namespace polaris_secure
