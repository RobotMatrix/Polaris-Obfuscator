// 风险分析层实现: 模型装载/验签/推理 + 规则引擎 + 策略控制器
#include "polaris_secure/risk_model.h"
#include "polaris_secure/crypto.h"

#include <cmath>
#include <cstring>

namespace polaris_secure {

using prim::ed25519_verify;

void SecuritySensors::collect(FeatureVector out) const {
    for (int i = 0; i < kFeatureCount; i++) out[i] = 0.0f;
}

// ---- 模型包 ----
static uint32_t rd_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static float rd_f32(const uint8_t* p) {
    float f;
    memcpy(&f, p, 4);
    return f;
}

std::vector<uint8_t> RiskModel::body() const {
    std::vector<uint8_t> b;
    b.insert(b.end(), {'P', 'R', 'M', '1'});
    auto put32 = [&](uint32_t v) {
        for (int i = 0; i < 4; i++) b.push_back((uint8_t)(v >> (i * 8)));
    };
    put32(version);
    put32(feats);
    put32(hid);
    auto putArr = [&](const std::vector<int8_t>& a) {
        b.insert(b.end(), (const uint8_t*)a.data(), (const uint8_t*)a.data() + a.size());
    };
    putArr(w1);
    putArr(b1);
    putArr(w2);
    b.push_back((uint8_t)b2);
    uint8_t s[4];
    memcpy(s, &s_w1, 4);
    b.insert(b.end(), s, s + 4);
    memcpy(s, &s_b1, 4);
    b.insert(b.end(), s, s + 4);
    memcpy(s, &s_w2, 4);
    b.insert(b.end(), s, s + 4);
    memcpy(s, &s_b2, 4);
    b.insert(b.end(), s, s + 4);
    return b;
}

ModelStatus loadRiskModel(const uint8_t* blob, size_t n, const uint8_t model_key[32],
                          RiskModel& out) {
    if (n < 12) return ModelStatus::BadFormat;
    if (memcmp(blob, "PRM1", 4) != 0) return ModelStatus::BadFormat;
    out.version = rd_u32(blob + 4);
    out.feats = rd_u32(blob + 8);
    out.hid = rd_u32(blob + 12);
    if (out.version != 1) return ModelStatus::Unsupported;
    if (out.feats == 0 || out.feats > 64 || out.hid == 0 || out.hid > 64)
        return ModelStatus::BadFormat;
    size_t body_len = 16 + out.feats * out.hid + out.hid + out.hid + 1 + 16;
    if (n != body_len + 64) return ModelStatus::BadFormat;
    const uint8_t* p = blob + 16;
    out.w1.assign((const int8_t*)p, (const int8_t*)p + out.feats * out.hid);
    p += out.feats * out.hid;
    out.b1.assign((const int8_t*)p, (const int8_t*)p + out.hid);
    p += out.hid;
    out.w2.assign((const int8_t*)p, (const int8_t*)p + out.hid);
    p += out.hid;
    out.b2 = (int8_t)*p++;
    out.s_w1 = rd_f32(p);
    p += 4;
    out.s_b1 = rd_f32(p);
    p += 4;
    out.s_w2 = rd_f32(p);
    p += 4;
    out.s_b2 = rd_f32(p);
    p += 4;
    memcpy(out.sig, p, 64);
    out.has_signature = true;
    if (!ed25519_verify(out.sig, blob, body_len, model_key)) return ModelStatus::BadSignature;
    return ModelStatus::Ok;
}

static float sigmoidf(float x) {
    if (x > 30) return 1.0f;
    if (x < -30) return 0.0f;
    return 1.0f / (1.0f + expf(-x));
}

float riskInference(const RiskModel& m, const FeatureVector x) {
    // 反量化 → ReLU 隐层 → sigmoid 输出 (与 tools/gen_mlp_model.py 的 infer2 一致)
    float h[64];
    for (uint32_t j = 0; j < m.hid && j < 64; j++) {
        float acc = (float)m.b1[j] * m.s_b1;
        for (uint32_t i = 0; i < m.feats && i < (uint32_t)kFeatureCount; i++)
            acc += x[i] * ((float)m.w1[i * m.hid + j] * m.s_w1);
        h[j] = acc > 0 ? acc : 0;
    }
    float z = (float)m.b2 * m.s_b2;
    for (uint32_t j = 0; j < m.hid; j++) z += h[j] * ((float)m.w2[j] * m.s_w2);
    return sigmoidf(z);
}

float ruleEngineRisk(const FeatureVector x) {
    // 确定性加权 (与训练标签同源的主因子, 去掉组合项; 宁可保守)
    const float w[kFeatureCount] = {0.30f, 0.16f, 0.14f, 0.12f, 0.08f, 0.05f,
                                    0.04f, 0.04f, 0.03f, 0.02f, 0.02f, 0.01f};
    float r = 0;
    for (int i = 0; i < kFeatureCount; i++) r += w[i] * x[i];
    float hard = 0.35f * (x[kFtIntegrityMismatch] > x[kFtAttestationFail]
                              ? x[kFtIntegrityMismatch]
                              : x[kFtAttestationFail]);
    r += hard;
    return r > 1 ? 1 : r;
}

PolicyDecision policyDecide(const DeterministicGates& gates, float model_risk,
                            float rule_risk, const PolicyParams& p) {
    PolicyDecision d;
    // 1. 确定性门 — 不可妥协 (模型/风险分不能翻案)
    if (!gates.license_valid) {
        d.decision = Decision::Deny;
        d.reason = "license invalid";
        return d;
    }
    if (!gates.integrity_ok) {
        d.decision = Decision::Deny;
        d.reason = "integrity check failed";
        return d;
    }
    if (!gates.protocol_fresh) {
        d.decision = Decision::Deny;
        d.reason = "protocol replay/rollback detected";
        return d;
    }
    // 2. 风险信号 (advisory): 模型可信则用模型分, 否则规则引擎兜底
    //    注意: 即使模型分被篡改为 0, 规则引擎在模型不可信时接管;
    //    且信号只能让决策变差 (degrade/deny), 不能让 Deny 变 Allow。
    if (gates.model_authentic) {
        d.risk = model_risk;
        d.used_rule_engine = false;
    } else {
        d.risk = rule_risk;
        d.used_rule_engine = true;
    }
    if (d.risk >= p.block_threshold) {
        d.decision = Decision::Deny;
        d.reason = "risk score above block threshold";
    } else if (d.risk >= p.degrade_threshold) {
        d.decision = Decision::AllowDegraded;
        d.reason = "risk score above degrade threshold";
    } else {
        d.decision = Decision::Allow;
        d.reason = "ok";
    }
    return d;
}

}  // namespace polaris_secure
