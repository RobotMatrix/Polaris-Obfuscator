// 风险分析层测试: 模型装载/验签/推理 + 攻击模拟 (模型篡改/替换/Hook 风险分)
// 核心断言 (§8.2): 模型与风险分不能让失败的确定性门通过。
#include "test_harness.h"
#include "polaris_secure/risk_model.h"

using namespace polaris_secure;
using namespace polaris_secure::testutil;

int main() {
    printf("== test_risk_policy ==\n");
    IssuerKey modelKey = testIssuer("model-signing");

    // ---- 模型装载与验签 ----
    RiskModel model;
    {
        std::vector<uint8_t> good = signedModelBlob(modelKey);
        CHECK(loadRiskModel(good.data(), good.size(), modelKey.pk, model) == ModelStatus::Ok,
              "已签名模型装载通过");
        // 篡改权重
        std::vector<uint8_t> bad = good;
        bad[20] ^= 0x01;
        RiskModel m2;
        CHECK(loadRiskModel(bad.data(), bad.size(), modelKey.pk, m2) == ModelStatus::BadSignature,
              "攻击[篡改模型权重]: 验签失败");
        // 攻击者重签
        IssuerKey attacker = testIssuer("model-attacker");
        std::vector<uint8_t> body(kRiskModelBlob, kRiskModelBlob + kRiskModelBlobSize);
        uint8_t sig[64];
        prim::ed25519_sign(sig, body.data(), body.size(), attacker.pk, attacker.sk);
        std::vector<uint8_t> forged = body;
        forged.insert(forged.end(), sig, sig + 64);
        RiskModel m3;
        CHECK(loadRiskModel(forged.data(), forged.size(), modelKey.pk, m3) ==
                  ModelStatus::BadSignature,
              "攻击[替换模型+重签]: 非受信密钥拒绝");
        // 截断
        CHECK(loadRiskModel(good.data(), good.size() - 1, modelKey.pk, m3) ==
                  ModelStatus::BadFormat,
              "截断模型拒绝");
    }

    // ---- 推理行为 ----
    {
        FeatureVector clean = {};
        FeatureVector all = {};
        for (int i = 0; i < kFeatureCount; i++) all[i] = 1.0f;
        FeatureVector integ = {};
        integ[kFtIntegrityMismatch] = 1.0f;
        FeatureVector dbg = {};
        dbg[kFtDebugger] = 1.0f;
        FeatureVector combo = {};
        combo[kFtHook] = 0.6f;
        combo[kFtInjection] = 0.6f;
        combo[kFtRootJailbreak] = 0.5f;

        float r_clean = riskInference(model, clean);
        float r_all = riskInference(model, all);
        float r_integ = riskInference(model, integ);
        float r_dbg = riskInference(model, dbg);
        float r_combo = riskInference(model, combo);
        CHECK(r_clean < 0.15f, "推理: 干净环境低风险");
        CHECK(r_all > 0.90f, "推理: 全信号高风险");
        CHECK(r_integ > 0.45f, "推理: 完整性失败显著抬升");
        CHECK(r_dbg > 0.05f && r_dbg < 0.5f, "推理: 单一调试器信号中等");
        CHECK(r_combo > r_clean + 0.05f, "推理: 组合信号高于干净");
        // 规则引擎方向一致
        CHECK(ruleEngineRisk(all) == 1.0f, "规则引擎: 全信号饱和 1.0");
        CHECK(ruleEngineRisk(clean) == 0.0f, "规则引擎: 干净 0.0");
    }

    // ---- 攻击模拟 13: Hook 篡改风险分输出 (强制返回 0) ----
    // 场景: 攻击者 Hook riskInference 返回 0, 但完整性/授权已失败
    {
        DeterministicGates gates;
        gates.license_valid = true;       // 授权本身有效
        gates.integrity_ok = false;       // 完整性检查失败
        gates.protocol_fresh = true;
        gates.model_authentic = true;
        float hooked_risk = 0.0f;  // Hook 后的风险分 (被压平)
        FeatureVector zero = {};
        PolicyDecision d = policyDecide(gates, hooked_risk, ruleEngineRisk(zero));
        CHECK(d.decision == Decision::Deny, "攻击[Hook风险分]: 确定性门失败仍 Deny");
        CHECK(d.reason.find("integrity") != std::string::npos, "拒绝原因指向完整性");
        // 授权门失败同样 Deny (逐门独立)
        gates.integrity_ok = true;
        gates.license_valid = false;
        d = policyDecide(gates, 0.0f, 0.0f);
        CHECK(d.decision == Decision::Deny && d.reason.find("license") != std::string::npos,
              "攻击[Hook风险分]: 授权门失败亦 Deny");
    }

    // ---- 攻击模拟 14: 模型被替换 (model_authentic=false) + 信号被压平 ----
    {
        DeterministicGates gates;
        gates.license_valid = true;
        gates.integrity_ok = true;
        gates.protocol_fresh = true;
        gates.model_authentic = false;  // 模型验签失败 → 规则引擎接管
        FeatureVector hostile = {};
        for (int i = 0; i < kFeatureCount; i++) hostile[i] = 1.0f;  // 全信号高危
        float hooked_model_risk = 0.0f;              // 模型输出被压平
        float rule = ruleEngineRisk(hostile);        // 饱和 1.0 → 规则引擎兜底
        PolicyDecision d = policyDecide(gates, hooked_model_risk, rule);
        CHECK(d.used_rule_engine, "攻击[模型替换]: 降级规则引擎");
        CHECK(d.decision == Decision::Deny, "攻击[模型替换]: 规则引擎兜底拒绝");
        CHECK(d.risk > 0.5f, "兜底风险分来自规则引擎 (非被压平的模型分)");
        // 单一硬性信号 (仅完整性失败) 在规则引擎下 → 至少降级
        FeatureVector integ_only = {};
        integ_only[kFtIntegrityMismatch] = 1.0f;
        d = policyDecide(gates, 0.0f, ruleEngineRisk(integ_only));
        CHECK(d.decision == Decision::AllowDegraded || d.decision == Decision::Deny,
              "攻击[模型替换]: 硬性信号规则兜底至少降级");
    }

    // ---- 正常梯度: Allow → AllowDegraded → Deny ----
    {
        DeterministicGates ok;
        ok.license_valid = ok.integrity_ok = ok.protocol_fresh = true;
        ok.model_authentic = true;
        CHECK(policyDecide(ok, 0.1f, 0.0f).decision == Decision::Allow, "策略: 低风险 Allow");
        CHECK(policyDecide(ok, 0.6f, 0.0f).decision == Decision::AllowDegraded,
              "策略: 中风险 AllowDegraded");
        CHECK(policyDecide(ok, 0.9f, 0.0f).decision == Decision::Deny, "策略: 高风险 Deny");
        // 边界
        CHECK(policyDecide(ok, 0.5f, 0.0f).decision == Decision::AllowDegraded,
              "策略: 阈值边界 0.5 降级");
        CHECK(policyDecide(ok, 0.8f, 0.0f).decision == Decision::Deny,
              "策略: 阈值边界 0.8 拒绝");
    }

    // ---- 攻击模拟 15: 单门失败逐一验证 (不可绕过) ----
    {
        DeterministicGates g;
        g.integrity_ok = g.protocol_fresh = g.model_authentic = true;
        g.license_valid = false;
        CHECK(policyDecide(g, 0.0f, 0.0f).decision == Decision::Deny, "门[license] 失败即 Deny");
        g.license_valid = true;
        g.integrity_ok = false;
        CHECK(policyDecide(g, 0.0f, 0.0f).decision == Decision::Deny, "门[integrity] 失败即 Deny");
        g.integrity_ok = true;
        g.protocol_fresh = false;
        CHECK(policyDecide(g, 0.0f, 0.0f).decision == Decision::Deny, "门[replay] 失败即 Deny");
        g.protocol_fresh = true;
        CHECK(policyDecide(g, 0.0f, 0.0f).decision == Decision::Allow, "全门通过 + 零风险 Allow");
    }

    return test_summary("test_risk_policy");
}
