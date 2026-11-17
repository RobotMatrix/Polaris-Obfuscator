// SecureSDK 门面实现
#include "polaris_secure/secure_sdk.h"

#include <ctime>
#include "polaris_secure/crypto.h"

namespace polaris_secure {

uint64_t unixNow() {
    return (uint64_t)time(nullptr);
}

std::unique_ptr<SecureSDK> SecureSDK::create(const SdkConfig& cfg) {
    std::unique_ptr<SecureSDK> sdk(new SecureSDK());
    sdk->kp_ = createSoftwareKeyProvider(cfg.state_dir);
    sdk->crypto_ = std::make_unique<CryptoService>(sdk->kp_);
    sdk->trusted_keys_ = cfg.trusted_issuer_keys;
    sdk->now_override_ = cfg.now;

    if (!sdk->kp_->ensureDeviceKey()) return nullptr;
    if (!deriveDeviceId(*sdk->kp_, sdk->device_id_)) return nullptr;

    // 恢复受保护 serial 水位
    std::vector<uint8_t> floor;
    if (sdk->kp_->protectedGet("serial_floor", floor) && floor.size() == 8) {
        sdk->serial_floor_ = 0;
        for (int i = 7; i >= 0; i--) sdk->serial_floor_ = (sdk->serial_floor_ << 8) | floor[i];
    }

    // 模型装载 + 验签 (失败 → 规则引擎降级, 不影响确定性策略)
    if (cfg.model_key.size() == 32 && cfg.model_blob && cfg.model_blob_size > 0) {
        ModelStatus st =
            loadRiskModel(cfg.model_blob, cfg.model_blob_size, cfg.model_key.data(), sdk->model_);
        sdk->model_ok_ = (st == ModelStatus::Ok);
    }
    return sdk;
}

CapabilityReport SecureSDK::capability() const { return kp_->capabilities(); }

bool SecureSDK::deviceId(uint8_t id32[32]) {
    memcpy(id32, device_id_, 32);
    return true;
}

SecureSDK::OnlineResult SecureSDK::onlineAuthorize(AuthorizationServer& server,
                                                   uint32_t features,
                                                   const FeatureVector risk_features,
                                                   const uint8_t* request_content,
                                                   size_t request_len) {
    OnlineResult r;
    uint64_t now = now_override_ ? now_override_ : unixNow();

    // 1) hello
    ClientHello hello;
    memcpy(hello.device_id, device_id_, 32);
    if (!polaris_secure::prim::secure_random(hello.client_nonce, 32)) {
        r.fail_reason = "rng";
        return r;
    }
    hello.features = features;
    hello.capability = (uint32_t)capability().level;
    ServerChallenge ch = server.processHello(hello);

    // 2) attest (设备密钥签名; 请求绑定哈希)
    ClientAttest att;
    memcpy(att.device_id, device_id_, 32);
    memcpy(att.client_nonce, hello.client_nonce, 32);
    memcpy(att.server_nonce, ch.server_nonce, 32);
    if (request_content) {
        requestHash(ByteView(request_content, request_len), att.request_hash);
    } else {
        const uint8_t login[] = {'l', 'o', 'g', 'i', 'n'};
        requestHash(ByteView(login, 4), att.request_hash);
    }
    if (!att.sign(*kp_)) {
        r.fail_reason = "device sign";
        return r;
    }

    // 风险分随 attest 上报 (不可信信号, 服务器仅作策略输入)
    float risk = model_ok_ ? riskInference(model_, risk_features) : ruleEngineRisk(risk_features);

    // 3) grant / deny
    auto gr = server.processAttest(att, (double)risk);
    if (!gr.granted) {
        r.deny_reason = gr.deny.reason;
        r.fail_reason = gr.deny.detail;
        return r;
    }

    // 4) 本地复核授权 (不盲信传输结果 — 独立验证签名/绑定/设备/时间)
    uint8_t expected[32];
    challengeHash(att.client_nonce, ch.server_nonce, expected);
    LicenseVerifyCtx ctx;
    ctx.trusted_keys = trusted_keys_;
    memcpy(ctx.device_id, device_id_, 32);
    ctx.now = now;
    ctx.protected_serial_floor = serial_floor_;
    uint64_t ctr = 0;
    kp_->counterRead(ctr);
    ctx.device_counter = ctr;
    ctx.expected_bind = expected;
    LicenseStatus st = verifyLicense(gr.grant.license, ctx);
    if (st != LicenseStatus::Ok) {
        r.fail_reason = std::string("local verify: ") + licenseStatusName(st);
        return r;
    }

    // 5) 接受: 推进受保护水位 + 设备计数器 (防回滚)
    serial_floor_ = gr.grant.license.serial;
    current_ = gr.grant.license;
    memcpy(last_bind_, expected, 32);  // 保存挑战绑定值供后续复核
    has_bind_ = true;
    has_license_ = true;
    license_ok_ = true;
    uint8_t fb[8];
    for (int i = 0; i < 8; i++) fb[i] = (uint8_t)(serial_floor_ >> (i * 8));
    kp_->protectedPut("serial_floor", ByteView(fb, 8));
    uint64_t bumped = 0;
    kp_->counterBump(bumped);

    r.ok = true;
    r.license = gr.grant.license;
    // 6) 策略评估 (授权与策略分离: 授权有效 ≠ 业务允许)
    DeterministicGates gates;
    gates.license_valid = true;
    gates.integrity_ok = true;
    gates.protocol_fresh = true;
    gates.model_authentic = model_ok_;
    r.policy = policyDecide(gates, risk, ruleEngineRisk(risk_features));
    return r;
}

LicenseStatus SecureSDK::acceptOfflineLicense(const License& lic) {
    uint64_t now = now_override_ ? now_override_ : unixNow();
    LicenseVerifyCtx ctx;
    ctx.trusted_keys = trusted_keys_;
    memcpy(ctx.device_id, device_id_, 32);
    ctx.now = now;
    ctx.protected_serial_floor = serial_floor_;
    uint64_t ctr = 0;
    kp_->counterRead(ctr);
    ctx.device_counter = ctr;
    LicenseStatus st = verifyLicense(lic, ctx);
    if (st != LicenseStatus::Ok) return st;
    // 接受: 水位推进 + 计数器递增
    if (lic.serial > serial_floor_) {
        serial_floor_ = lic.serial;
        uint8_t fb[8];
        for (int i = 0; i < 8; i++) fb[i] = (uint8_t)(serial_floor_ >> (i * 8));
        kp_->protectedPut("serial_floor", ByteView(fb, 8));
    }
    uint64_t bumped = 0;
    kp_->counterBump(bumped);
    current_ = lic;
    has_license_ = true;
    license_ok_ = true;
    return LicenseStatus::Ok;
}

LicenseStatus SecureSDK::verifyCurrentLicense(uint64_t now) {
    // 纯函数式复核: 不改变内部授权状态 (license_ok_ 仅在接受新授权时置位)
    if (!has_license_) return LicenseStatus::BadFormat;
    LicenseVerifyCtx ctx;
    ctx.trusted_keys = trusted_keys_;
    memcpy(ctx.device_id, device_id_, 32);
    // 显式传入的 now 优先 (测试注入); 其次配置覆盖; 最后真实时钟
    ctx.now = now ? now : (now_override_ ? now_override_ : unixNow());
    ctx.protected_serial_floor = serial_floor_;
    uint64_t ctr = 0;
    kp_->counterRead(ctr);
    ctx.device_counter = ctr;
    if (current_.bind != LicenseBind::None) ctx.expected_bind = has_bind_ ? last_bind_ : nullptr;
    return verifyLicense(current_, ctx);
}

PolicyDecision SecureSDK::evaluatePolicy(const DeterministicGates& gates,
                                         const FeatureVector features) {
    float model_risk = model_ok_ ? riskInference(model_, features) : 0.0f;
    float rule_risk = ruleEngineRisk(features);
    return policyDecide(gates, model_risk, rule_risk);
}

}  // namespace polaris_secure
