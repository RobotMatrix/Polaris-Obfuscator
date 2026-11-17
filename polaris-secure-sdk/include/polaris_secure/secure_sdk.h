// polaris_secure/secure_sdk.h — 统一门面 (业务层入口)
// 组合五层: 密码服务 / 硬件信任 / 授权协议 / 风险分析 / 策略控制。
// 使用方式见 docs/01 §快速开始; 各层也可独立使用。
#pragma once

#include <memory>
#include <vector>
#include "authorization_server.h"
#include "crypto_service.h"
#include "key_provider.h"
#include "license.h"
#include "protocol.h"
#include "risk_model.h"

namespace polaris_secure {

struct SdkConfig {
    std::string state_dir;                    // 软件后端状态目录
    std::vector<std::vector<uint8_t>> trusted_issuer_keys;  // 32B 公钥列表
    std::vector<uint8_t> model_key;           // 32B 模型签名公钥
    const uint8_t* model_blob = nullptr;      // 已签名模型包
    size_t model_blob_size = 0;
    uint64_t now = 0;                         // 时间注入 (测试); 0 = 使用真实时间
};

class SecureSDK {
public:
    static std::unique_ptr<SecureSDK> create(const SdkConfig& cfg);

    // ---- 能力 (硬件信任层) ----
    CapabilityReport capability() const;
    const KeyProvider& keyProvider() const { return *kp_; }
    KeyProvider& keyProviderMut() { return *kp_; }  // 协议签名等需要非只读访问

    // ---- 密码服务 (密码服务层) ----
    CryptoService& crypto() { return *crypto_; }

    // ---- 设备身份 ----
    bool deviceId(uint8_t id32[32]);

    // ---- 在线授权 (完整挑战-应答; transport 由调用方提供) ----
    struct OnlineResult {
        bool ok = false;
        License license;                 // 验证通过的短期授权
        std::string fail_reason;         // ServerDeny detail 或本地错误
        uint16_t deny_reason = 0;
        PolicyDecision policy;           // 授权后的策略评估
    };
    // risk_features: 当前传感器特征 (随 attest 上报风险分)
    OnlineResult onlineAuthorize(AuthorizationServer& server, uint32_t features,
                                 const FeatureVector risk_features,
                                 const uint8_t* request_content, size_t request_len);

    // ---- 离线授权 ----
    LicenseStatus acceptOfflineLicense(const License& lic);
    LicenseStatus verifyCurrentLicense(uint64_t now);

    // ---- 风险评估 (§8.3 决策链: 信号→模型→策略) ----
    PolicyDecision evaluatePolicy(const DeterministicGates& gates,
                                  const FeatureVector features);

    bool hasValidLicense() const { return license_ok_; }
    const License& currentLicense() const { return current_; }

private:
    SecureSDK() = default;
    std::shared_ptr<KeyProvider> kp_;
    std::unique_ptr<CryptoService> crypto_;
    std::vector<std::vector<uint8_t>> trusted_keys_;
    RiskModel model_;
    bool model_ok_ = false;
    uint8_t device_id_[32] = {0};
    uint64_t serial_floor_ = 0;  // 受保护存储的 serial 水位
    License current_;
    bool has_license_ = false;   // 是否持有授权材料
    bool license_ok_ = false;    // 最近一次接受时是否验证通过
    uint8_t last_bind_[32] = {0};  // 最近一次在线授权的挑战绑定值
    bool has_bind_ = false;
    uint64_t now_override_ = 0;
};

uint64_t unixNow();

}  // namespace polaris_secure
