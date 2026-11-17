// 全链路集成测试: 在线授权 → 业务加密 → 离线续期 → 撤销 → 降级
// 模拟一台设备从激活到离线运行再到授权更新的完整生命周期。
#include "test_harness.h"
#include "polaris_secure/authorization_server.h"
#include "polaris_secure/secure_sdk.h"

using namespace polaris_secure;
using namespace polaris_secure::testutil;

int main() {
    printf("== test_integration ==\n");
    IssuerKey issuer = testIssuer("issuer-main");
    IssuerKey modelKey = testIssuer("model-signing");
    const uint64_t T0 = 1762900000;

    std::string dir = tmpdir("integ");
    SdkConfig cfg;
    cfg.state_dir = dir;
    cfg.trusted_issuer_keys = {{issuer.pk, issuer.pk + 32}};
    cfg.model_key = {modelKey.pk, modelKey.pk + 32};
    cfg.model_blob = kRiskModelBlob;
    cfg.model_blob_size = kRiskModelBlobSize;
    cfg.now = T0;
    auto sdk = SecureSDK::create(cfg);
    CHECK(sdk != nullptr, "SDK 初始化 (含签名模型)");

    uint8_t dev[32], pk[32];
    sdk->deviceId(dev);
    sdk->keyProvider().devicePublicKey(pk);

    AuthorizationServer server(issuer, T0);
    server.registerDevice(dev, pk);

    FeatureVector clean = {};

    // ---- 场景 1: 在线授权 → 加密业务数据 ----
    {
        auto r = sdk->onlineAuthorize(server, 0x03, clean, nullptr, 0);
        CHECK(r.ok && r.policy.decision == Decision::Allow, "场景1: 在线授权 + 策略通过");
        CHECK(sdk->hasValidLicense(), "授权状态有效");

        // 业务侧: 用密码服务加密数据 (密钥由根密钥派生)
        auto& cs = sdk->crypto();
        KeyId root;
        KeyPolicy rp;
        rp.usage = (uint32_t)KeyUsage::Derive | (uint32_t)KeyUsage::Encrypt;
        uint8_t rootseed[32];
        fixedSeed("biz-root", rootseed);
        CHECK(cs.importSecret(ByteView(rootseed, 32), rp, root) == CryptoError::Ok,
              "导入业务根密钥");
        KeyId dataKey;
        KeyPolicy dp;
        dp.usage = (uint32_t)KeyUsage::Encrypt;
        CHECK(cs.deriveKey(root, ByteView("data-key|v1"), dp, dataKey) == CryptoError::Ok,
              "派生数据密钥");
        std::vector<uint8_t> ct, pt;
        std::string secret_payload = "消费者数据 1762900000";
        CHECK(cs.encrypt(dataKey, ByteView(secret_payload), ByteView("rec-42", 6), ct) ==
                  CryptoError::Ok,
              "业务数据加密");
        CHECK(cs.decrypt(dataKey, ByteView(ct), ByteView("rec-42", 6), pt) == CryptoError::Ok,
              "业务数据解密");
    }

    // ---- 场景 2: 短期在线授权过期 → 拒绝业务 ----
    {
        auto r = sdk->onlineAuthorize(server, 0x03, clean, nullptr, 0);
        CHECK(r.ok, "场景2: 重新授权");
        CHECK(sdk->verifyCurrentLicense(T0 + 301) == LicenseStatus::Expired,
              "TTL 过期后复核失败 (需重新授权)");
        CHECK(sdk->verifyCurrentLicense(T0 + 100) == LicenseStatus::Ok,
              "TTL 内复核通过");
    }

    // ---- 场景 3: 离线授权 (长有效期) ----
    {
        License t;
        t.serial = 500;           // 高于在线授权 serial
        t.issued_at = T0;
        t.not_before = T0 - 10;
        t.not_after = T0 + 86400 * 30;  // 30 天离线授权
        t.features = 0x01;
        t.min_device_counter = 1;
        memcpy(t.device_id, dev, 32);
        License off;
        issueLicense(issuer, t, off);
        CHECK(sdk->acceptOfflineLicense(off) == LicenseStatus::Ok, "场景3: 接受离线授权");
        CHECK(sdk->verifyCurrentLicense(T0 + 3600) == LicenseStatus::Ok, "离线期内有效");
        // 离线期风险策略仍独立运行
        DeterministicGates g;
        g.license_valid = true;
        g.integrity_ok = true;
        g.protocol_fresh = true;
        g.model_authentic = true;
        auto d = sdk->evaluatePolicy(g, clean);
        CHECK(d.decision == Decision::Allow, "离线模式策略评估独立运行");
    }

    // ---- 场景 4: 离线授权回滚 (水位防御) ----
    {
        // 攻击者重放旧的在线授权 (serial 更低)
        License t;
        t.serial = 400;
        t.issued_at = T0;
        t.not_before = T0 - 10;
        t.not_after = T0 + 86400 * 365;
        memcpy(t.device_id, dev, 32);
        License old_lic;
        issueLicense(issuer, t, old_lic);
        CHECK(sdk->acceptOfflineLicense(old_lic) == LicenseStatus::RollbackRejected,
              "场景4: 旧 serial 授权被受保护水位拒绝");
    }

    // ---- 场景 5: SDK 状态持久化 (进程重启) ----
    {
        // 重新打开同一状态目录 — serial 水位与设备密钥保持
        SdkConfig cfg2 = cfg;
        auto sdk2 = SecureSDK::create(cfg2);
        CHECK(sdk2 != nullptr, "场景5: SDK 重启初始化");
        uint8_t dev2[32], pk2[32];
        sdk2->deviceId(dev2);
        sdk2->keyProvider().devicePublicKey(pk2);
        CHECK(memcmp(dev, dev2, 32) == 0 && memcmp(pk, pk2, 32) == 0,
              "重启后设备身份不变");
        // 低 serial 授权仍被拒 (水位已持久化)
        License t;
        t.serial = 300;
        t.issued_at = T0;
        t.not_before = T0 - 10;
        t.not_after = T0 + 86400 * 365;
        memcpy(t.device_id, dev, 32);
        License old_lic;
        issueLicense(issuer, t, old_lic);
        CHECK(sdk2->acceptOfflineLicense(old_lic) == LicenseStatus::RollbackRejected,
              "重启后回滚防御仍生效");
    }

    // ---- 场景 6: 能力降级声明 (SoftwareOnly 如实上报) ----
    {
        auto cap = sdk->capability();
        CHECK(cap.level == SecurityCapability::SoftwareOnly &&
                  cap.backend_name == "software",
              "场景6: 软件后端如实上报能力等级");
    }

    // ---- 场景 7: 撤销 → 在线请求被拒; 离线授权到期后无法续期 ----
    {
        server.revokeDevice(dev);
        auto r = sdk->onlineAuthorize(server, 0x03, clean, nullptr, 0);
        CHECK(!r.ok && r.deny_reason == (uint16_t)DenyReason::DeviceRevoked,
              "场景7: 撤销设备在线请求被拒");
    }

    // ---- 场景 8: 模型不可用时策略降级 (规则引擎) ----
    {
        // 用坏模型创建 SDK
        SdkConfig cfg3 = cfg;
        cfg3.state_dir = tmpdir("integ-badmodel");
        std::vector<uint8_t> badModel(kRiskModelBlob, kRiskModelBlob + kRiskModelBlobSize);
        badModel[25] ^= 0xFF;  // 篡改
        cfg3.model_blob = badModel.data();
        auto sdk3 = SecureSDK::create(cfg3);
        CHECK(sdk3 != nullptr, "场景8: 坏模型不阻止 SDK 启动");
        DeterministicGates g;
        g.license_valid = g.integrity_ok = g.protocol_fresh = true;
        g.model_authentic = false;
        FeatureVector high = {};
        for (int i = 0; i < kFeatureCount; i++) high[i] = 1.0f;  // 全信号高危
        auto d = sdk3->evaluatePolicy(g, high);
        CHECK(d.decision == Decision::Deny && d.used_rule_engine,
              "场景8: 模型不可用 → 规则引擎兜底仍拒绝高风险");
    }

    std::string cmd = "rm -rf " + dir + " " + tmpdir("integ-badmodel");
    system(cmd.c_str());
    return test_summary("test_integration");
}
