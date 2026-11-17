// 在线授权协议测试: 完整流程 / 重放 / 撤销 / 伪造 / 时效
#include "test_harness.h"
#include "polaris_secure/authorization_server.h"
#include "polaris_secure/secure_sdk.h"

using namespace polaris_secure;
using namespace polaris_secure::testutil;

int main() {
    printf("== test_protocol_online ==\n");
    IssuerKey issuer = testIssuer("issuer-main");
    const uint64_t T0 = 1762900000;
    AuthorizationServer server(issuer, T0);
    server.setGrantTtlSeconds(300);

    std::string dir = tmpdir("proto");
    SdkConfig cfg;
    cfg.state_dir = dir;
    cfg.trusted_issuer_keys = {{issuer.pk, issuer.pk + 32}};
    cfg.now = T0;
    auto sdk = SecureSDK::create(cfg);
    CHECK(sdk != nullptr, "SDK 初始化");

    // 注册设备到服务器 (真实部署经带外注册/证明)
    uint8_t dev[32], pkdev[32];
    sdk->deviceId(dev);
    sdk->keyProvider().devicePublicKey(pkdev);
    server.registerDevice(dev, pkdev);

    FeatureVector clean = {};
    FeatureVector hostile = {};
    hostile[kFtIntegrityMismatch] = 1.0f;
    hostile[kFtDebugger] = 1.0f;
    hostile[kFtHook] = 1.0f;
    hostile[kFtInjection] = 1.0f;

    // ---- 正常在线授权全流程 ----
    {
        auto r = sdk->onlineAuthorize(server, 0x03, clean, nullptr, 0);
        CHECK(r.ok, "在线授权成功");
        CHECK(r.license.not_after - r.license.issued_at == 300, "短期 TTL 授权");
        CHECK(r.policy.decision == Decision::Allow, "干净环境策略 Allow");
        CHECK(sdk->verifyCurrentLicense(T0) == LicenseStatus::Ok, "授权后立即可复核");
    }

    // ---- 攻击模拟 6: 伪造设备证明 (无设备私钥) ----
    {
        // 攻击者用自己的密钥签名 attest, 冒充受害设备
        auto attacker_kp = createSoftwareKeyProvider(tmpdir("attacker"));
        attacker_kp->ensureDeviceKey();
        ClientHello hello;
        memcpy(hello.device_id, dev, 32);  // 冒充
        prim::secure_random(hello.client_nonce, 32);
        hello.features = 0x03;
        ServerChallenge ch = server.processHello(hello);
        ClientAttest att;
        memcpy(att.device_id, dev, 32);
        memcpy(att.client_nonce, hello.client_nonce, 32);
        memcpy(att.server_nonce, ch.server_nonce, 32);
        memset(att.request_hash, 0, 32);
        att.sign(*attacker_kp);  // 攻击者密钥签名
        auto gr = server.processAttest(att);
        CHECK(!gr.granted && gr.deny.reason == (uint16_t)DenyReason::AttestBadSignature,
              "攻击[伪造证明]: 设备签名不匹配 → 拒绝");
    }

    // ---- 攻击模拟 7: client_nonce 重放 ----
    {
        ClientHello hello;
        memcpy(hello.device_id, dev, 32);
        prim::secure_random(hello.client_nonce, 32);
        hello.features = 0x03;
        ServerChallenge ch = server.processHello(hello);
        ClientAttest att;
        memcpy(att.device_id, dev, 32);
        memcpy(att.client_nonce, hello.client_nonce, 32);
        memcpy(att.server_nonce, ch.server_nonce, 32);
        memset(att.request_hash, 0, 32);
        att.sign(sdk->keyProviderMut());
        auto first = server.processAttest(att);
        CHECK(first.granted, "首次 attest 成功");
        // 重放同一 client_nonce (需要新挑战, 但 nonce 已用)
        ServerChallenge ch2 = server.processHello(hello);
        ClientAttest att2 = att;
        memcpy(att2.server_nonce, ch2.server_nonce, 32);
        att2.sign((KeyProvider&)sdk->keyProvider());
        auto replay = server.processAttest(att2);
        CHECK(!replay.granted && replay.deny.reason == (uint16_t)DenyReason::ReplayDetected,
              "攻击[nonce重放]: 服务器拒绝");
    }

    // ---- 攻击模拟 8: 挑战重用 (同 challenge 两次 attest) ----
    {
        ClientHello hello;
        memcpy(hello.device_id, dev, 32);
        prim::secure_random(hello.client_nonce, 32);
        hello.features = 0x03;
        ServerChallenge ch = server.processHello(hello);
        ClientAttest att;
        memcpy(att.device_id, dev, 32);
        memcpy(att.client_nonce, hello.client_nonce, 32);
        memcpy(att.server_nonce, ch.server_nonce, 32);
        memset(att.request_hash, 0, 32);
        att.sign(sdk->keyProviderMut());
        auto a1 = server.processAttest(att);
        auto a2 = server.processAttest(att);  // 同挑战同 nonce 重放
        CHECK(a1.granted && !a2.granted, "攻击[挑战重用]: 第二次被拒 (nonce/挑战消费)");
    }

    // ---- 攻击模拟 9: 未注册设备 ----
    {
        uint8_t ghost[32];
        fixedSeed("ghost-device", ghost);
        ClientHello hello;
        memcpy(hello.device_id, ghost, 32);
        prim::secure_random(hello.client_nonce, 32);
        ServerChallenge ch = server.processHello(hello);
        ClientAttest att;
        memcpy(att.device_id, ghost, 32);
        memcpy(att.client_nonce, hello.client_nonce, 32);
        memcpy(att.server_nonce, ch.server_nonce, 32);
        memset(att.request_hash, 0, 32);
        att.sign(sdk->keyProviderMut());  // 有签名但设备未注册
        auto gr = server.processAttest(att);
        CHECK(!gr.granted && gr.deny.reason == (uint16_t)DenyReason::UnknownDevice,
              "攻击[未注册设备]: 拒绝");
    }

    // ---- 攻击模拟 10: 撤销后请求 ----
    {
        server.revokeDevice(dev);
        auto r = sdk->onlineAuthorize(server, 0x03, clean, nullptr, 0);
        CHECK(!r.ok && r.deny_reason == (uint16_t)DenyReason::DeviceRevoked,
              "攻击[撤销后授权]: 服务器拒绝");
        server.registerDevice(dev, pkdev);  // 恢复
    }

    // ---- 攻击模拟 11: 高风险设备 (服务端复核) ----
    {
        auto r = sdk->onlineAuthorize(server, 0x03, hostile, nullptr, 0);
        bool denied_by_risk = !r.ok && r.deny_reason == (uint16_t)DenyReason::RiskDenied;
        bool degraded = r.ok && r.policy.decision == Decision::Deny;
        CHECK(denied_by_risk || degraded, "攻击[高风险设备]: 服务端风险策略拒绝");
    }

    // ---- 攻击模拟 12: 过期挑战 ----
    {
        ClientHello hello;
        memcpy(hello.device_id, dev, 32);
        prim::secure_random(hello.client_nonce, 32);
        hello.features = 0x03;
        ServerChallenge ch = server.processHello(hello);
        server.advanceTime(T0 + 1000);  // 挑战已过期 (>120s)
        ClientAttest att;
        memcpy(att.device_id, dev, 32);
        memcpy(att.client_nonce, hello.client_nonce, 32);
        memcpy(att.server_nonce, ch.server_nonce, 32);
        memset(att.request_hash, 0, 32);
        att.sign(sdk->keyProviderMut());
        auto gr = server.processAttest(att);
        CHECK(!gr.granted && gr.deny.reason == (uint16_t)DenyReason::ChallengeInvalid,
              "攻击[过期挑战]: 拒绝");
    }

    // ---- 客户端独立复核: 伪造 grant (中间人替换) ----
    {
        // 前一场景推进了服务器时钟, 用新服务器实例避免时间偏差干扰
        AuthorizationServer fresh(issuer, T0);
        fresh.registerDevice(dev, pkdev);
        auto r = sdk->onlineAuthorize(fresh, 0x03, clean, nullptr, 0);
        CHECK(r.ok, "正常授权");
        License lic = sdk->currentLicense();
        lic.not_after += 3600;  // 中间人延长
        // 直接用 acceptOfflineLicense 路径复核
        LicenseStatus st = sdk->acceptOfflineLicense(lic);
        CHECK(st == LicenseStatus::BadSignature, "攻击[中间人篡改grant]: 本地复核拒绝");
    }

    std::string cmd = "rm -rf " + dir + " " + tmpdir("attacker");
    system(cmd.c_str());
    return test_summary("test_protocol_online");
}
