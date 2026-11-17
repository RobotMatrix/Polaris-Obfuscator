// 授权材料测试: 签发/验证/篡改/设备绑定/时间窗/防回滚
#include "test_harness.h"

using namespace polaris_secure;
using namespace polaris_secure::testutil;

static License makeTemplate(uint64_t now) {
    License t;
    t.serial = 100;
    t.issued_at = now;
    t.not_before = now - 10;
    t.not_after = now + 3600;
    t.features = 0x03;
    return t;
}

int main() {
    printf("== test_license ==\n");
    IssuerKey issuer = testIssuer("issuer-main");
    uint8_t issuer_id[32];
    issuerKeyId(issuer, issuer_id);
    IssuerKey attacker = testIssuer("attacker-key");

    const uint64_t NOW = 1762900000;
    uint8_t dev[32];
    fixedSeed("device-A", dev);
    uint8_t dev_other[32];
    fixedSeed("device-B", dev_other);

    // ---- 正常签发与验证 ----
    {
        License t = makeTemplate(NOW);
        memcpy(t.device_id, dev, 32);
        License lic;
        CHECK(issueLicense(issuer, t, lic), "签发授权");
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.now = NOW;
        ctx.protected_serial_floor = 100;
        ctx.device_counter = 1;
        License lic2;
        CHECK(License::decode(lic.encode().data(), 211, lic2), "编解码往返");
        CHECK(verifyLicense(lic2, ctx) == LicenseStatus::Ok, "正常授权验证通过");
        CHECK(lic2.serial == 100 && lic2.features == 0x03, "字段无损");
    }

    // ---- 攻击模拟 1: 篡改授权字段 (重签成本验证) ----
    {
        License t = makeTemplate(NOW);
        memcpy(t.device_id, dev, 32);
        License lic;
        issueLicense(issuer, t, lic);
        // 攻击者延长有效期
        License tampered = lic;
        tampered.not_after += 86400 * 365;
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.now = NOW;
        ctx.device_counter = 1;
        CHECK(verifyLicense(tampered, ctx) == LicenseStatus::BadSignature,
              "攻击[篡改有效期]: 签名失败");
        // 攻击者改 serial 重放高位
        License tampered2 = lic;
        tampered2.serial = 999;
        CHECK(verifyLicense(tampered2, ctx) == LicenseStatus::BadSignature,
              "攻击[篡改serial]: 签名失败");
    }

    // ---- 攻击模拟 2: 攻击者自签 ----
    {
        License t = makeTemplate(NOW);
        memcpy(t.device_id, dev, 32);
        License forged;
        issueLicense(attacker, t, forged);  // 攻击者密钥
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.now = NOW;
        ctx.device_counter = 1;
        CHECK(verifyLicense(forged, ctx) == LicenseStatus::UnknownKey,
              "攻击[自签授权]: 非受信密钥拒绝");
    }

    // ---- 攻击模拟 3: 换设备重放 ----
    {
        License t = makeTemplate(NOW);
        memcpy(t.device_id, dev, 32);
        License lic;
        issueLicense(issuer, t, lic);
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev_other, 32);
        ctx.now = NOW;
        ctx.device_counter = 1;
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::DeviceMismatch,
              "攻击[跨设备重放]: 设备绑定拒绝");
    }

    // ---- 时间窗 ----
    {
        License t = makeTemplate(NOW);
        License lic;
        issueLicense(issuer, t, lic);
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.device_counter = 1;
        ctx.now = lic.not_before - 1;
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::NotYetValid, "未生效拒绝");
        ctx.now = lic.not_after + 1;
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::Expired, "过期拒绝");
    }

    // ---- 攻击模拟 4: 旧授权回滚 (serial 水位) ----
    {
        // 已接受 serial=200 的授权 (水位 200), 攻击者重放 serial=100
        License old_lic;
        {
            License t = makeTemplate(NOW);
            t.serial = 100;
            t.not_after = NOW + 86400 * 365;  // 长有效期旧授权
            memcpy(t.device_id, dev, 32);
            issueLicense(issuer, t, old_lic);
        }
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.now = NOW;
        ctx.protected_serial_floor = 200;  // 受保护存储水位
        ctx.device_counter = 5;
        CHECK(verifyLicense(old_lic, ctx) == LicenseStatus::RollbackRejected,
              "攻击[旧授权重放]: serial < 受保护水位 → 拒绝");
    }

    // ---- 攻击模拟 5: 设备计数器水位 ----
    {
        License t = makeTemplate(NOW);
        t.min_device_counter = 10;
        memcpy(t.device_id, dev, 32);
        License lic;
        issueLicense(issuer, t, lic);
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.now = NOW;
        ctx.device_counter = 3;  // 计数器被回拨
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::CounterTooLow,
              "攻击[计数器回拨]: 低于授权水位 → 拒绝");
        ctx.device_counter = 10;
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::Ok, "计数器达标 → 通过");
    }

    // ---- 挑战绑定 ----
    {
        License t = makeTemplate(NOW);
        t.bind = LicenseBind::Challenge;
        memset(t.bind_value, 0xAB, 32);
        memcpy(t.device_id, dev, 32);
        License lic;
        issueLicense(issuer, t, lic);
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.now = NOW;
        ctx.device_counter = 1;
        uint8_t good[32];
        memset(good, 0xAB, 32);
        uint8_t bad[32];
        memset(bad, 0xCD, 32);
        ctx.expected_bind = bad;
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::BindMismatch,
              "挑战绑定不匹配 → 拒绝 (防重放到其他会话)");
        ctx.expected_bind = good;
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::Ok, "挑战绑定匹配 → 通过");
    }

    // ---- 密钥轮换: 多受信密钥 ----
    {
        IssuerKey next = testIssuer("issuer-next");
        License t = makeTemplate(NOW);
        memcpy(t.device_id, dev, 32);
        License lic;
        issueLicense(next, t, lic);
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{issuer.pk, issuer.pk + 32}, {next.pk, next.pk + 32}};
        memcpy(ctx.device_id, dev, 32);
        ctx.now = NOW;
        ctx.device_counter = 1;
        CHECK(verifyLicense(lic, ctx) == LicenseStatus::Ok, "密钥轮换: 新密钥签发可信");
    }

    // ---- 损坏格式 ----
    {
        License lic;
        std::vector<uint8_t> bad(211, 0);
        CHECK(!License::decode(bad.data(), 211, lic), "魔数错误拒绝");
        bad[0] = 'P'; bad[1] = 'S'; bad[2] = 'L'; bad[3] = '1';
        bad[4] = 1;  // version = 1
        bad[114] = 0;  // bind = None
        CHECK(License::decode(bad.data(), 211, lic), "格式合法可解析");
        std::vector<uint8_t> shortone(100, 0);
        CHECK(!License::decode(shortone.data(), 100, lic), "长度错误拒绝");
    }

    return test_summary("test_license");
}
