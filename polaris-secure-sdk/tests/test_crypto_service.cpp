// 密码服务层 + 硬件信任层测试
// 覆盖: 密钥生命周期/策略、AEAD、派生、设备密钥签名、能力报告、受保护状态
#include "test_harness.h"

using namespace polaris_secure;
using namespace polaris_secure::testutil;

int main() {
    printf("== test_crypto_service ==\n");

    std::string dir = tmpdir("cryptosvc");
    std::shared_ptr<KeyProvider> kp = createSoftwareKeyProvider(dir);
    CryptoService cs(kp);

    // ---- 能力探测 (诚实降级声明) ----
    {
        auto cap = kp->capabilities();
        CHECK(cap.level == SecurityCapability::SoftwareOnly, "能力: 软件后端报告 SoftwareOnly");
        CHECK(!cap.monotonic_counter, "能力: 软件后端不虚报单调计数器");
        CHECK(kp->ensureDeviceKey(), "设备密钥生成");
        uint8_t pk[32];
        CHECK(kp->devicePublicKey(pk) && kp->devicePublicKey(pk), "设备公钥稳定 (复用)");
        uint8_t id[32];
        CHECK(deriveDeviceId(*kp, id), "设备 ID 派生");
        uint8_t id2[32];
        deriveDeviceId(*kp, id2);
        CHECK(memcmp(id, id2, 32) == 0, "设备 ID 确定");
        // 重开同一目录 → 密钥持久
        auto kp2 = createSoftwareKeyProvider(dir);
        uint8_t pk2[32];
        CHECK(kp2->ensureDeviceKey() && kp2->devicePublicKey(pk2) && memcmp(pk, pk2, 32) == 0,
              "设备密钥持久化后恢复一致");
    }

    // ---- 密钥策略: 用途强制 ----
    {
        KeyId encKey, signOnlyKey;
        KeyPolicy p;
        p.usage = (uint32_t)KeyUsage::Encrypt;
        CHECK(cs.generateKey(p, encKey) == CryptoError::Ok, "生成加密密钥");
        KeyPolicy sp;
        sp.usage = (uint32_t)KeyUsage::Sign;
        CHECK(cs.generateKey(sp, signOnlyKey) == CryptoError::Ok, "生成签名用途密钥");
        uint8_t mac[32];
        CHECK(cs.hmac(signOnlyKey, ByteView("data", 4), mac) == CryptoError::KeyPolicyDenied,
              "策略拒绝: 签名密钥不能 HMAC");
        std::vector<uint8_t> out;
        CHECK(cs.encrypt(signOnlyKey, ByteView("x", 1), ByteView(), out) ==
                  CryptoError::KeyPolicyDenied,
              "策略拒绝: 签名密钥不能加密");
        KeyId missing;
        memset(&missing, 0xAB, sizeof(missing));
        CHECK(cs.encrypt(missing, ByteView("x", 1), ByteView(), out) ==
                  CryptoError::KeyNotFound,
              "不存在密钥 → KeyNotFound");
    }

    // ---- AEAD 往返 + 派生密钥 ----
    {
        KeyId base;
        KeyPolicy p;
        p.usage = (uint32_t)KeyUsage::Derive | (uint32_t)KeyUsage::Encrypt;
        CHECK(cs.generateKey(p, base) == CryptoError::Ok, "生成可派生根密钥");
        KeyId sess;
        KeyPolicy sp;
        sp.usage = (uint32_t)KeyUsage::Encrypt;
        CHECK(cs.deriveKey(base, ByteView("session|dev1|2026-11-11"), sp, sess) ==
                  CryptoError::Ok,
              "HKDF 派生会话密钥");
        KeyId sess2;
        cs.deriveKey(base, ByteView("session|dev1|2026-11-11"), sp, sess2);
        CHECK(sess == sess2, "同上下文派生结果确定");
        KeyId sess3;
        cs.deriveKey(base, ByteView("session|dev2|2026-11-11"), sp, sess3);
        CHECK(!(sess == sess3), "不同上下文派生不同密钥");
        std::vector<uint8_t> ct, pt;
        std::string plaintext = "attack at dawn — 跨平台保护";
        CHECK(cs.encrypt(sess, ByteView(plaintext), ByteView("hdr", 3), ct) == CryptoError::Ok,
              "AEAD 加密");
        CHECK(cs.decrypt(sess, ByteView(ct), ByteView("hdr", 3), pt) == CryptoError::Ok &&
                  pt == std::vector<uint8_t>(plaintext.begin(), plaintext.end()),
              "AEAD 往返");
        CHECK(cs.decrypt(sess, ByteView(ct), ByteView("HDR", 3), pt) == CryptoError::OpenFailure,
              "AAD 不匹配 → 拒绝");
        ct[10] ^= 0x40;
        CHECK(cs.decrypt(sess, ByteView(ct), ByteView("hdr", 3), pt) == CryptoError::OpenFailure,
              "密文篡改 → 拒绝");
    }

    // ---- 设备密钥签名/验签 (经 CryptoService) ----
    {
        uint8_t sig[64], pk[32];
        CHECK(cs.deviceSign(sig, ByteView("hello", 5)) == CryptoError::Ok, "设备签名");
        cs.devicePublicKey(pk);
        CHECK(CryptoService::verify(pk, ByteView("hello", 5), sig) == CryptoError::Ok,
              "设备签名验证");
        CHECK(CryptoService::verify(pk, ByteView("hellO", 5), sig) == CryptoError::OpenFailure,
              "篡改消息 → 验签失败");
    }

    // ---- 受保护状态 + 单调计数器 ----
    {
        uint64_t c1 = 0, c2 = 0, c3 = 0;
        CHECK(kp->counterBump(c1) && kp->counterBump(c2) && c2 == c1 + 1, "计数器单调递增");
        kp->counterRead(c3);
        CHECK(c3 == c2, "计数器读取一致");
        kp->protectedPut("k1", ByteView("value1", 6));
        std::vector<uint8_t> got;
        CHECK(kp->protectedGet("k1", got) && got == std::vector<uint8_t>({'v','a','l','u','e','1'}),
              "受保护状态读写");
        // 跨实例持久
        auto kp2 = createSoftwareKeyProvider(dir);
        uint64_t c4 = 0;
        kp2->counterRead(c4);
        CHECK(c4 == c3, "计数器持久化");
        std::vector<uint8_t> got2;
        CHECK(kp2->protectedGet("k1", got2) && got2 == got, "受保护状态持久化");
    }

    // ---- 随机 & 哈希 ----
    {
        uint8_t a[16], b[16];
        CHECK(cs.random(a, 16) == CryptoError::Ok && cs.random(b, 16) == CryptoError::Ok &&
                  memcmp(a, b, 16) != 0,
              "随机数不重复");
        uint8_t h[32];
        cs.hash(ByteView("abc", 3), h);
        CHECK(to_hex(h, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "SHA-256 via service");
    }

    std::string cmd = "rm -rf " + dir;
    system(cmd.c_str());
    return test_summary("test_crypto_service");
}
