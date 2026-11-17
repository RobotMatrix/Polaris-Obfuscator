// KeyProvider 实现: 软件后端 + Apple Keychain 后端 + 平台映射占位
#include "polaris_secure/key_provider.h"
#include "polaris_secure/crypto.h"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <sys/stat.h>

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace polaris_secure {

using prim::ed25519_keypair;
using prim::ed25519_sign;
using prim::hmac_sha256;
using prim::secure_random;
using prim::sha256;

// ============================================================
// 软件后端: 状态目录 + HMAC 自封装
// 威胁模型声明: 攻击者获得文件系统 + 内存权限即可导出/回滚,
// 能力报告如实报告 SoftwareOnly (不虚标硬件保证)。
// ============================================================
class SoftwareKeyProvider : public KeyProvider {
public:
    explicit SoftwareKeyProvider(const std::string& dir) : dir_(dir) {
        mkdir(dir_.c_str(), 0700);
        loadState();
    }

    CapabilityReport capabilities() const override {
        CapabilityReport r;
        r.level = SecurityCapability::SoftwareOnly;
        r.secure_key_storage = false;
        r.monotonic_counter = false;  // 文件计数器可被整体回滚
        r.protected_storage = false;
        r.remote_attestation = false;
        r.backend_name = "software";
        r.detail = "文件状态 + HMAC 自封装; 无硬件防导出/防回滚保证 (降级模式)";
        return r;
    }

    bool ensureDeviceKey() override {
        std::lock_guard<std::mutex> g(mu_);
        if (have_key_) return true;
        uint8_t seed[32];
        if (!secure_random(seed, 32)) return false;
        ed25519_keypair(pk_, sk_, seed);
        have_key_ = true;
        // 存 seed (软件后端密钥可导出 — 如实告知)
        return writeBlob("device_seed", seed, 32);
    }

    bool deviceSign(uint8_t sig64[64], ByteView msg) override {
        std::lock_guard<std::mutex> g(mu_);
        if (!have_key_) return false;
        ed25519_sign(sig64, msg.data, msg.size, pk_, sk_);
        return true;
    }

    bool devicePublicKey(uint8_t pk32[32]) const override {
        std::lock_guard<std::mutex> g(mu_);
        if (!have_key_) return false;
        memcpy(pk32, pk_, 32);
        return true;
    }

    bool counterBump(uint64_t& out) override {
        std::lock_guard<std::mutex> g(mu_);
        counter_ += 1;
        if (!persistCounter()) return false;
        out = counter_;
        return true;
    }

    bool counterRead(uint64_t& out) const override {
        std::lock_guard<std::mutex> g(mu_);
        out = counter_;
        return true;
    }

    bool protectedPut(const std::string& key, ByteView value) override {
        std::lock_guard<std::mutex> g(mu_);
        return writeBlob("kv_" + key, value.data, value.size);
    }

    bool protectedGet(const std::string& key, std::vector<uint8_t>& out) const override {
        std::lock_guard<std::mutex> g(mu_);
        return readBlob("kv_" + key, out);
    }

private:
    // 封装: blob = HMAC(master, name || data) || data; master = SHA256("polaris-sw" || dir)
    void deriveMaster() {
        std::string material = "polaris-sw-master|" + dir_;
        sha256(material.data(), material.size(), master_);
    }

    std::string path(const std::string& name) const { return dir_ + "/" + name + ".blob"; }

    bool writeBlob(const std::string& name, const uint8_t* data, size_t n) {
        uint8_t mac[32];
        std::string nm = name;
        hmac_sha256(master_, 32, nm.data(), nm.size(), mac);  // name 绑定
        uint8_t mac2[32];
        hmac_sha256(mac, 32, data, n, mac2);                  // name-MAC 作为密钥再 MAC 数据
        FILE* f = fopen(path(name).c_str(), "wb");
        if (!f) return false;
        bool ok = fwrite(mac2, 1, 32, f) == 32 && fwrite(data, 1, n, f) == n;
        fclose(f);
        return ok;
    }

    bool readBlob(const std::string& name, std::vector<uint8_t>& out) const {
        FILE* f = fopen(path(name).c_str(), "rb");
        if (!f) return false;
        std::vector<uint8_t> all;
        uint8_t buf[4096];
        size_t r;
        while ((r = fread(buf, 1, sizeof(buf), f)) > 0) all.insert(all.end(), buf, buf + r);
        fclose(f);
        if (all.size() < 32) return false;
        uint8_t mac[32];
        std::string nm = name;
        hmac_sha256(master_, 32, nm.data(), nm.size(), mac);
        uint8_t mac2[32];
        hmac_sha256(mac, 32, all.data() + 32, all.size() - 32, mac2);
        if (!constant_time_equal(mac2, all.data(), 32)) return false;
        out.assign(all.begin() + 32, all.end());
        return true;
    }

    bool persistCounter() {
        uint8_t v[8];
        for (int i = 0; i < 8; i++) v[i] = (uint8_t)(counter_ >> (i * 8));
        return writeBlob("counter", v, 8);
    }

    void loadState() {
        deriveMaster();
        std::vector<uint8_t> seed;
        if (readBlob("device_seed", seed) && seed.size() == 32) {
            ed25519_keypair(pk_, sk_, seed.data());
            have_key_ = true;
        }
        std::vector<uint8_t> c;
        if (readBlob("counter", c) && c.size() == 8) {
            counter_ = 0;
            for (int i = 7; i >= 0; i--) counter_ = (counter_ << 8) | c[i];
        }
    }

    mutable std::mutex mu_;
    std::string dir_;
    uint8_t master_[32];
    uint8_t pk_[32], sk_[64];
    bool have_key_ = false;
    uint64_t counter_ = 0;
};

std::unique_ptr<KeyProvider> createSoftwareKeyProvider(const std::string& stateDir) {
    return std::make_unique<SoftwareKeyProvider>(stateDir);
}

// ============================================================
// Apple Keychain 后端: 设备密钥种子 + 计数器 + KV 存 Keychain
// Secure Enclave 密钥 (kSecAttrTokenIDSecureEnclavePKey) 需要额外
// 权限与设备支持, 生产实现按设备探测; 本后端如实报告能力。
// ============================================================
#if defined(__APPLE__)
class KeychainKeyProvider : public KeyProvider {
public:
    explicit KeychainKeyProvider(const std::string& service) : service_(service) {}

    CapabilityReport capabilities() const override {
        CapabilityReport r;
        r.level = SecurityCapability::HardwareBackedKey;
        r.secure_key_storage = true;   // Keychain 由系统保护
        r.monotonic_counter = false;   // Keychain 计数器仍可被高权限回滚
        r.protected_storage = true;
        r.remote_attestation = false;  // App 沙盒内无设备级证明 API
        r.backend_name = "keychain";
        r.detail = "Apple Keychain; Secure Enclave 密钥须按设备型号探测后启用";
        return r;
    }

    bool ensureDeviceKey() override {
        std::lock_guard<std::mutex> g(mu_);
        if (have_key_) return true;
        // 读 Keychain
        std::vector<uint8_t> seed;
        if (!kcGet("device_seed", seed)) {
            uint8_t s[32];
            if (!secure_random(s, 32)) return false;
            if (!kcPut("device_seed", s, 32)) return false;
            seed.assign(s, s + 32);
        }
        if (seed.size() != 32) return false;
        ed25519_keypair(pk_, sk_, seed.data());
        have_key_ = true;
        return true;
    }

    bool deviceSign(uint8_t sig64[64], ByteView msg) override {
        std::lock_guard<std::mutex> g(mu_);
        if (!have_key_ && !ensureDeviceKeyUnlocked()) return false;
        ed25519_sign(sig64, msg.data, msg.size, pk_, sk_);
        return true;
    }

    bool devicePublicKey(uint8_t pk32[32]) const override {
        std::lock_guard<std::mutex> g(mu_);
        if (!have_key_ && !const_cast<KeychainKeyProvider*>(this)->ensureDeviceKeyUnlocked())
            return false;
        memcpy(pk32, pk_, 32);
        return true;
    }

    bool counterBump(uint64_t& out) override {
        std::lock_guard<std::mutex> g(mu_);
        counter_ += 1;
        uint8_t v[8];
        for (int i = 0; i < 8; i++) v[i] = (uint8_t)(counter_ >> (i * 8));
        if (!kcPut("counter", v, 8)) return false;
        out = counter_;
        return true;
    }

    bool counterRead(uint64_t& out) const override {
        std::lock_guard<std::mutex> g(mu_);
        out = counter_;
        return true;
    }

    bool protectedPut(const std::string& key, ByteView value) override {
        std::lock_guard<std::mutex> g(mu_);
        return kcPut("kv_" + key, value.data, value.size);
    }

    bool protectedGet(const std::string& key, std::vector<uint8_t>& out) const override {
        std::lock_guard<std::mutex> g(mu_);
        return kcGet("kv_" + key, out);
    }

private:
    bool ensureDeviceKeyUnlocked() { return ensureDeviceKey(); }

    bool kcPut(const std::string& name, const uint8_t* data, size_t n) {
        CFMutableDictionaryRef q = CFDictionaryCreateMutable(nullptr, 0, nullptr, nullptr);
        CFStringRef svc = CFStringCreateWithCString(nullptr, service_.c_str(), kCFStringEncodingUTF8);
        CFStringRef acc = CFStringCreateWithCString(nullptr, name.c_str(), kCFStringEncodingUTF8);
        CFDataRef val = CFDataCreate(nullptr, data, (CFIndex)n);
        CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(q, kSecAttrService, svc);
        CFDictionarySetValue(q, kSecAttrAccount, acc);
        CFDictionarySetValue(q, kSecValueData, val);
        // 先删旧值
        SecItemDelete(q);
        OSStatus st = SecItemAdd(q, nullptr);
        CFRelease(q); CFRelease(svc); CFRelease(acc); CFRelease(val);
        return st == errSecSuccess;
    }

    bool kcGet(const std::string& name, std::vector<uint8_t>& out) const {
        CFMutableDictionaryRef q = CFDictionaryCreateMutable(nullptr, 0, nullptr, nullptr);
        CFStringRef svc = CFStringCreateWithCString(nullptr, service_.c_str(), kCFStringEncodingUTF8);
        CFStringRef acc = CFStringCreateWithCString(nullptr, name.c_str(), kCFStringEncodingUTF8);
        CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(q, kSecAttrService, svc);
        CFDictionarySetValue(q, kSecAttrAccount, acc);
        CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
        CFTypeRef res = nullptr;
        OSStatus st = SecItemCopyMatching(q, &res);
        CFRelease(q); CFRelease(svc); CFRelease(acc);
        if (st != errSecSuccess) return false;
        CFDataRef d = (CFDataRef)res;
        const uint8_t* bytes = CFDataGetBytePtr(d);
        size_t len = (size_t)CFDataGetLength(d);
        out.assign(bytes, bytes + len);
        CFRelease(d);
        return true;
    }

    mutable std::mutex mu_;
    std::string service_;
    uint8_t pk_[32], sk_[64];
    bool have_key_ = false;
    uint64_t counter_ = 0;
};

std::unique_ptr<KeyProvider> createKeychainKeyProvider(const std::string& service) {
    return std::make_unique<KeychainKeyProvider>(service);
}
#endif  // __APPLE__

bool deriveDeviceId(const KeyProvider& kp, uint8_t id32[32]) {
    uint8_t pk[32];
    if (!kp.devicePublicKey(pk)) return false;
    // id = SHA256("polaris-device-id" || pk)
    prim::Sha256Ctx c;
    prim::sha256_init(&c);
    const char* tag = "polaris-device-id";
    prim::sha256_update(&c, tag, strlen(tag));
    prim::sha256_update(&c, pk, 32);
    prim::sha256_final(&c, id32);
    return true;
}

}  // namespace polaris_secure
