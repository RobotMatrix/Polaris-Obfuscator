// CryptoService 实现 — 密码服务层
// 分层密钥 (§7.3): 本层管理会话密钥/派生密钥; 服务端根密钥永不入客户端;
// 设备密钥经 KeyProvider (硬件层); 代码加密密钥按版本派生。
#include "polaris_secure/crypto_service.h"
#include "polaris_secure/crypto.h"

#include <cstring>
#include <map>
#include <mutex>

namespace polaris_secure {

using prim::aead_open;
using prim::aead_seal;
using prim::ed25519_verify;
using prim::hkdf_sha256;
using prim::hmac_sha256;
using prim::secure_random;
using prim::sha256;

struct CryptoService::Impl {
    std::shared_ptr<KeyProvider> provider;
    struct Entry {
        SecureBuffer material;  // 32B 密钥材料
        KeyPolicy policy;
        uint64_t created_at = 0;
    };
    std::map<KeyId, Entry> keys;
    std::mutex mu;

    KeyId idFor(const SecureBuffer& m) const {
        KeyId id;
        sha256(m.data(), m.size(), id.id);
        return id;
    }
};

CryptoService::CryptoService(std::shared_ptr<KeyProvider> provider)
    : impl_(new Impl) {
    impl_->provider = std::move(provider);
}
CryptoService::~CryptoService() = default;

CryptoError CryptoService::random(uint8_t* out, size_t n) const {
    return secure_random(out, n) ? CryptoError::Ok : CryptoError::ProviderFailure;
}

CryptoError CryptoService::hash(ByteView data, uint8_t out32[32]) const {
    sha256(data.data, data.size, out32);
    return CryptoError::Ok;
}

CryptoError CryptoService::generateKey(const KeyPolicy& policy, KeyId& out) {
    std::lock_guard<std::mutex> g(impl_->mu);
    uint8_t material[32];
    if (!secure_random(material, 32)) return CryptoError::ProviderFailure;
    SecureBuffer m(material, 32);
    memset(material, 0, sizeof(material));
    out = impl_->idFor(m);
    Impl::Entry e;
    e.material = std::move(m);
    e.policy = policy;
    e.created_at = 12345;  // 参考实现: 无时钟依赖, 仅为演示字段
    impl_->keys[out] = std::move(e);
    return CryptoError::Ok;
}

CryptoError CryptoService::importSecret(ByteView secret32, const KeyPolicy& policy,
                                        KeyId& out) {
    std::lock_guard<std::mutex> g(impl_->mu);
    if (secret32.size != 32) return CryptoError::InvalidParam;
    SecureBuffer m(secret32.data, secret32.size);
    out = impl_->idFor(m);
    Impl::Entry e;
    e.material = std::move(m);
    e.policy = policy;
    impl_->keys[out] = std::move(e);
    return CryptoError::Ok;
}

CryptoError CryptoService::deriveKey(const KeyId& base, ByteView context,
                                     const KeyPolicy& policy, KeyId& out) {
    std::lock_guard<std::mutex> g(impl_->mu);
    auto it = impl_->keys.find(base);
    if (it == impl_->keys.end()) return CryptoError::KeyNotFound;
    if (!(it->second.policy.usage & (uint32_t)KeyUsage::Derive))
        return CryptoError::KeyPolicyDenied;
    uint8_t material[32];
    static const uint8_t kSalt[16] = {'p', 'o', 'l', 'a', 'r', 'i', 's', '-',
                                      'h', 'k', 'd', 'f', '-', 'v', '1', 0};
    hkdf_sha256(it->second.material.data(), 32, kSalt, sizeof(kSalt),
                context.data, context.size, material, 32);
    SecureBuffer m(material, 32);
    memset(material, 0, sizeof(material));
    out = impl_->idFor(m);
    Impl::Entry e;
    e.material = std::move(m);
    e.policy = policy;
    impl_->keys[out] = std::move(e);
    return CryptoError::Ok;
}

CryptoError CryptoService::destroyKey(const KeyId& key) {
    std::lock_guard<std::mutex> g(impl_->mu);
    return impl_->keys.erase(key) ? CryptoError::Ok : CryptoError::KeyNotFound;
}

CryptoError CryptoService::keyInfo(const KeyId& key, KeyInfo& out) const {
    std::lock_guard<std::mutex> g(impl_->mu);
    auto it = impl_->keys.find(key);
    if (it == impl_->keys.end()) return CryptoError::KeyNotFound;
    out.policy = it->second.policy;
    out.hardware_protected = it->second.policy.hardware_protected;
    out.created_at = it->second.created_at;
    return CryptoError::Ok;
}

CryptoError CryptoService::hmac(const KeyId& key, ByteView data, uint8_t out32[32]) const {
    std::lock_guard<std::mutex> g(impl_->mu);
    auto it = impl_->keys.find(key);
    if (it == impl_->keys.end()) return CryptoError::KeyNotFound;
    if (!(it->second.policy.usage & (uint32_t)KeyUsage::Encrypt) &&
        !(it->second.policy.usage & (uint32_t)KeyUsage::Derive))
        return CryptoError::KeyPolicyDenied;
    hmac_sha256(it->second.material.data(), 32, data.data, data.size, out32);
    return CryptoError::Ok;
}

CryptoError CryptoService::encrypt(const KeyId& key, ByteView plaintext, ByteView aad,
                                   std::vector<uint8_t>& out) const {
    std::lock_guard<std::mutex> g(impl_->mu);
    auto it = impl_->keys.find(key);
    if (it == impl_->keys.end()) return CryptoError::KeyNotFound;
    if (!(it->second.policy.usage & (uint32_t)KeyUsage::Encrypt))
        return CryptoError::KeyPolicyDenied;
    if (!aead_seal(it->second.material.data(), plaintext.data, plaintext.size,
                  aad.data, aad.size, out))
        return CryptoError::ProviderFailure;
    return CryptoError::Ok;
}

CryptoError CryptoService::decrypt(const KeyId& key, ByteView blob, ByteView aad,
                                   std::vector<uint8_t>& out) const {
    std::lock_guard<std::mutex> g(impl_->mu);
    auto it = impl_->keys.find(key);
    if (it == impl_->keys.end()) return CryptoError::KeyNotFound;
    if (!(it->second.policy.usage & (uint32_t)KeyUsage::Encrypt))
        return CryptoError::KeyPolicyDenied;
    if (!aead_open(it->second.material.data(), blob.data, blob.size, aad.data,
                   aad.size, out))
        return CryptoError::OpenFailure;
    return CryptoError::Ok;
}

CryptoError CryptoService::deviceSign(uint8_t sig64[64], ByteView msg) const {
    if (!impl_->provider) return CryptoError::ProviderFailure;
    if (!impl_->provider->ensureDeviceKey()) return CryptoError::ProviderFailure;
    if (!impl_->provider->deviceSign(sig64, msg)) return CryptoError::ProviderFailure;
    return CryptoError::Ok;
}

CryptoError CryptoService::devicePublicKey(uint8_t pk32[32]) const {
    if (!impl_->provider) return CryptoError::ProviderFailure;
    if (!impl_->provider->ensureDeviceKey()) return CryptoError::ProviderFailure;
    if (!impl_->provider->devicePublicKey(pk32)) return CryptoError::ProviderFailure;
    return CryptoError::Ok;
}

CryptoError CryptoService::verify(const uint8_t pk32[32], ByteView msg,
                                  const uint8_t sig64[64]) {
    return ed25519_verify(sig64, msg.data, msg.size, pk32) ? CryptoError::Ok
                                                           : CryptoError::OpenFailure;
}

}  // namespace polaris_secure
