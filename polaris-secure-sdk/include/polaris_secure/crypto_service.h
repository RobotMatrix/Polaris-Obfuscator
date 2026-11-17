// polaris_secure/crypto_service.h — 密码服务层 (软件密码模块)
// 对应参考架构 §7: 统一密码 API + 密钥生命周期 + 分层密钥 (§7.3)。
// 定位声明 (§3.2): 本模块是"软件密码模块", 不是硬件 HSM;
// 密钥是否受硬件保护取决于注入的 KeyProvider 能力。
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "bytes.h"
#include "key_provider.h"

namespace polaris_secure {

enum class CryptoAlg : uint8_t {
    Aes128CtrHmacSha256 = 0,  // AEAD (encrypt-then-MAC)
    HmacSha256 = 1,
    Sha256 = 2,
    Ed25519 = 3,
    HkdfSha256 = 4,
};

// 统一错误码
enum class CryptoError : int {
    Ok = 0,
    KeyNotFound = 1,
    KeyPolicyDenied = 2,   // 用途与策略不符
    InvalidParam = 3,
    OpenFailure = 4,       // 解密/验签失败
    ProviderFailure = 5,   // 硬件层故障
};

// 密钥策略: 用途 / 来源 / 可导出性 (§7.2)
struct KeyPolicy {
    uint32_t usage = 0;             // KeyUsage 位组合
    bool exportable = false;        // 软件模块默认不可导出
    bool hardware_protected = false;// 由 KeyProvider 支撑
    std::string label;              // 用途标签 ("session" / "code-enc" / ...)
};

// KeyId: 32 字节不透明标识
struct KeyId {
    uint8_t id[32] = {0};
    bool operator<(const KeyId& o) const { return memcmp(id, o.id, 32) < 0; }
    bool operator==(const KeyId& o) const { return memcmp(id, o.id, 32) == 0; }
};

struct KeyInfo {
    KeyPolicy policy;
    bool hardware_protected = false;
    uint64_t created_at = 0;
};

// CryptoService — 统一密码 API (§7.2 接口的落地形态)
class CryptoService {
public:
    // provider 可为空 (纯软件密钥, 测试); 有 provider 时设备密钥相关操作
    // 走硬件层。
    explicit CryptoService(std::shared_ptr<KeyProvider> provider = nullptr);

    // ---- 随机 / 哈希 / MAC ----
    CryptoError random(uint8_t* out, size_t n) const;
    CryptoError hash(ByteView data, uint8_t out32[32]) const;
    CryptoError hmac(const KeyId& key, ByteView data, uint8_t out32[32]) const;

    // ---- 密钥生命周期 ----
    CryptoError generateKey(const KeyPolicy& policy, KeyId& out);
    CryptoError importSecret(ByteView secret32, const KeyPolicy& policy, KeyId& out);
    CryptoError deriveKey(const KeyId& base, ByteView context, const KeyPolicy& policy,
                          KeyId& out);  // HKDF-SHA256
    CryptoError destroyKey(const KeyId& key);
    CryptoError keyInfo(const KeyId& key, KeyInfo& out) const;

    // ---- 对称 AEAD ----
    CryptoError encrypt(const KeyId& key, ByteView plaintext, ByteView aad,
                        std::vector<uint8_t>& out) const;
    CryptoError decrypt(const KeyId& key, ByteView blob, ByteView aad,
                        std::vector<uint8_t>& out) const;

    // ---- 签名 (设备密钥 = KeyProvider Ed25519) ----
    CryptoError deviceSign(uint8_t sig64[64], ByteView msg) const;
    CryptoError devicePublicKey(uint8_t pk32[32]) const;

    // ---- 独立验签 (公钥验证, 不需私钥) ----
    static CryptoError verify(const uint8_t pk32[32], ByteView msg, const uint8_t sig64[64]);

    ~CryptoService();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace polaris_secure
