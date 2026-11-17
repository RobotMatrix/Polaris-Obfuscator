// polaris_secure/license.h — 授权材料 (在线短期令牌 / 离线授权)
// 对应参考架构 §9: 服务端签发、设备绑定、请求绑定、有效期、防回滚水位。
// 编码: 固定布局 211B (见 docs/05 的字段表), Ed25519 签名覆盖 [0,147)。
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "bytes.h"

namespace polaris_secure {

constexpr size_t kLicenseSize = 211;
constexpr uint8_t kLicenseMagic[4] = {'P', 'S', 'L', '1'};

// 授权绑定类型
enum class LicenseBind : uint8_t {
    None = 0,        // 离线长授权
    Challenge = 1,   // 在线: 绑定 SHA256(client_nonce || server_nonce)
    Request = 2,     // 在线: 绑定请求内容哈希 (高价值操作)
};

struct License {
    uint16_t version = 1;
    uint8_t key_id[32] = {0};     // 签发公钥 id = SHA256(pubkey)
    uint64_t serial = 0;          // 全局单调序列 (防回滚水位)
    uint64_t issued_at = 0;       // unix 秒
    uint64_t not_before = 0;
    uint64_t not_after = 0;
    uint8_t device_id[32] = {0};  // 全零 = 不绑定
    uint32_t features = 0;        // 功能位掩码
    uint64_t min_device_counter = 0;  // 设备受保护计数器下限
    LicenseBind bind = LicenseBind::None;
    uint8_t bind_value[32] = {0};
    uint8_t signature[64] = {0};

    // 编码 / 解码 (无损)
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* data, size_t n, License& out);
};

// 服务器签发侧工具 (真实部署中运行于服务端; 测试中由本地模拟器使用)
struct IssuerKey {
    uint8_t pk[32];
    uint8_t sk[64];  // seed || pk
};
bool issuerGenerate(IssuerKey& out, const uint8_t seed32[32]);
bool issuerKeyId(const IssuerKey& k, uint8_t id32[32]);
bool issueLicense(const IssuerKey& key, const License& tmpl, License& out);

// 客户端验证结果
enum class LicenseStatus {
    Ok = 0,
    BadFormat,
    UnknownKey,       // 非受信签发公钥
    BadSignature,
    NotYetValid,      // now < not_before
    Expired,          // now > not_after
    DeviceMismatch,   // 授权绑定其他设备
    BindMismatch,     // 挑战/请求绑定不匹配
    RollbackRejected, // serial < 受保护水位 (旧授权重放)
    CounterTooLow,    // 设备计数器 < min_device_counter
};

struct LicenseVerifyCtx {
    // 受信签发公钥 (可多个, 支持轮换)
    std::vector<std::vector<uint8_t>> trusted_keys;  // 每个 32B
    uint8_t device_id[32] = {0};
    uint64_t now = 0;                 // 注入时间 (生产: TEE 可信时间优先)
    uint64_t protected_serial_floor = 0;  // 受保护存储中的已见最大 serial
    uint64_t device_counter = 0;      // 受保护计数器当前值
    // 期望绑定 (验证 Challenge/Request 授权时填)
    const uint8_t* expected_bind = nullptr;  // 32B
};

LicenseStatus verifyLicense(const License& lic, const LicenseVerifyCtx& ctx);

const char* licenseStatusName(LicenseStatus s);

}  // namespace polaris_secure
