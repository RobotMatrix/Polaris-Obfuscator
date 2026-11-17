// polaris_secure/key_provider.h — 硬件信任层抽象
// 对应参考架构 §5 (硬TEE)、§10 (跨平台能力策略):
//   - SecurityCapability 能力枚举 (统一抽象, 不统一假设)
//   - KeyProvider: 设备密钥 + 受保护状态 (单调计数器 / 受保护存储)
// 实现后端: SoftwareKeyProvider (宿主/测试), KeychainKeyProvider (Apple),
//           AndroidKeystore / OpenHarmony HUKS 后端为接口占位 (见 docs/03)。
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "bytes.h"

namespace polaris_secure {

// 能力分级 (参考架构 §10.1): 只是能力抽象, 实际可用性须按平台/设备验证
enum class SecurityCapability : uint32_t {
    SoftwareOnly = 0,        // 纯软件: 密钥驻留普通内存, 最低保证
    HardwareBackedKey = 1,   // 硬件支撑密钥存储 (Keychain/Keystore/HUKS)
    HardwareBackedCrypto = 2,// 密码操作在硬件内完成, 密钥不可导出
    TrustedExecution = 3,    // 可信执行环境中运行少量验证逻辑
    RemoteAttestation = 4,   // 支持远程证明
};

struct CapabilityReport {
    SecurityCapability level = SecurityCapability::SoftwareOnly;
    bool secure_key_storage = false;   // 受保护密钥存储
    bool monotonic_counter = false;    // 防回滚单调计数器 (硬件 RPMB/SE 计数器)
    bool protected_storage = false;    // 受保护状态存储
    bool remote_attestation = false;   // 设备证明能力
    std::string backend_name;          // 后端实现名
    std::string detail;                // 探测明细 (版本/失败原因等)
};

// 密钥用途策略
enum class KeyUsage : uint32_t {
    Sign = 1,
    Encrypt = 2,
    Derive = 4,
};

// KeyProvider — 设备密钥与受保护状态的提供者
// 真实平台后端将此接口映射到: iOS Keychain/Secure Enclave、Android
// Keystore/StrongBox、OpenHarmony HUKS、Linux TPM、Windows VBS 等。
class KeyProvider {
public:
    virtual ~KeyProvider() = default;

    virtual CapabilityReport capabilities() const = 0;

    // 设备身份密钥 (Ed25519): 首次调用时生成, 之后复用
    virtual bool ensureDeviceKey() = 0;
    virtual bool deviceSign(uint8_t sig64[64], ByteView msg) = 0;
    virtual bool devicePublicKey(uint8_t pk32[32]) const = 0;

    // 受保护单调计数器: bump 返回递增后的值; read 只读
    // 硬件后端映射到 RPMB / Secure Enclave 计数器;
    // 软件后端为 HMAC 封装文件 (可被完全回滚 — 已知局限, 见 docs/03)
    virtual bool counterBump(uint64_t& out) = 0;
    virtual bool counterRead(uint64_t& out) const = 0;

    // 受保护存储 (小容量关键状态)
    virtual bool protectedPut(const std::string& key, ByteView value) = 0;
    virtual bool protectedGet(const std::string& key, std::vector<uint8_t>& out) const = 0;
};

// 软件后端 (宿主自动化测试 / 无硬件能力平台降级):
// 密钥与状态保存于文件, 用设备主密钥(HMAC) 自封装。
// 明确声明: 不具备防导出/防回滚的硬件保证。
std::unique_ptr<KeyProvider> createSoftwareKeyProvider(const std::string& stateDir);

// Apple 后端: Keychain 通用密码存储设备密钥种子与状态。
// (macOS/iOS; 自动化验证默认不启用, 避免测试弹窗 — 见 tests/test_capability.cpp)
#if defined(__APPLE__)
std::unique_ptr<KeyProvider> createKeychainKeyProvider(const std::string& service);
#endif

// 按 ID 生成的设备标识 (软件级; 真实部署应绑定硬件标识)
bool deriveDeviceId(const KeyProvider& kp, uint8_t id32[32]);

}  // namespace polaris_secure
