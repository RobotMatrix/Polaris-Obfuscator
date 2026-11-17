// polaris_secure/authorization_server.h — 授权服务器模拟器 (进程内)
// 对应参考架构 §9.1: 签发、设备注册表、撤销、防重放、风险复核。
// 真实部署: 该逻辑运行于服务端信任域, 根密钥绝不进入客户端。
// 模拟器用于自动化验证协议正确性, 时间可注入。
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "license.h"
#include "protocol.h"

namespace polaris_secure {

enum class DenyReason : uint16_t {
    UnknownDevice = 1,
    DeviceRevoked = 2,
    ReplayDetected = 3,      // client_nonce 重放
    ChallengeInvalid = 4,    // server_nonce 未签发/已消费/设备不符
    AttestBadSignature = 5,  // 设备签名验证失败
    FeatureDenied = 6,
    RiskDenied = 7,          // 服务端风险策略拒绝
    RateLimited = 8,
};

class AuthorizationServer {
public:
    AuthorizationServer(const IssuerKey& key, uint64_t start_time);

    // ---- 设备注册表 / 撤销 ----
    void registerDevice(const uint8_t device_id[32], const uint8_t device_pk[32]);
    void revokeDevice(const uint8_t device_id[32]);
    bool isRevoked(const uint8_t device_id[32]) const;
    // 服务端记录的设备计数器 (客户端每次上报/签发时推进)
    uint64_t deviceCounterFloor(const uint8_t device_id[32]) const;

    // ---- 时间注入 ----
    void advanceTime(uint64_t to);

    // ---- 策略参数 ----
    void setGrantTtlSeconds(uint64_t s) { grant_ttl_s_ = s; }
    void setRiskThreshold(double t) { risk_threshold_ = t; }  // [0,1]

    // ---- 协议处理 ----
    // 1) hello → challenge (记录 pending 挑战)
    ServerChallenge processHello(const ClientHello& hello);
    // 2) attest → grant 或 deny
    //    risk_signal: 客户端随请求上报的风险分 (不可信信号, 仅作策略输入)
    struct GrantResult {
        bool granted = false;
        ServerGrant grant;
        ServerDeny deny;
    };
    GrantResult processAttest(const ClientAttest& attest, double risk_signal = 0.0);

    const IssuerKey& issuerKey() const { return key_; }
    uint64_t now() const { return now_; }

private:
    struct DeviceEntry {
        uint8_t pk[32];
        uint64_t counter_floor = 0;
    };
    struct Pending {
        uint8_t device_id[32];
        uint64_t issued_at = 0;
        bool consumed = false;
    };
    IssuerKey key_;
    uint64_t now_;
    uint64_t grant_ttl_s_ = 300;      // 短期授权默认 5 分钟
    double risk_threshold_ = 0.85;
    uint64_t next_serial_ = 1;
    std::map<std::vector<uint8_t>, DeviceEntry> devices_;
    std::set<std::vector<uint8_t>> revoked_;
    std::set<std::vector<uint8_t>> used_client_nonces_;
    std::map<std::vector<uint8_t>, Pending> pending_;  // server_nonce → 状态
};

// 便捷: 由 IssuerKey 生成 ServerChallenge 签名
bool signServerChallenge(const IssuerKey& key, ServerChallenge& c);

}  // namespace polaris_secure
