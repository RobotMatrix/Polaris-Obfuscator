// 授权服务器模拟器实现
#include "polaris_secure/authorization_server.h"
#include "polaris_secure/crypto.h"

#include <cstring>

namespace polaris_secure {

using prim::ed25519_sign;
using prim::ed25519_verify;
using prim::secure_random;

static std::vector<uint8_t> v32(const uint8_t* p) { return std::vector<uint8_t>(p, p + 32); }

bool signServerChallenge(const IssuerKey& key, ServerChallenge& c) {
    ServerChallenge t = c;
    memset(t.sig, 0, 64);
    std::vector<uint8_t> body = t.encode();
    ed25519_sign(c.sig, body.data(), body.size(), key.pk, key.sk);
    return true;
}

AuthorizationServer::AuthorizationServer(const IssuerKey& key, uint64_t start_time)
    : key_(key), now_(start_time) {}

void AuthorizationServer::registerDevice(const uint8_t device_id[32],
                                         const uint8_t device_pk[32]) {
    DeviceEntry e;
    memcpy(e.pk, device_pk, 32);
    devices_[v32(device_id)] = e;
    revoked_.erase(v32(device_id));
}
void AuthorizationServer::revokeDevice(const uint8_t device_id[32]) {
    revoked_.insert(v32(device_id));
}
bool AuthorizationServer::isRevoked(const uint8_t device_id[32]) const {
    return revoked_.count(v32(device_id)) > 0;
}
uint64_t AuthorizationServer::deviceCounterFloor(const uint8_t device_id[32]) const {
    auto it = devices_.find(v32(device_id));
    return it == devices_.end() ? 0 : it->second.counter_floor;
}
void AuthorizationServer::advanceTime(uint64_t to) {
    if (to > now_) now_ = to;
}

ServerChallenge AuthorizationServer::processHello(const ClientHello& hello) {
    ServerChallenge c;
    secure_random(c.server_nonce, 32);
    c.timestamp = now_;
    signServerChallenge(key_, c);
    Pending p;
    memcpy(p.device_id, hello.device_id, 32);
    p.issued_at = now_;
    pending_[v32(c.server_nonce)] = p;
    return c;
}

AuthorizationServer::GrantResult AuthorizationServer::processAttest(const ClientAttest& att,
                                                                    double risk_signal) {
    GrantResult r;
    auto deny = [&](DenyReason reason, const char* detail) {
        r.granted = false;
        r.deny.reason = (uint16_t)reason;
        r.deny.detail = detail;
        return r;
    };
    // 1. 设备注册与撤销
    auto it = devices_.find(v32(att.device_id));
    if (it == devices_.end()) return deny(DenyReason::UnknownDevice, "device not registered");
    if (revoked_.count(v32(att.device_id))) return deny(DenyReason::DeviceRevoked, "revoked");
    // 2. 防重放: client_nonce 全局唯一
    if (used_client_nonces_.count(v32(att.client_nonce)))
        return deny(DenyReason::ReplayDetected, "client_nonce reused");
    // 3. 挑战有效性: 本服务器签发、未消费、同设备、未过期
    auto pit = pending_.find(v32(att.server_nonce));
    if (pit == pending_.end())
        return deny(DenyReason::ChallengeInvalid, "unknown server_nonce");
    if (pit->second.consumed)
        return deny(DenyReason::ChallengeInvalid, "challenge consumed");
    if (memcmp(pit->second.device_id, att.device_id, 32) != 0)
        return deny(DenyReason::ChallengeInvalid, "challenge device mismatch");
    if (now_ > pit->second.issued_at + 120)
        return deny(DenyReason::ChallengeInvalid, "challenge expired");
    // 4. 设备签名 (KeyProvider 硬件密钥; 软件后端为等价签名验证)
    if (!att.verifySignature(it->second.pk))
        return deny(DenyReason::AttestBadSignature, "device signature invalid");
    // 5. 服务端风险复核 (客户端上报信号仅作参考, §8.2: 不能成为唯一依据)
    if (risk_signal >= risk_threshold_)
        return deny(DenyReason::RiskDenied, "risk policy");

    // ---- 通过: 签发短期授权 ----
    used_client_nonces_.insert(v32(att.client_nonce));
    pit->second.consumed = true;
    // 服务端计数水位: 记录设备"已知至少推进到"的值 (客户端每次接受授权会 bump)
    uint64_t known_floor = it->second.counter_floor;
    it->second.counter_floor += 1;

    License lic;
    lic.serial = next_serial_++;
    lic.issued_at = now_;
    lic.not_before = now_ - 5;  // 容忍小规模时钟偏差
    lic.not_after = now_ + grant_ttl_s_;
    memcpy(lic.device_id, att.device_id, 32);
    lic.features = 0xFFFFFFFF;  // 参考实现: 全功能 (策略矩阵见 docs/05)
    // 在线授权的防重放由双向 nonce 保证; 计数器水位取签发前的已知值,
    // 避免首次授权即触发客户端 CounterTooLow。
    lic.min_device_counter = known_floor;
    lic.bind = LicenseBind::Challenge;
    challengeHash(att.client_nonce, att.server_nonce, lic.bind_value);
    issueLicense(key_, lic, r.grant.license);

    // 传输签名 = 签名 challengeHash || licenseBytes (防御传输层替换)
    uint8_t ch[32];
    challengeHash(att.client_nonce, att.server_nonce, ch);
    std::vector<uint8_t> body;
    body.insert(body.end(), ch, ch + 32);
    std::vector<uint8_t> lb = r.grant.license.encode();
    body.insert(body.end(), lb.begin(), lb.end());
    ed25519_sign(r.grant.transport_sig, body.data(), body.size(), key_.pk, key_.sk);

    r.granted = true;
    return r;
}

}  // namespace polaris_secure
