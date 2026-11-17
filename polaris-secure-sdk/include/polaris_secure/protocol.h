// polaris_secure/protocol.h — 在线授权协议 (挑战-应答)
// 对应参考架构 §5.3 (TEE接口设计要点) + §9.1 (在线模式):
//   请求绑定随机数/会话, 授权结果绑定具体挑战, 服务器端防重放。
// 传输无关: 消息为纯字节, 可跑在任何通道 (生产建议 TLS 之上)。
#pragma once

#include <cstdint>
#include <vector>
#include "bytes.h"
#include "license.h"

namespace polaris_secure {

// ---------- 消息 (固定布局, little-endian) ----------
// ClientHello: 'PCH1' | device_id(32) | client_nonce(32) | features(u32) | capability(u32) = 76B
struct ClientHello {
    uint8_t device_id[32];
    uint8_t client_nonce[32];
    uint32_t features = 0;
    uint32_t capability = 0;
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* d, size_t n, ClientHello& out);
};

// ServerChallenge: 'PSC1' | server_nonce(32) | timestamp(u64) | sig(64) = 108B
// sig = IssuerKey 签名 "PSC1" || server_nonce || timestamp (服务器身份防伪造)
struct ServerChallenge {
    uint8_t server_nonce[32];
    uint64_t timestamp = 0;
    uint8_t sig[64];
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* d, size_t n, ServerChallenge& out);
};

// ClientAttest: 'PCA1' | device_id(32) | client_nonce(32) | server_nonce(32) |
//               request_hash(32) | device_sig(64) = 200B
// device_sig = 设备密钥签名 over "PCA1"||device_id||client_nonce||server_nonce||request_hash
struct ClientAttest {
    uint8_t device_id[32];
    uint8_t client_nonce[32];
    uint8_t server_nonce[32];
    uint8_t request_hash[32];  // 高价值操作: SHA256(请求内容); 其他场景为请求摘要或全零
    uint8_t device_sig[64];
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* d, size_t n, ClientAttest& out);
    // 用 KeyProvider 设备密钥签名填充 device_sig
    bool sign(class KeyProvider& kp);
    bool verifySignature(const uint8_t device_pk32[32]) const;
};

// ServerGrant: 'PSG1' | license(211) | sig(64) = 283B
// sig = IssuerKey 签名 challenge-hash || license-bytes (传输完整性; license 内部亦有签名)
struct ServerGrant {
    License license;
    uint8_t transport_sig[64];
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* d, size_t n, ServerGrant& out);
};

// ServerDeny: 'PSD1' | reason(u16) | detail_len(u16) | detail = 变长
struct ServerDeny {
    uint16_t reason = 0;
    std::string detail;
    std::vector<uint8_t> encode() const;
    static bool decode(const uint8_t* d, size_t n, ServerDeny& out);
};

// 挑战哈希: 绑定授权的双随机数
void challengeHash(const uint8_t client_nonce[32], const uint8_t server_nonce[32],
                   uint8_t out32[32]);

// 请求哈希 (业务侧计算后填入 ClientAttest)
void requestHash(ByteView request, uint8_t out32[32]);

}  // namespace polaris_secure
