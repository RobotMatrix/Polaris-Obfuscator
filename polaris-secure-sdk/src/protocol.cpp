// 协议消息编解码与签名
#include "polaris_secure/protocol.h"
#include "polaris_secure/crypto.h"
#include "polaris_secure/key_provider.h"

#include <cstring>

namespace polaris_secure {

using prim::ed25519_sign;
using prim::ed25519_verify;
using prim::sha256;

static void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; i++) b[off + i] = (uint8_t)(v >> (i * 8));
}
static uint64_t get64(const uint8_t* b) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

// ---- ClientHello ----
std::vector<uint8_t> ClientHello::encode() const {
    std::vector<uint8_t> b;
    const uint8_t m[4] = {'P', 'C', 'H', '1'};
    b.insert(b.end(), m, m + 4);
    b.insert(b.end(), device_id, device_id + 32);
    b.insert(b.end(), client_nonce, client_nonce + 32);
    for (int i = 0; i < 4; i++) b.push_back((uint8_t)(features >> (i * 8)));
    for (int i = 0; i < 4; i++) b.push_back((uint8_t)(capability >> (i * 8)));
    return b;
}
bool ClientHello::decode(const uint8_t* d, size_t n, ClientHello& out) {
    if (n != 76 || memcmp(d, "PCH1", 4) != 0) return false;
    memcpy(out.device_id, d + 4, 32);
    memcpy(out.client_nonce, d + 36, 32);
    uint32_t f = 0, c = 0;
    for (int i = 3; i >= 0; i--) f = (f << 8) | d[68 + i];
    for (int i = 3; i >= 0; i--) c = (c << 8) | d[72 + i];
    out.features = f;
    out.capability = c;
    return true;
}

// ---- ServerChallenge ----
std::vector<uint8_t> ServerChallenge::encode() const {
    std::vector<uint8_t> b;
    b.insert(b.end(), {'P', 'S', 'C', '1'});
    b.insert(b.end(), server_nonce, server_nonce + 32);
    b.insert(b.end(), 8, 0);
    put64(b, 36, timestamp);
    b.insert(b.end(), sig, sig + 64);
    return b;
}
bool ServerChallenge::decode(const uint8_t* d, size_t n, ServerChallenge& out) {
    if (n != 108 || memcmp(d, "PSC1", 4) != 0) return false;
    memcpy(out.server_nonce, d + 4, 32);
    out.timestamp = get64(d + 36);
    memcpy(out.sig, d + 44, 64);
    return true;
}

// ---- ClientAttest ----
std::vector<uint8_t> ClientAttest::encode() const {
    std::vector<uint8_t> b;
    b.insert(b.end(), {'P', 'C', 'A', '1'});
    b.insert(b.end(), device_id, device_id + 32);
    b.insert(b.end(), client_nonce, client_nonce + 32);
    b.insert(b.end(), server_nonce, server_nonce + 32);
    b.insert(b.end(), request_hash, request_hash + 32);
    b.insert(b.end(), device_sig, device_sig + 64);
    return b;
}
bool ClientAttest::decode(const uint8_t* d, size_t n, ClientAttest& out) {
    if (n != 200 || memcmp(d, "PCA1", 4) != 0) return false;
    memcpy(out.device_id, d + 4, 32);
    memcpy(out.client_nonce, d + 36, 32);
    memcpy(out.server_nonce, d + 68, 32);
    memcpy(out.request_hash, d + 100, 32);
    memcpy(out.device_sig, d + 132, 64);
    return true;
}

bool ClientAttest::sign(KeyProvider& kp) {
    if (!kp.ensureDeviceKey()) return false;
    ClientAttest tmp = *this;
    memset(tmp.device_sig, 0, 64);
    std::vector<uint8_t> body = tmp.encode();
    if (!kp.deviceSign(device_sig, ByteView(body.data(), body.size()))) return false;
    // device_id 顺带由设备公钥派生 (调用方负责一致)
    return true;
}

bool ClientAttest::verifySignature(const uint8_t device_pk32[32]) const {
    ClientAttest tmp = *this;
    memset(tmp.device_sig, 0, 64);
    std::vector<uint8_t> body = tmp.encode();
    return ed25519_verify(device_sig, body.data(), body.size(), device_pk32);
}

// ---- ServerGrant ----
std::vector<uint8_t> ServerGrant::encode() const {
    std::vector<uint8_t> b;
    b.insert(b.end(), {'P', 'S', 'G', '1'});
    std::vector<uint8_t> l = license.encode();
    b.insert(b.end(), l.begin(), l.end());
    b.insert(b.end(), transport_sig, transport_sig + 64);
    return b;
}
bool ServerGrant::decode(const uint8_t* d, size_t n, ServerGrant& out) {
    if (n != 283 || memcmp(d, "PSG1", 4) != 0) return false;
    return License::decode(d + 4, 211, out.license) &&
           (memcpy(out.transport_sig, d + 215, 64), true);
}

// ---- ServerDeny ----
std::vector<uint8_t> ServerDeny::encode() const {
    std::vector<uint8_t> b;
    b.insert(b.end(), {'P', 'S', 'D', '1'});
    b.push_back((uint8_t)reason);
    b.push_back((uint8_t)(reason >> 8));
    b.push_back((uint8_t)detail.size());
    b.push_back((uint8_t)(detail.size() >> 8));
    b.insert(b.end(), detail.begin(), detail.end());
    return b;
}
bool ServerDeny::decode(const uint8_t* d, size_t n, ServerDeny& out) {
    if (n < 8 || memcmp(d, "PSD1", 4) != 0) return false;
    out.reason = (uint16_t)(d[4] | (d[5] << 8));
    uint16_t len = (uint16_t)(d[6] | (d[7] << 8));
    if (n != 8u + len) return false;
    out.detail.assign((const char*)d + 8, len);
    return true;
}

void challengeHash(const uint8_t client_nonce[32], const uint8_t server_nonce[32],
                   uint8_t out32[32]) {
    prim::Sha256Ctx c;
    sha256_init(&c);
    sha256_update(&c, client_nonce, 32);
    sha256_update(&c, server_nonce, 32);
    sha256_final(&c, out32);
}

void requestHash(ByteView request, uint8_t out32[32]) {
    static const char kTag[] = "polaris-request-v1";
    prim::Sha256Ctx c;
    sha256_init(&c);
    sha256_update(&c, kTag, strlen(kTag));
    sha256_update(&c, request.data, request.size);
    sha256_final(&c, out32);
}

}  // namespace polaris_secure
