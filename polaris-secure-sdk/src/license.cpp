// License 编解码 / 签发 / 验证
#include "polaris_secure/license.h"
#include "polaris_secure/crypto.h"

#include <cstring>

namespace polaris_secure {

using prim::ed25519_keypair;
using prim::ed25519_sign;
using prim::ed25519_verify;
using prim::sha256;

// 布局常量 (见 license.h)
static constexpr size_t OFF_VERSION = 4;        // u16
static constexpr size_t OFF_KEYID = 6;          // 32
static constexpr size_t OFF_SERIAL = 38;        // u64
static constexpr size_t OFF_ISSUED = 46;        // u64
static constexpr size_t OFF_NOTBEFORE = 54;     // u64
static constexpr size_t OFF_NOTAFTER = 62;      // u64
static constexpr size_t OFF_DEVICE = 70;        // 32
static constexpr size_t OFF_FEATURES = 102;     // u32
static constexpr size_t OFF_MINCTR = 106;       // u64
static constexpr size_t OFF_BINDTYPE = 114;     // u8
static constexpr size_t OFF_BINDVALUE = 115;    // 32
static constexpr size_t OFF_SIG = 147;          // 64
static constexpr size_t TOTAL = 211;

static void put_u16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = (uint8_t)v;
    b[off + 1] = (uint8_t)(v >> 8);
}
static void put_u32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (int i = 0; i < 4; i++) b[off + i] = (uint8_t)(v >> (i * 8));
}
static void put_u64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (int i = 0; i < 8; i++) b[off + i] = (uint8_t)(v >> (i * 8));
}
static uint16_t get_u16(const uint8_t* b) { return (uint16_t)(b[0] | (b[1] << 8)); }
static uint32_t get_u32(const uint8_t* b) {
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}
static uint64_t get_u64(const uint8_t* b) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | b[i];
    return v;
}

std::vector<uint8_t> License::encode() const {
    std::vector<uint8_t> b(TOTAL, 0);
    memcpy(b.data(), kLicenseMagic, 4);
    put_u16(b, OFF_VERSION, version);
    memcpy(b.data() + OFF_KEYID, key_id, 32);
    put_u64(b, OFF_SERIAL, serial);
    put_u64(b, OFF_ISSUED, issued_at);
    put_u64(b, OFF_NOTBEFORE, not_before);
    put_u64(b, OFF_NOTAFTER, not_after);
    memcpy(b.data() + OFF_DEVICE, device_id, 32);
    put_u32(b, OFF_FEATURES, features);
    put_u64(b, OFF_MINCTR, min_device_counter);
    b[OFF_BINDTYPE] = (uint8_t)bind;
    memcpy(b.data() + OFF_BINDVALUE, bind_value, 32);
    memcpy(b.data() + OFF_SIG, signature, 64);
    return b;
}

bool License::decode(const uint8_t* data, size_t n, License& out) {
    if (n != TOTAL) return false;
    if (memcmp(data, kLicenseMagic, 4) != 0) return false;
    out.version = get_u16(data + OFF_VERSION);
    if (out.version != 1) return false;
    memcpy(out.key_id, data + OFF_KEYID, 32);
    out.serial = get_u64(data + OFF_SERIAL);
    out.issued_at = get_u64(data + OFF_ISSUED);
    out.not_before = get_u64(data + OFF_NOTBEFORE);
    out.not_after = get_u64(data + OFF_NOTAFTER);
    memcpy(out.device_id, data + OFF_DEVICE, 32);
    out.features = get_u32(data + OFF_FEATURES);
    out.min_device_counter = get_u64(data + OFF_MINCTR);
    out.bind = (LicenseBind)data[OFF_BINDTYPE];
    if ((uint8_t)out.bind > 2) return false;
    memcpy(out.bind_value, data + OFF_BINDVALUE, 32);
    memcpy(out.signature, data + OFF_SIG, 64);
    return true;
}

bool issuerGenerate(IssuerKey& out, const uint8_t seed32[32]) {
    ed25519_keypair(out.pk, out.sk, seed32);
    return true;
}

bool issuerKeyId(const IssuerKey& k, uint8_t id32[32]) {
    sha256(k.pk, 32, id32);
    return true;
}

bool issueLicense(const IssuerKey& key, const License& tmpl, License& out) {
    out = tmpl;
    issuerKeyId(key, out.key_id);
    std::vector<uint8_t> body = out.encode();
    // 签名覆盖 [0, OFF_SIG)
    ed25519_sign(out.signature, body.data(), OFF_SIG, key.pk, key.sk);
    return true;
}

LicenseStatus verifyLicense(const License& lic, const LicenseVerifyCtx& ctx) {
    // 1. 签发者信任链
    const std::vector<uint8_t>* trusted = nullptr;
    for (auto& k : ctx.trusted_keys) {
        if (k.size() != 32) continue;
        uint8_t id[32];
        sha256(k.data(), 32, id);
        if (memcmp(id, lic.key_id, 32) == 0) {
            trusted = &k;
            break;
        }
    }
    if (!trusted) return LicenseStatus::UnknownKey;
    // 2. 签名
    License copy = lic;
    memset(copy.signature, 0, 64);
    std::vector<uint8_t> body = copy.encode();
    if (!ed25519_verify(lic.signature, body.data(), OFF_SIG, trusted->data()))
        return LicenseStatus::BadSignature;
    // 3. 时间窗 (注入时间; 离线无 TEE 时间时的残余风险见 docs/05)
    if (ctx.now < lic.not_before) return LicenseStatus::NotYetValid;
    if (ctx.now > lic.not_after) return LicenseStatus::Expired;
    // 4. 设备绑定 (device_id 全零 = 不绑定)
    bool any_device = false;
    for (int i = 0; i < 32; i++)
        if (lic.device_id[i]) { any_device = true; break; }
    if (any_device && memcmp(lic.device_id, ctx.device_id, 32) != 0)
        return LicenseStatus::DeviceMismatch;
    // 5. 挑战/请求绑定
    if (lic.bind != LicenseBind::None) {
        if (!ctx.expected_bind) return LicenseStatus::BindMismatch;
        if (!constant_time_equal(lic.bind_value, ctx.expected_bind, 32))
            return LicenseStatus::BindMismatch;
    }
    // 6. 防回滚: serial 不低于受保护水位
    if (lic.serial < ctx.protected_serial_floor) return LicenseStatus::RollbackRejected;
    // 7. 设备计数器下限 (硬件计数器不可回退时有效)
    if (ctx.device_counter < lic.min_device_counter) return LicenseStatus::CounterTooLow;
    return LicenseStatus::Ok;
}

const char* licenseStatusName(LicenseStatus s) {
    switch (s) {
        case LicenseStatus::Ok: return "Ok";
        case LicenseStatus::BadFormat: return "BadFormat";
        case LicenseStatus::UnknownKey: return "UnknownKey";
        case LicenseStatus::BadSignature: return "BadSignature";
        case LicenseStatus::NotYetValid: return "NotYetValid";
        case LicenseStatus::Expired: return "Expired";
        case LicenseStatus::DeviceMismatch: return "DeviceMismatch";
        case LicenseStatus::BindMismatch: return "BindMismatch";
        case LicenseStatus::RollbackRejected: return "RollbackRejected";
        case LicenseStatus::CounterTooLow: return "CounterTooLow";
    }
    return "?";
}

}  // namespace polaris_secure
