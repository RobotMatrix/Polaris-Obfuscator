// AES-128 封装与 AEAD (AES-CTR || HMAC-SHA256 encrypt-then-MAC)。
// AES 轮函数复用 third_party/tiny_aes.c (NIST SP800-38A KAT 验证)。
#include "polaris_secure/crypto.h"
#include "../../third_party/aes.h"

#include <cstring>
#include <vector>

namespace polaris_secure {
namespace prim {

void aes128_init(Aes128Ctx* c, const uint8_t key[16]) {
    struct AES_ctx a;
    AES_init_ctx(&a, key);
    memcpy(c->rk, a.RoundKey, sizeof(c->rk));
}

void aes128_ecb_encrypt(const Aes128Ctx* c, const uint8_t in[16], uint8_t out[16]) {
    struct AES_ctx a;
    memcpy(a.RoundKey, c->rk, sizeof(a.RoundKey));
    memcpy(out, in, 16);
    AES_ECB_encrypt(&a, out);
}

void aes128_ecb_decrypt(const Aes128Ctx* c, const uint8_t in[16], uint8_t out[16]) {
    struct AES_ctx a;
    memcpy(a.RoundKey, c->rk, sizeof(a.RoundKey));
    memcpy(out, in, 16);
    AES_ECB_decrypt(&a, out);
}

// 标准 CTR: 计数块 = iv, 每块后整 16 字节大端 +1 (与 OpenSSL enc -aes-128-ctr 一致)
void aes128_ctr_xcrypt(const Aes128Ctx* c, const uint8_t iv[16], const uint8_t* in,
                       uint8_t* out, size_t n) {
    uint8_t ctr[16], ks[16];
    memcpy(ctr, iv, 16);
    size_t off = 0;
    while (off < n) {
        aes128_ecb_encrypt(c, ctr, ks);
        size_t chunk = n - off < 16 ? n - off : 16;
        for (size_t i = 0; i < chunk; i++) out[off + i] = in[off + i] ^ ks[i];
        off += chunk;
        for (int i = 15; i >= 0; i--)
            if (++ctr[i]) break;
    }
}

// key32 = enc_key(16) || mac_key(16)
// out = nonce(12) || ct(n) || tag(16)
// tag = HMAC-SHA256(mac_key, aad || nonce || ct) 截断 16B
static void aead_tag(const uint8_t key32[32], const uint8_t* aad, size_t aad_len,
                     const uint8_t* nonce, const uint8_t* ct, size_t n, uint8_t tag[32]) {
    // 增量计算 inner: SHA256(ipad || aad || nonce || ct)
    uint8_t k0[64], ipad[64];
    memset(k0, 0, 64);
    memcpy(k0, key32 + 16, 16);
    for (int i = 0; i < 64; i++) ipad[i] = k0[i] ^ 0x36;
    Sha256Ctx h;
    sha256_init(&h);
    sha256_update(&h, ipad, 64);
    if (aad && aad_len) sha256_update(&h, aad, aad_len);
    sha256_update(&h, nonce, 12);
    sha256_update(&h, ct, n);
    uint8_t inner[32];
    sha256_final(&h, inner);
    hmac_sha256(key32 + 16, 16, inner, 32, tag);
    memset(k0, 0, sizeof(k0));
}

bool aead_seal(const uint8_t key32[32], const uint8_t* plaintext, size_t n,
               const uint8_t* aad, size_t aad_len, std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(12 + n + 16);
    uint8_t nonce[12];
    if (!secure_random(nonce, sizeof(nonce))) return false;
    uint8_t iv[16];
    memset(iv, 0, 16);
    iv[0] = 1;  // 版式: 4B 保留 || 12B nonce || (计数从 0 起, 由 ctr_xcrypt 内部递增)
    memcpy(iv + 4, nonce, 12);

    Aes128Ctx aes;
    aes128_init(&aes, key32);

    std::vector<uint8_t> ct(n);
    aes128_ctr_xcrypt(&aes, iv, plaintext, ct.data(), n);

    uint8_t tag[32];
    aead_tag(key32, aad, aad_len, nonce, ct.data(), n, tag);

    out.insert(out.end(), nonce, nonce + 12);
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag, tag + 16);
    return true;
}

bool aead_open(const uint8_t key32[32], const uint8_t* blob, size_t blob_len,
               const uint8_t* aad, size_t aad_len, std::vector<uint8_t>& out) {
    if (blob_len < 12 + 16) return false;
    size_t n = blob_len - 12 - 16;
    const uint8_t* nonce = blob;
    const uint8_t* ct = blob + 12;
    const uint8_t* tag = blob + 12 + n;

    uint8_t calc[32];
    aead_tag(key32, aad, aad_len, nonce, ct, n, calc);
    if (!constant_time_equal(calc, tag, 16)) return false;

    uint8_t iv[16];
    memset(iv, 0, 16);
    iv[0] = 1;
    memcpy(iv + 4, nonce, 12);
    Aes128Ctx aes;
    aes128_init(&aes, key32);
    out.resize(n);
    aes128_ctr_xcrypt(&aes, iv, ct, out.data(), n);
    return true;
}

}  // namespace prim
}  // namespace polaris_secure
