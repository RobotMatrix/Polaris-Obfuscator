// polaris_secure/crypto.h — 自包含密码原语 (无外部依赖)
// SHA-256 / SHA-512 / HMAC / HKDF / AES-128 / Ed25519
// 定位: 密码服务层(CryptoService)之下的原语层, 见 docs/02。
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include "bytes.h"

namespace polaris_secure {
namespace prim {

// ---------- SHA-256 ----------
struct Sha256Ctx {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t buflen;
};
void sha256_init(Sha256Ctx* c);
void sha256_update(Sha256Ctx* c, const void* data, size_t n);
void sha256_final(Sha256Ctx* c, uint8_t out[32]);
void sha256(const void* data, size_t n, uint8_t out[32]);

// ---------- SHA-512 ----------
struct Sha512Ctx {
    uint64_t h[8];
    uint64_t len_lo, len_hi;  // 已处理字节数 (128-bit)
    uint8_t buf[128];
    size_t buflen;
};
void sha512_init(Sha512Ctx* c);
void sha512_update(Sha512Ctx* c, const void* data, size_t n);
void sha512_final(Sha512Ctx* c, uint8_t out[64]);
void sha512(const void* data, size_t n, uint8_t out[64]);

// ---------- HMAC (SHA-256 / SHA-512) ----------
void hmac_sha256(const uint8_t* key, size_t keylen, const void* data, size_t n,
                 uint8_t out[32]);
void hmac_sha512(const uint8_t* key, size_t keylen, const void* data, size_t n,
                 uint8_t out[64]);

// ---------- HKDF-SHA256 (RFC 5869) ----------
// ikm -> (salt, info, L) -> okm[L]
void hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt,
                 size_t salt_len, const uint8_t* info, size_t info_len,
                 uint8_t* okm, size_t okm_len);

// ---------- AES-128 (复用 third_party/tiny_aes.c, NIST SP800-38A 验证) ----------
struct Aes128Ctx {
    uint32_t rk[44];
};
void aes128_init(Aes128Ctx* c, const uint8_t key[16]);
void aes128_ecb_encrypt(const Aes128Ctx* c, const uint8_t in[16], uint8_t out[16]);
void aes128_ecb_decrypt(const Aes128Ctx* c, const uint8_t in[16], uint8_t out[16]);
void aes128_ctr_xcrypt(const Aes128Ctx* c, const uint8_t iv[16], const uint8_t* in,
                       uint8_t* out, size_t n);

// AEAD 构造: AES-128-CTR 加密 + HMAC-SHA256 (encrypt-then-MAC, 截断 16B)
// 输出 = nonce(12) || ciphertext(n) || tag(16); 密钥 32B = enc(16)||mac(16)
bool aead_seal(const uint8_t key32[32], const uint8_t* plaintext, size_t n,
               const uint8_t* aad, size_t aad_len, std::vector<uint8_t>& out);
bool aead_open(const uint8_t key32[32], const uint8_t* blob, size_t blob_len,
               const uint8_t* aad, size_t aad_len, std::vector<uint8_t>& out);

// ---------- Ed25519 (RFC 8032) ----------
void ed25519_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]);
bool ed25519_sign(uint8_t sig[64], const uint8_t* msg, size_t n, const uint8_t pk[32],
                  const uint8_t sk[64]);
bool ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t n,
                    const uint8_t pk[32]);

// 密码学随机: 平台 CSPRNG (getentropy/arc4random/BCrypt 后端见 .c)
bool secure_random(uint8_t* out, size_t n);

}  // namespace prim
}  // namespace polaris_secure
