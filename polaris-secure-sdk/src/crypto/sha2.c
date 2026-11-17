// SHA-256 / SHA-512 / HMAC / HKDF — 参照 FIPS 180-4 / RFC 2104 / RFC 5869 实现。
// 实现以正确性与可审计性为先 (参考实现), 已知并非最优侧信道加固 (见 docs/02)。
#include "polaris_secure/crypto.h"

#include <cstring>

namespace polaris_secure {
namespace prim {

// ============================ SHA-256 ============================
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_compress(uint32_t h[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha256_init(Sha256Ctx* c) {
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85; c->h[2] = 0x3c6ef372;
    c->h[3] = 0xa54ff53a; c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->len = 0;
    c->buflen = 0;
}

void sha256_update(Sha256Ctx* c, const void* data, size_t n) {
    const uint8_t* p = (const uint8_t*)data;
    c->len += n;
    if (c->buflen) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_compress(c->h, c->buf);
            c->buflen = 0;
        }
    }
    while (n >= 64) {
        sha256_compress(c->h, p);
        p += 64;
        n -= 64;
    }
    if (n) {
        memcpy(c->buf, p, n);
        c->buflen = n;
    }
}

void sha256_final(Sha256Ctx* c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen != 56) sha256_update(c, &z, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - i * 8));
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

void sha256(const void* data, size_t n, uint8_t out[32]) {
    Sha256Ctx c;
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, out);
}

// ============================ SHA-512 ============================
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_compress(uint64_t h[8], const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v = (v << 8) | block[i * 8 + j];
        w[i] = v;
    }
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = ROTR64(w[i - 15], 1) ^ ROTR64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ROTR64(w[i - 2], 19) ^ ROTR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t S1 = ROTR64(e, 14) ^ ROTR64(e, 18) ^ ROTR64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = hh + S1 + ch + K512[i] + w[i];
        uint64_t S0 = ROTR64(a, 28) ^ ROTR64(a, 34) ^ ROTR64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha512_init(Sha512Ctx* c) {
    c->h[0] = 0x6a09e667f3bcc908ULL; c->h[1] = 0xbb67ae8584caa73bULL;
    c->h[2] = 0x3c6ef372fe94f82bULL; c->h[3] = 0xa54ff53a5f1d36f1ULL;
    c->h[4] = 0x510e527fade682d1ULL; c->h[5] = 0x9b05688c2b3e6c1fULL;
    c->h[6] = 0x1f83d9abfb41bd6bULL; c->h[7] = 0x5be0cd19137e2179ULL;
    c->len_lo = 0;
    c->len_hi = 0;
    c->buflen = 0;
}

static void sha512_inc(Sha512Ctx* c, uint64_t n) {
    uint64_t prev = c->len_lo;
    c->len_lo += n;
    if (c->len_lo < prev) c->len_hi++;
}

void sha512_update(Sha512Ctx* c, const void* data, size_t n) {
    const uint8_t* p = (const uint8_t*)data;
    sha512_inc(c, n);
    if (c->buflen) {
        size_t take = 128 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 128) {
            sha512_compress(c->h, c->buf);
            c->buflen = 0;
        }
    }
    while (n >= 128) {
        sha512_compress(c->h, p);
        p += 128;
        n -= 128;
    }
    if (n) {
        memcpy(c->buf, p, n);
        c->buflen = n;
    }
}

void sha512_final(Sha512Ctx* c, uint8_t out[64]) {
    uint64_t bits_lo = c->len_lo * 8, bits_hi = c->len_hi * 8 + (c->len_lo >> 61);
    uint8_t pad = 0x80;
    sha512_update(c, &pad, 1);
    uint8_t z = 0;
    while (c->buflen != 112) sha512_update(c, &z, 1);
    uint8_t lenb[16];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits_hi >> (56 - i * 8));
    for (int i = 0; i < 8; i++) lenb[8 + i] = (uint8_t)(bits_lo >> (56 - i * 8));
    sha512_update(c, lenb, 16);
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) out[i * 8 + j] = (uint8_t)(c->h[i] >> (56 - j * 8));
    }
}

void sha512(const void* data, size_t n, uint8_t out[64]) {
    Sha512Ctx c;
    sha512_init(&c);
    sha512_update(&c, data, n);
    sha512_final(&c, out);
}

// ============================ HMAC ============================
static void hmac_generic(int is512, const uint8_t* key, size_t keylen,
                         const void* data, size_t n, uint8_t* out, int* outlen) {
    int B = is512 ? 128 : 64;
    int L = is512 ? 64 : 32;
    uint8_t k0[128];
    memset(k0, 0, sizeof(k0));
    if (keylen > (size_t)B) {
        if (is512) sha512(key, keylen, k0);
        else sha256(key, keylen, k0);
    } else {
        memcpy(k0, key, keylen);
    }
    uint8_t ipad[128], opad[128];
    for (int i = 0; i < B; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    uint8_t inner[64];
    if (is512) {
        Sha512Ctx c;
        sha512_init(&c);
        sha512_update(&c, ipad, B);
        sha512_update(&c, data, n);
        sha512_final(&c, inner);
        Sha512Ctx c2;
        sha512_init(&c2);
        sha512_update(&c2, opad, B);
        sha512_update(&c2, inner, L);
        sha512_final(&c2, out);
    } else {
        Sha256Ctx c;
        sha256_init(&c);
        sha256_update(&c, ipad, B);
        sha256_update(&c, data, n);
        sha256_final(&c, inner);
        Sha256Ctx c2;
        sha256_init(&c2);
        sha256_update(&c2, opad, B);
        sha256_update(&c2, inner, L);
        sha256_final(&c2, out);
    }
    *outlen = L;
    memset(k0, 0, sizeof(k0));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
}

void hmac_sha256(const uint8_t* key, size_t keylen, const void* data, size_t n,
                 uint8_t out[32]) {
    int l;
    hmac_generic(0, key, keylen, data, n, out, &l);
}
void hmac_sha512(const uint8_t* key, size_t keylen, const void* data, size_t n,
                 uint8_t out[64]) {
    int l;
    hmac_generic(1, key, keylen, data, n, out, &l);
}

// ============================ HKDF-SHA256 ============================
// 增量式 HMAC: 内层 = SHA256(ipad || data...), 外层 = SHA256(opad || inner)
static void hkdf_hmac_update(const uint8_t prk[32], const uint8_t* parts[],
                             const size_t lens[], size_t nparts, uint8_t out[32]) {
    Sha256Ctx c;
    sha256_init(&c);
    // k0 = prk (32B, 右侧补零到 64B)
    uint8_t k0[64];
    memset(k0, 0, sizeof(k0));
    memcpy(k0, prk, 32);
    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) ipad[i] = k0[i] ^ 0x36;
    sha256_update(&c, ipad, 64);
    for (size_t i = 0; i < nparts; i++) sha256_update(&c, parts[i], lens[i]);
    uint8_t inner[32];
    sha256_final(&c, inner);
    uint8_t opad[64];
    for (int i = 0; i < 64; i++) opad[i] = k0[i] ^ 0x5c;
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
    memset(k0, 0, sizeof(k0));
}

void hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt,
                 size_t salt_len, const uint8_t* info, size_t info_len,
                 uint8_t* okm, size_t okm_len) {
    uint8_t prk[32];
    if (salt && salt_len)
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    else {
        uint8_t zeros[32] = {0};
        hmac_sha256(zeros, sizeof(zeros), ikm, ikm_len, prk);
    }
    uint8_t t[32];
    size_t tlen = 0;
    size_t off = 0;
    uint8_t counter = 1;
    while (off < okm_len) {
        // T(i) = HMAC(prk, T(i-1) || info || i)
        const uint8_t* parts[3];
        size_t lens[3];
        size_t np = 0;
        if (tlen) {
            parts[np] = t;
            lens[np] = tlen;
            np++;
        }
        parts[np] = info;
        lens[np] = info_len;
        np++;
        parts[np] = &counter;
        lens[np] = 1;
        np++;
        hkdf_hmac_update(prk, parts, lens, np, t);
        tlen = 32;
        size_t cp = okm_len - off < 32 ? okm_len - off : 32;
        memcpy(okm + off, t, cp);
        off += cp;
        counter++;
    }
    memset(prk, 0, sizeof(prk));
}

}  // namespace prim
}  // namespace polaris_secure
