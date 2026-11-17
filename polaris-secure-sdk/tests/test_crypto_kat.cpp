// 密码原语已知答案测试 (KAT)
// 向量来源: FIPS 180-4 / RFC 4231 / RFC 5869 / NIST SP800-38A / RFC 8032
#include "test_harness.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace polaris_secure;
using namespace polaris_secure::prim;

static bool hexeq(const uint8_t* got, size_t n, const char* want) {
    std::string g = to_hex(got, n);
    std::string w(want);
    for (auto& c : w)
        if (c >= 'A' && c <= 'F') c = (char)(c - 'A' + 'a');
    return g == w;
}

int main() {
    printf("== test_crypto_kat ==\n");

    // ---- SHA-256 ----
    {
        uint8_t d[32];
        sha256("abc", 3, d);
        CHECK(hexeq(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
              "sha256('abc')");
        sha256("", 0, d);
        CHECK(hexeq(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
              "sha256('')");
        // 分块边界: 55/56/64/1000 字节增量一致性
        std::vector<uint8_t> buf(1000, 0x61);
        uint8_t d1[32], d2[32];
        sha256(buf.data(), buf.size(), d1);
        Sha256Ctx c;
        sha256_init(&c);
        for (size_t i = 0; i < buf.size(); i += 7) {
            size_t k = i + 7 < buf.size() ? 7 : buf.size() - i;
            sha256_update(&c, buf.data() + i, k);
        }
        sha256_final(&c, d2);
        CHECK(memcmp(d1, d2, 32) == 0, "sha256 incremental == oneshot (跨块)");
    }
    // ---- SHA-512 ----
    {
        uint8_t d[64];
        sha512("abc", 3, d);
        CHECK(hexeq(d, 64,
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
              "sha512('abc')");
        std::vector<uint8_t> buf(2000, 0x37);
        uint8_t d1[64], d2[64];
        sha512(buf.data(), buf.size(), d1);
        Sha512Ctx c;
        sha512_init(&c);
        for (size_t i = 0; i < buf.size(); i += 13) {
            size_t k = i + 13 < buf.size() ? 13 : buf.size() - i;
            sha512_update(&c, buf.data() + i, k);
        }
        sha512_final(&c, d2);
        CHECK(memcmp(d1, d2, 64) == 0, "sha512 incremental == oneshot (跨块)");
    }
    // ---- HMAC RFC 4231 TC1 ----
    {
        uint8_t key[20], mac[64];
        memset(key, 0x0b, 20);
        hmac_sha256(key, 20, "Hi There", 8, mac);
        CHECK(hexeq(mac, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
              "hmac_sha256 RFC4231-TC1");
        hmac_sha512(key, 20, "Hi There", 8, mac);
        CHECK(hexeq(mac, 64,
                    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"),
              "hmac_sha512 RFC4231-TC1");
        // 长密钥 (>block size) TC 用例: RFC4231 TC6 key 131B
        std::vector<uint8_t> k131(131, 0xaa);
        const char* data6 = "Test Using Larger Than Block-Size Key - Hash Key First";
        hmac_sha256(k131.data(), 131, data6, strlen(data6), mac);
        CHECK(hexeq(mac, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
              "hmac_sha256 RFC4231-TC6 (长密钥)");
    }
    // ---- HKDF RFC 5869 TC1 ----
    {
        uint8_t ikm[22], okm[42];
        memset(ikm, 0x0b, 22);
        uint8_t salt[13], info[10];
        for (int i = 0; i < 13; i++) salt[i] = (uint8_t)i;
        for (int i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
        hkdf_sha256(ikm, 22, salt, 13, info, 10, okm, 42);
        CHECK(hexeq(okm, 42,
                    "3cb25f25faacd57a90434f64d0362f2a"
                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    "34007208d5b887185865"),
              "hkdf RFC5869-TC1");
    }
    // ---- AES-128 NIST SP800-38A ----
    {
        uint8_t key[16], pt[16], ct[16], rt[16];
        const char* khex = "2b7e151628aed2a6abf7158809cf4f3c";
        const char* pthex = "6bc1bee22e409f96e93d7e117393172a";
        const char* cthex = "3ad77bb40d7a3660a89ecaf32466ef97";
        std::vector<uint8_t> kk, pp, cc;
        from_hex(khex, kk);
        from_hex(pthex, pp);
        from_hex(cthex, cc);
        Aes128Ctx c;
        aes128_init(&c, kk.data());
        aes128_ecb_encrypt(&c, pp.data(), ct);
        CHECK(hexeq(ct, 16, cthex), "aes128-ecb encrypt NIST");
        aes128_ecb_decrypt(&c, cc.data(), rt);
        CHECK(hexeq(rt, 16, pthex), "aes128-ecb decrypt NIST");
        // CTR 自洽 + 已知向量 (F.5.1: same key, counter from 0)
        // F.5.1 CTR-AES128.Encrypt: 初值 f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
        const char* ivhex = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        const char* ctr_ct =
            "874d6191b620e3261bef6864990db6ce";
        std::vector<uint8_t> iv;
        from_hex(ivhex, iv);
        uint8_t out[16];
        aes128_ctr_xcrypt(&c, iv.data(), pp.data(), out, 16);
        CHECK(hexeq(out, 16, ctr_ct), "aes128-ctr NIST F.5.1");
    }
    // ---- AEAD ----
    {
        uint8_t key32[32];
        for (int i = 0; i < 32; i++) key32[i] = (uint8_t)i;
        std::vector<uint8_t> pt(100, 0xAB), ct, rt;
        const char* aad = "header";
        CHECK(aead_seal(key32, pt.data(), pt.size(), (const uint8_t*)aad, 6, ct),
              "aead_seal ok");
        CHECK(aead_open(key32, ct.data(), ct.size(), (const uint8_t*)aad, 6, rt) &&
                  rt == pt,
              "aead_open roundtrip");
        // 篡改密文 → 拒绝
        ct[15] ^= 1;
        CHECK(!aead_open(key32, ct.data(), ct.size(), (const uint8_t*)aad, 6, rt),
              "aead tampered ct rejected");
        ct[15] ^= 1;
        // 篡改 AAD → 拒绝
        CHECK(!aead_open(key32, ct.data(), ct.size(), (const uint8_t*)"headeX", 6, rt),
              "aead tampered aad rejected");
        // 篡改 nonce → 拒绝
        ct[3] ^= 1;
        CHECK(!aead_open(key32, ct.data(), ct.size(), (const uint8_t*)aad, 6, rt),
              "aead tampered nonce rejected");
    }
    // ---- Ed25519 RFC 8032 ----
    struct Vec { const char* seed, *pk, *msg, *sig; };
    static const Vec vecs[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
         "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
         "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
    };
    for (size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        std::vector<uint8_t> seed, pk, msg, want;
        from_hex(vecs[i].seed, seed);
        from_hex(vecs[i].pk, pk);
        from_hex(vecs[i].msg, msg);
        from_hex(vecs[i].sig, want);
        uint8_t got_pk[32], sk[64], sig[64];
        ed25519_keypair(got_pk, sk, seed.data());
        char name[128];
        snprintf(name, sizeof(name), "ed25519 keypair RFC8032-T%zu", i + 1);
        CHECK(hexeq(got_pk, 32, vecs[i].pk), name);
        snprintf(name, sizeof(name), "ed25519 sign RFC8032-T%zu", i + 1);
        ed25519_sign(sig, msg.data(), msg.size(), got_pk, sk);
        CHECK(hexeq(sig, 64, vecs[i].sig), name);
        snprintf(name, sizeof(name), "ed25519 verify RFC8032-T%zu", i + 1);
        CHECK(ed25519_verify(want.data(), msg.data(), msg.size(), pk.data()), name);
    }
    // 篡改消息/签名/公钥 → 拒绝
    {
        std::vector<uint8_t> seed, pk, msg, want;
        from_hex(vecs[1].seed, seed);
        from_hex(vecs[1].pk, pk);
        from_hex(vecs[1].msg, msg);
        from_hex(vecs[1].sig, want);
        msg[0] ^= 1;
        CHECK(!ed25519_verify(want.data(), msg.data(), msg.size(), pk.data()),
              "ed25519 reject tampered msg");
        msg[0] ^= 1;
        want[10] ^= 1;
        CHECK(!ed25519_verify(want.data(), msg.data(), msg.size(), pk.data()),
              "ed25519 reject tampered sig");
        want[10] ^= 1;
        pk[5] ^= 1;
        CHECK(!ed25519_verify(want.data(), msg.data(), msg.size(), pk.data()),
              "ed25519 reject wrong pubkey");
        // S >= L (非规范标量) → 拒绝: 用 L 本身当 S (大端序字节即 LE 的逆序)
        static const uint8_t Lbe[32] = {0x10,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                                        0x14,0xde,0xf9,0xde,0xa2,0xf7,0x9c,0xd6,
                                        0x58,0x12,0x63,0x1a,0x5c,0xf5,0xd3,0xed};
        std::vector<uint8_t> sigL = want;
        for (int j = 0; j < 32; j++) sigL[32 + j] = Lbe[31 - j];  // 转小端
        CHECK(!ed25519_verify(sigL.data(), msg.data(), msg.size(), pk.data()),
              "ed25519 reject non-canonical S (S==L)");
    }
    // ---- secure_random ----
    {
        uint8_t a[32] = {0}, b[32] = {0};
        CHECK(secure_random(a, 32) && secure_random(b, 32) && memcmp(a, b, 32) != 0,
              "secure_random 两次输出不同");
    }

    printf(g_fail_count == 0 ? "== test_crypto_kat ALL PASS ==\n"
                             : "== test_crypto_kat FAILED (%d) ==\n", g_fail_count);
    return test_summary("test_crypto_kat");
}
