// bench_core — 核心操作性能基准 (混淆矩阵开销测量)
// 输出: 各操作耗时 (ms), 供 PLAIN vs OBF 对比。
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

#include "polaris_secure/crypto.h"
#include "polaris_secure/license.h"
#include "polaris_secure/risk_model.h"
#include "risk_model_data.h"

using namespace polaris_secure;
using namespace polaris_secure::prim;

template <typename F>
static double bench_ms(int iters, F&& f) {
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < iters; i++) f();
    auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

int main() {
    // SHA-256 64KB × 200
    {
        std::vector<uint8_t> buf(65536, 0x5A);
        uint8_t h[32];
        double ms = bench_ms(200, [&] { sha256(buf.data(), buf.size(), h); });
        printf("sha256_64kx200_ms %.3f\n", ms);
    }
    // SHA-512 64KB × 200
    {
        std::vector<uint8_t> buf(65536, 0x5A);
        uint8_t h[64];
        double ms = bench_ms(200, [&] { sha512(buf.data(), buf.size(), h); });
        printf("sha512_64kx200_ms %.3f\n", ms);
    }
    // AES-CTR 256KB × 50
    {
        uint8_t key[16] = {0}, iv[16] = {0};
        std::vector<uint8_t> in(262144, 0x33), out(262144);
        Aes128Ctx c;
        aes128_init(&c, key);
        double ms = bench_ms(50, [&] { aes128_ctr_xcrypt(&c, iv, in.data(), out.data(), in.size()); });
        printf("aes_ctr_256kx50_ms %.3f\n", ms);
    }
    // AEAD 4KB × 200
    {
        uint8_t key[32] = {0};
        std::vector<uint8_t> in(4096, 0x44), out;
        double ms = bench_ms(200, [&] {
            aead_seal(key, in.data(), in.size(), nullptr, 0, out);
        });
        printf("aead_4kx200_ms %.3f\n", ms);
    }
    // Ed25519 sign × 20 / verify × 20
    {
        uint8_t pk[32], sk[64], sig[64], seed[32] = {1};
        ed25519_keypair(pk, sk, seed);
        const char* msg = "benchmark-message";
        double ms = bench_ms(20, [&] { ed25519_sign(sig, (const uint8_t*)msg, 16, pk, sk); });
        printf("ed25519_sign_x20_ms %.3f\n", ms);
        ms = bench_ms(20, [&] { ed25519_verify(sig, (const uint8_t*)msg, 16, pk); });
        printf("ed25519_verify_x20_ms %.3f\n", ms);
    }
    // License verify × 100
    {
        IssuerKey k;
        uint8_t seed[32];
        sha256("bench", 5, seed);
        issuerGenerate(k, seed);
        License t;
        t.serial = 1;
        t.issued_at = 1000;
        t.not_before = 1000;
        t.not_after = 2000;
        License lic;
        issueLicense(k, t, lic);
        LicenseVerifyCtx ctx;
        ctx.trusted_keys = {{k.pk, k.pk + 32}};
        ctx.now = 1500;
        ctx.device_counter = 0;
        double ms = bench_ms(100, [&] {
            if (verifyLicense(lic, ctx) != LicenseStatus::Ok) printf("verify failed\n");
        });
        printf("license_verify_x100_ms %.3f\n", ms);
    }
    // 风险推理 × 10000 (直接解包参数; 签名验证路径另由测试覆盖)
    {
        RiskModel m;
        memset(&m, 0, sizeof(m));
        m.version = 1;
        m.feats = 12;
        m.hid = 8;
        const uint8_t* p = kRiskModelBlob + 16;
        m.w1.assign((const int8_t*)p, (const int8_t*)p + 96);
        p += 96;
        m.b1.assign((const int8_t*)p, (const int8_t*)p + 8);
        p += 8;
        m.w2.assign((const int8_t*)p, (const int8_t*)p + 8);
        p += 8;
        m.b2 = (int8_t)*p++;
        memcpy(&m.s_w1, p, 4); p += 4;
        memcpy(&m.s_b1, p, 4); p += 4;
        memcpy(&m.s_w2, p, 4); p += 4;
        memcpy(&m.s_b2, p, 4);
        FeatureVector fv = {};
        fv[kFtHook] = 0.5f;
        float acc = 0;
        double ms = bench_ms(10000, [&] { acc += riskInference(m, fv); });
        printf("risk_infer_x10k_ms %.3f acc %.6f\n", ms, acc);
    }
    printf("bench done\n");
    return 0;
}
