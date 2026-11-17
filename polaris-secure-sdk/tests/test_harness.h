// 测试公共工具: 断言宏 / 固定测试密钥 / 模型签名
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

#include "polaris_secure/crypto.h"
#include "polaris_secure/crypto_service.h"
#include "polaris_secure/license.h"
#include "risk_model_data.h"

static int g_fail_count = 0;
static int g_pass_count = 0;

#define CHECK(cond, name)                                                    \
    do {                                                                     \
        if (cond) {                                                          \
            printf("  [PASS] %s\n", name);                                   \
            g_pass_count++;                                                  \
        } else {                                                             \
            printf("  [FAIL] %s  (%s:%d)\n", name, __FILE__, __LINE__);      \
            g_fail_count++;                                                  \
        }                                                                    \
    } while (0)

static int test_summary(const char* suite) {
    printf("== %s: %d pass, %d fail ==\n", suite, g_pass_count, g_fail_count);
    return g_fail_count == 0 ? 0 : 1;
}

namespace polaris_secure {
namespace testutil {

// 固定种子派生密钥 (测试确定性; 生产严禁固定种子)
inline void fixedSeed(const char* tag, uint8_t out32[32]) {
    polaris_secure::prim::sha256(tag, strlen(tag), out32);
}

inline IssuerKey testIssuer(const char* tag) {
    IssuerKey k;
    uint8_t seed[32];
    fixedSeed(tag, seed);
    issuerGenerate(k, seed);
    return k;
}

// 对内嵌模型包签名 → 返回签名后的完整包 (body || sig)
inline std::vector<uint8_t> signedModelBlob(const IssuerKey& key) {
    std::vector<uint8_t> blob(kRiskModelBlob, kRiskModelBlob + kRiskModelBlobSize);
    std::vector<uint8_t> out(blob);
    uint8_t sig[64];
    polaris_secure::prim::ed25519_sign(sig, blob.data(), blob.size(), key.pk, key.sk);
    out.insert(out.end(), sig, sig + 64);
    return out;
}

inline std::string tmpdir(const char* tag) {
    std::string d = "/tmp/polaris-test-" + std::string(tag) + "-" +
                    std::to_string(getpid());
    return d;
}

}  // namespace testutil
}  // namespace polaris_secure
