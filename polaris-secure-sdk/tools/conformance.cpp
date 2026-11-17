// conformance — 全栈一致性载荷
// 用途: 混淆矩阵等价性验证。PLAIN 与 Polaris 混淆两个构建必须输出
// 逐字节相同的 stdout (退出码 0)。固定种子 → 确定性结果流。
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "polaris_secure/authorization_server.h"
#include "polaris_secure/crypto.h"
#include "polaris_secure/secure_sdk.h"
#include "risk_model_data.h"

using namespace polaris_secure;
using polaris_secure::prim::aead_open;
using polaris_secure::prim::aead_seal;
using polaris_secure::prim::ed25519_keypair;
using polaris_secure::prim::ed25519_sign;
using polaris_secure::prim::ed25519_verify;
using polaris_secure::prim::hkdf_sha256;
using polaris_secure::prim::sha256;

// 固定种子密钥 (确定性输出; 仅测试)
static IssuerKey keyFrom(const char* tag) {
    IssuerKey k;
    uint8_t seed[32];
    prim::sha256(tag, strlen(tag), seed);
    issuerGenerate(k, seed);
    return k;
}

int main() {
    IssuerKey issuer = keyFrom("conformance-issuer");
    IssuerKey modelKey = keyFrom("conformance-model");

    // 模型签名 (确定性)
    std::vector<uint8_t> blob(kRiskModelBlob, kRiskModelBlob + kRiskModelBlobSize);
    uint8_t sig[64];
    prim::ed25519_sign(sig, blob.data(), blob.size(), modelKey.pk, modelKey.sk);
    blob.insert(blob.end(), sig, sig + 64);

    const uint64_t T0 = 1762900000;
    // 逐场景输出 PASS/FAIL 行; 任何 FAIL 或非零退出 = 不一致
    int failures = 0;
    auto emit = [&](bool ok, const char* tag) {
        printf("%s %s\n", ok ? "PASS" : "FAIL", tag);
        if (!ok) failures++;
    };

    // 1) 签名/验签确定性
    {
        uint8_t pk[32], sk[64], s[64];
        uint8_t seed[32];
        prim::sha256("seed-1", 6, seed);
        prim::ed25519_keypair(pk, sk, seed);
        prim::ed25519_sign(s, (const uint8_t*)"payload", 7, pk, sk);
        emit(prim::ed25519_verify(s, (const uint8_t*)"payload", 7, pk), "ed25519-roundtrip");
        emit(!prim::ed25519_verify(s, (const uint8_t*)"payloae", 7, pk), "ed25519-reject");
    }

    // 2) 哈希/AEAD/HKDF 链
    {
        uint8_t h[32];
        prim::sha256("conformance", 11, h);
        printf("sha256 ");
        for (int i = 0; i < 32; i++) printf("%02x", h[i]);
        printf("\n");
        uint8_t ikm[32], okm[64];
        for (int i = 0; i < 32; i++) ikm[i] = (uint8_t)(i * 5 + 1);
        prim::hkdf_sha256(ikm, 32, nullptr, 0, (const uint8_t*)"info", 4, okm, 64);
        printf("hkdf ");
        for (int i = 0; i < 64; i++) printf("%02x", okm[i]);
        printf("\n");
        // AEAD 确定性 (固定 nonce 由 seal 内随机… 不可 — 改为对称自检)
        uint8_t key[32];
        memcpy(key, okm, 32);
        std::vector<uint8_t> ct, pt;
        emit(prim::aead_seal(key, (const uint8_t*)"data16-bytes-ok!", 16, nullptr, 0, ct),
             "aead-seal");
        emit(prim::aead_open(key, ct.data(), ct.size(), nullptr, 0, pt) &&
                 pt.size() == 16 && memcmp(pt.data(), "data16-bytes-ok!", 16) == 0,
             "aead-open");
    }

    // 3) 模型推理确定性
    {
        RiskModel m;
        if (loadRiskModel(blob.data(), blob.size(), modelKey.pk, m) == ModelStatus::Ok) {
            float base = 0.0f;
            FeatureVector fv = {};
            fv[kFtHook] = 0.5f;
            fv[kFtDebugger] = 0.3f;
            float r = riskInference(m, fv);
            printf("risk %.6f\n", r + base);
            emit(r > 0.0f && r < 1.0f, "risk-range");
        } else {
            emit(false, "model-load");
        }
    }

    // 4) 全链路: 在线授权 + 策略
    {
        const char* dir = "/tmp/polaris-conformance-state";
        std::string rm = "rm -rf " + std::string(dir);
        system(rm.c_str());
        SdkConfig cfg;
        cfg.state_dir = dir;
        cfg.trusted_issuer_keys = {{issuer.pk, issuer.pk + 32}};
        cfg.model_key = {modelKey.pk, modelKey.pk + 32};
        cfg.model_blob = blob.data();
        cfg.model_blob_size = blob.size();
        cfg.now = T0;
        auto sdk = SecureSDK::create(cfg);
        emit(sdk != nullptr, "sdk-create");
        if (sdk) {
            uint8_t dev[32], pk[32];
            sdk->deviceId(dev);
            sdk->keyProvider().devicePublicKey(pk);
            AuthorizationServer server(issuer, T0);
            server.registerDevice(dev, pk);
            FeatureVector clean = {};
            auto r = sdk->onlineAuthorize(server, 0x03, clean, nullptr, 0);
            emit(r.ok, "online-grant");
            emit(r.ok && r.license.serial > 0, "license-serial");
            emit(r.ok && r.policy.decision == Decision::Allow, "policy-allow");
            emit(sdk->verifyCurrentLicense(T0 + 10) == LicenseStatus::Ok, "recheck-ok");
            emit(sdk->verifyCurrentLicense(T0 + 100000) == LicenseStatus::Expired,
                 "recheck-expired");
            // 撤销
            server.revokeDevice(dev);
            auto r2 = sdk->onlineAuthorize(server, 0x03, clean, nullptr, 0);
            emit(!r2.ok, "revoked-deny");
        }
        system(rm.c_str());
    }

    // 5) 策略控制器不变量
    {
        DeterministicGates g;  // 全 false
        FeatureVector zero = {};
        emit(policyDecide(g, 0.0f, ruleEngineRisk(zero)).decision == Decision::Deny,
             "gate-deny");
        g.license_valid = g.integrity_ok = g.protocol_fresh = g.model_authentic = true;
        emit(policyDecide(g, 0.99f, 0.0f).decision == Decision::Deny, "high-risk-deny");
        emit(policyDecide(g, 0.05f, 0.0f).decision == Decision::Allow, "low-risk-allow");
    }

    printf("conformance %s (%d failures)\n", failures == 0 ? "OK" : "BROKEN", failures);
    return failures == 0 ? 0 : 1;
}
