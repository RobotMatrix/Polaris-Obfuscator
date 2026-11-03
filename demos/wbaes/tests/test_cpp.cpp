// test_cpp.cpp — C++ 复杂语法 × 白盒 AES
// 覆盖: 模板特化/变参模板/CRTP/lambda/异常/STL 容器/智能指针/RAII/运算符重载
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <array>
#include <memory>
#include <functional>
#include <string>
#include <map>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

// ---------- CRTP + 模板 ----------
template <typename Derived>
class CryptoBase {
public:
    void process(uint8_t *data) { static_cast<Derived *>(this)->do_process(data); }
};
class AESOps : public CryptoBase<AESOps> {
public:
    WBAES wb;
    AESOps() { wb.init(); }
    void selfcheck() {
        uint8_t k[16]; for (int i=0;i<16;i++) k[i]=wbaes_key::key_byte(i);
        fprintf(stderr, "AESOps key: ");
        for (int i=0;i<16;i++) fprintf(stderr, "%02x", k[i]);
        fprintf(stderr, "\n");
    }
    void do_process(uint8_t *data) { wb.encrypt(data, data); }
    void undo(uint8_t *data) { wb.decrypt(data, data); }
};

// ---------- 变参模板: 递归多块加密 ----------
template <typename... Rest>
void encrypt_all(WBAES &wb, uint8_t *first, Rest... rest) {
    wb.encrypt(first, first);
    encrypt_all(wb, rest...);
}
void encrypt_all(WBAES &) {}   // 终止
template <typename... Rest>
void decrypt_all(WBAES &wb, uint8_t *first, Rest... rest) {
    wb.decrypt(first, first);
    decrypt_all(wb, rest...);
}
void decrypt_all(WBAES &) {}

// ---------- 模板特化: 不同大小块 ----------
template <size_t N>
struct Block {
    uint8_t data[N];
    void encryptWith(WBAES &wb) {
        for (size_t i = 0; i < N; i += 16)
            wb.encrypt(data + i, data + i);
    }
    void decryptWith(WBAES &wb) {
        for (size_t i = 0; i < N; i += 16)
            wb.decrypt(data + i, data + i);
    }
};
template <> void Block<16>::encryptWith(WBAES &wb) { wb.encrypt(data, data); }   // 特化
template <> void Block<16>::decryptWith(WBAES &wb) { wb.decrypt(data, data); }

// ---------- 运算符重载 + RAII ----------
class ScopedDecrypt {
    WBAES &wb_;
    uint8_t *data_;
    uint8_t backup_[16];
public:
    ScopedDecrypt(WBAES &wb, uint8_t *data) : wb_(wb), data_(data) {
        wb_.encrypt(data_, backup_);        // 进入作用域: 加密
    }
    uint8_t &operator[](size_t i) { return data_[i]; }
    ~ScopedDecrypt() {                      // 离开作用域: 解密 (RAII)
        uint8_t tmp[16];
        wb_.decrypt(backup_, tmp);
        memcpy(data_, tmp, 16);
    }
};

int main() {
    static AESOps ops;   // 704KB 表 — 必须静态/堆, 栈会溢出
    ops.selfcheck();
    int fails = 0;

    // 1. CRTP + 运算符重载
    uint8_t d1[16];
    for (int i = 0; i < 16; i++) d1[i] = i;
    ops.process(d1);
    ops.undo(d1);
    for (int i = 0; i < 16; i++) if (d1[i] != i) { fails++; break; }
    printf("[C++ CRTP+RAII] %s\n", fails == 0 ? "PASS" : "FAIL");

    // 2. 变参模板 (3 块)
    uint8_t a[16], b[16], c[16];
    for (int i = 0; i < 16; i++) { a[i] = i; b[i] = i * 5; c[i] = i * 11; }
    encrypt_all(ops.wb, a, b, c);
    decrypt_all(ops.wb, a, b, c);
    bool ok = true;
    for (int i = 0; i < 16; i++) if (a[i] != i || b[i] != i*5 || c[i] != i*11) ok = false;
    if (!ok) fails++;
    printf("[C++ vararg-tpl] %s\n", ok ? "PASS" : "FAIL");

    // 3. 模板特化
    Block<16> small;
    Block<64> big;
    for (int i = 0; i < 16; i++) small.data[i] = i * 3;
    for (int i = 0; i < 64; i++) big.data[i] = i * 2;
    small.encryptWith(ops.wb);
    big.encryptWith(ops.wb);
    small.decryptWith(ops.wb);
    big.decryptWith(ops.wb);
    ok = true;
    for (int i = 0; i < 16; i++) if (small.data[i] != (uint8_t)(i*3)) ok = false;
    for (int i = 0; i < 64; i++) if (big.data[i] != (uint8_t)(i*2)) ok = false;
    if (!ok) fails++;
    printf("[C++ tpl-spec] %s\n", ok ? "PASS" : "FAIL");

    // 4. RAII + 异常
    uint8_t secret[16];
    for (int i = 0; i < 16; i++) secret[i] = i * 9;
    {
        ScopedDecrypt sd(ops.wb, secret);
        try {
            if (sd[0] == 0) throw std::runtime_error("test");
            sd[0] = 0xFF;
        } catch (...) {}
    }
    ok = true;
    for (int i = 0; i < 16; i++) if (secret[i] != (uint8_t)(i*9)) ok = false;
    if (!ok) fails++;
    printf("[C++ RAII-throw] %s\n", ok ? "PASS" : "FAIL");

    // 5. 标准向量 (在 pwb 之前 — 排除 TLS 全局覆盖)
    {
        fprintf(stderr, "tampered=0x%x\n", wbaes_key::g_key_tampered);
        uint8_t tv[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                          0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
        uint8_t tvo[16];
        ops.wb.encrypt(tv, tvo);
        printf("[std-vector] %s\n",
               memcmp(tvo, "\xde\x23\x99\x2a\xa3\xc7\x42\x7f\x3a\xd4\x0f\xda\x83\x73\x0d\x07", 16)==0 ? "PASS" : "FAIL");
        if (memcmp(tvo, "\x05\x0b\x02\xb8", 4)!=0) fails++;
    }

    // 6. lambda + std::function
    WBAES *wbptr = &ops.wb;
    std::function<void(uint8_t *)> enc_fn = [wbptr](uint8_t *d) { wbptr->encrypt(d, d); };
    std::function<void(uint8_t *)> dec_fn = [wbptr](uint8_t *d) { wbptr->decrypt(d, d); };
    for (int i = 0; i < 16; i++) d1[i] = i * 13;
    enc_fn(d1);
    dec_fn(d1);
    ok = true;
    for (int i = 0; i < 16; i++) if (d1[i] != (uint8_t)(i*13)) ok = false;
    if (!ok) fails++;
    printf("[C++ lambda] %s\n", ok ? "PASS" : "FAIL");

    // 7. STL (pwb — 独立实例, 最后 — TLS 全局覆盖不影响前面已完成测试)
    std::map<std::string, std::vector<uint8_t>> vault;
    vault["k1"] = std::vector<uint8_t>(16, 0x11);
    vault["k2"] = std::vector<uint8_t>(16, 0x22);
    auto pwb = std::make_unique<WBAES>();
    pwb->init();
    for (auto &[k, v] : vault)
        for (size_t i = 0; i < v.size(); i += 16)
            pwb->encrypt(v.data() + i, v.data() + i);
    for (auto &[k, v] : vault)
        for (size_t i = 0; i < v.size(); i += 16)
            pwb->decrypt(v.data() + i, v.data() + i);
    ok = true;
    for (auto &byte : vault["k1"]) if (byte != 0x11) ok = false;
    for (auto &byte : vault["k2"]) if (byte != 0x22) ok = false;
    if (!ok) fails++;
    printf("[C++ STL-map] %s\n", ok ? "PASS" : "FAIL");

    return fails ? 1 : 0;
}
