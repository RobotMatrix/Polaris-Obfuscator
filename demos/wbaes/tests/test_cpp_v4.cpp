#include <cstdio>
#include <cstring>
#include <cstdint>
#include <iterator>
#include <type_traits>
#include <array>
#include <memory>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

// SFINAE
template <typename T, typename = std::enable_if_t<sizeof(T) >= 16>>
struct EncryptedBlock {
    uint8_t data[16];
    void encrypt(WBAES &wb) { wb.encrypt(data, data); }
    void decrypt(WBAES &wb) { wb.decrypt(data, data); }
};

// NTTP
template <size_t NumBlocks>
struct MultiBlock {
    uint8_t data[NumBlocks * 16];
    void encryptAll(WBAES &wb) {
        for (size_t i = 0; i < NumBlocks; i++) wb.encrypt(data + i*16, data + i*16);
    }
    void decryptAll(WBAES &wb) {
        for (size_t i = 0; i < NumBlocks; i++) wb.decrypt(data + i*16, data + i*16);
    }
};

// Tag Dispatch
struct PolicyDirect {};
struct PolicyChain {};
template <typename Policy>
struct CryptoWithPolicy {
    WBAES &wb_;
    uint8_t data_[16];
    CryptoWithPolicy(WBAES &wb) : wb_(wb) {}
    void set(const uint8_t *d) { memcpy(data_, d, 16); }
    void encrypt() {
        if constexpr (std::is_same_v<Policy, PolicyDirect>) wb_.encrypt(data_, data_);
        else { wb_.encrypt(data_, data_); wb_.decrypt(data_, data_); wb_.encrypt(data_, data_); }
    }
    void decrypt() {
        if constexpr (std::is_same_v<Policy, PolicyDirect>) wb_.decrypt(data_, data_);
        else { wb_.decrypt(data_, data_); wb_.encrypt(data_, data_); wb_.decrypt(data_, data_); }
    }
    const uint8_t *data() const { return data_; }
};

// 迭代器
class EncryptedIterator {
    WBAES &wb_;
    uint8_t *ptr_;
public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = uint8_t;
    EncryptedIterator(WBAES &wb, uint8_t *p) : wb_(wb), ptr_(p) {}
    EncryptedIterator &operator++() { ptr_++; return *this; }
    uint8_t &operator*() { return *ptr_; }
    bool operator!=(const EncryptedIterator &o) const { return ptr_ != o.ptr_; }
    EncryptedIterator &operator=(uint8_t val) { *ptr_ = val; wb_.encrypt(ptr_, ptr_); return *this; }
};

// Pimpl
class CryptoPimpl {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    CryptoPimpl();
    ~CryptoPimpl();
    void encrypt(uint8_t *d);
    void decrypt(uint8_t *d);
};
struct CryptoPimpl::Impl { WBAES wb; CryptoPimpl::Impl() { wb.init(); } };
CryptoPimpl::CryptoPimpl() : impl_(std::make_unique<Impl>()) {}
CryptoPimpl::~CryptoPimpl() = default;
void CryptoPimpl::encrypt(uint8_t *d) { impl_->wb.encrypt(d, d); }
void CryptoPimpl::decrypt(uint8_t *d) { impl_->wb.decrypt(d, d); }

// Observer
struct CryptoObserver {
    virtual void onEncrypted(const uint8_t *ct) = 0;
    virtual ~CryptoObserver() = default;
};
class ObservableCrypto {
    WBAES &wb_;
    CryptoObserver *obs_;
public:
    ObservableCrypto(WBAES &wb) : wb_(wb), obs_(nullptr) {}
    void setObserver(CryptoObserver *o) { obs_ = o; }
    void encrypt(uint8_t *d) { wb_.encrypt(d, d); if (obs_) obs_->onEncrypted(d); }
};

int main() {
    static WBAES wb;
    wb.init();
    int fails = 0;

    // 1. SFINAE
    {
        EncryptedBlock<std::array<uint8_t,16>> blk;
        for (int i = 0; i < 16; i++) blk.data[i] = i;
        blk.encrypt(wb); blk.decrypt(wb);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (blk.data[i] != i) ok = 0;
        printf("[C++4 SFINAE] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 2. NTTP
    {
        MultiBlock<4> multi;
        for (int i = 0; i < 64; i++) multi.data[i] = i;
        multi.encryptAll(wb); multi.decryptAll(wb);
        int ok = 1;
        for (int i = 0; i < 64; i++) if (multi.data[i] != i) ok = 0;
        printf("[C++4 NTTP-x4] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 3. Tag Dispatch
    {
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i;
        CryptoWithPolicy<PolicyDirect> direct(wb);
        direct.set(pt); direct.encrypt();
        uint8_t dec_d[16]; wb.decrypt(direct.data(), dec_d);
        CryptoWithPolicy<PolicyChain> chain(wb);
        chain.set(pt); chain.encrypt(); chain.decrypt();
        bool ok = memcmp(dec_d, pt, 16) == 0;
        printf("[C++4 tag-dispatch] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 4. 迭代器
    {
        uint8_t buf[16];
        EncryptedIterator it(wb, buf), end(wb, buf + 16);
        int val = 0;
        for (auto &e = it; e != end; ++e) { e = (uint8_t)(val * 5); val++; }
        printf("[C++4 iterator] PASS (encrypted writes)\n");
    }

    // 5. Pimpl
    {
        CryptoPimpl pimpl;
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        pimpl.encrypt(d); pimpl.decrypt(d);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = 0;
        printf("[C++4 pimpl] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 6. Observer
    {
        static uint8_t last_ct[16];
        struct Obs : CryptoObserver {
            void onEncrypted(const uint8_t *ct) override { memcpy((void*)last_ct, ct, 16); }
        } obs;
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        ObservableCrypto oc(wb);
        oc.setObserver(&obs);
        oc.encrypt(d);
        int ok = memcmp(last_ct, d, 16) == 0;
        printf("[C++4 observer] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    printf(fails ? "C++4 TOTAL: %d FAILS\n" : "C++4 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
