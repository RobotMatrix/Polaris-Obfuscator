// test_cpp_v3.cpp — C++ 复杂使用场景 × 白盒 AES (第三层)
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <thread>
#include <mutex>
#include <vector>
#include <memory>
#include <string>
#include <algorithm>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

#include <mutex>
class ThreadSafeWBAES {
    mutable std::mutex mtx_;
    WBAES wb_;
public:
    ThreadSafeWBAES() { wb_.init(); }
    void encrypt(uint8_t *data) { std::lock_guard<std::mutex> lock(mtx_); wb_.encrypt(data, data); }
    void decrypt(uint8_t *data) { std::lock_guard<std::mutex> lock(mtx_); wb_.decrypt(data, data); }
    WBAES &wb() { return wb_; }
};

static ThreadSafeWBAES tswb;   // 704KB — static (栈会溢出)

// CRTP 多层
template <typename T>
class Base { public: void process(uint8_t *d) { static_cast<T*>(this)->impl(d); } };
template <typename T>
class Middle : public Base<T> { };
class Concrete : public Middle<Concrete> {
public:
    void impl(uint8_t *d) { tswb.encrypt(d); }
};

// Movable
class MovableCrypto {
    WBAES *wb_;
public:
    MovableCrypto(WBAES *w) : wb_(w) {}
    MovableCrypto(MovableCrypto &&o) noexcept : wb_(o.wb_) { o.wb_ = nullptr; }
    MovableCrypto &operator=(MovableCrypto &&o) noexcept { wb_=o.wb_; o.wb_=nullptr; return *this; }
    void encrypt(uint8_t *d) { if (wb_) wb_->encrypt(d, d); }
    void decrypt(uint8_t *d) { if (wb_) wb_->decrypt(d, d); }
};

// Chained
class ChainedCrypto {
    WBAES &wb_;
    uint8_t data_[16];
public:
    ChainedCrypto(WBAES &wb) : wb_(wb) { memset(data_, 0, 16); }
    ChainedCrypto &enc() { wb_.encrypt(data_, data_); return *this; }
    ChainedCrypto &dec() { wb_.decrypt(data_, data_); return *this; }
    ChainedCrypto &set(const uint8_t *d) { memcpy(data_, d, 16); return *this; }
    bool eq(const uint8_t *e) { return memcmp(data_, e, 16) == 0; }
};

// RAII
class CryptoScope {
    ThreadSafeWBAES &wb_;
    uint8_t *data_;
public:
    CryptoScope(ThreadSafeWBAES &wb, uint8_t *d) : wb_(wb), data_(d) { wb_.encrypt(data_); }
    ~CryptoScope() { wb_.decrypt(data_); }
};

int main() {
    int fails = 0;

    // 1. 多线程并发
    {
        std::vector<std::thread> threads;
        int errors[4] = {0};
        for (int t = 0; t < 4; t++) {
            threads.emplace_back([t, &errors]() {
                for (int i = 0; i < 100; i++) {
                    uint8_t data[16], backup[16];
                    for (int j = 0; j < 16; j++)
                        data[j] = (uint8_t)(t * 64 + i + j);
                    memcpy(backup, data, 16);
                    tswb.encrypt(data);
                    tswb.decrypt(data);
                    if (memcmp(data, backup, 16) != 0) errors[t]++;
                }
            });
        }
        for (auto &t : threads) t.join();
        int total = 0;
        for (int e : errors) total += e;
        printf("[C++3 thread-x4x100] %s (%d errors)\n", total == 0 ? "PASS" : "FAIL", total);
        if (total) fails++;
    }

    // 2. CRTP 多层
    {
        Concrete c;
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        c.process(d);     // 加密
        tswb.decrypt(d);  // 解密
        bool ok = true;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = false;
        printf("[C++3 CRTP-multi] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 3. RAII 链
    {
        uint8_t data[16];
        for (int i = 0; i < 16; i++) data[i] = i;
        { CryptoScope scope(tswb, data); }
        bool ok = true;
        for (int i = 0; i < 16; i++) if (data[i] != i) ok = false;
        printf("[C++3 RAII-chain] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 4. Move semantics
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i * 7;
        MovableCrypto m1(&tswb.wb());
        MovableCrypto m2 = std::move(m1);
        m2.encrypt(d); m2.decrypt(d);
        bool ok = true;
        for (int i = 0; i < 16; i++) if (d[i] != (uint8_t)(i*7)) ok = false;
        printf("[C++3 move-semantics] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 5. Operator 链式调用
    {
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i * 3;
        auto r = ChainedCrypto(tswb.wb()).set(pt).enc().dec();
        bool ok = r.eq(pt);
        printf("[C++3 operator-chain] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 6. shared_ptr
    {
        auto wb_ptr = std::make_shared<WBAES>();
        wb_ptr->init();
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i * 11;
        wb_ptr->encrypt(d, d);
        wb_ptr->decrypt(d, d);
        bool ok = true;
        for (int i = 0; i < 16; i++) if (d[i] != (uint8_t)(i*11)) ok = false;
        printf("[C++3 shared-virtual] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    printf(fails ? "C++3 TOTAL: %d FAILS\n" : "C++3 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
