// test_cpp_v6.cpp — C++ 深层: STL 嵌套/智能指针/工厂+策略/线程池/异常安全 × 白盒 AES
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <stdexcept>
#include <optional>
#include <variant>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

// ===== 1. STL 嵌套容器: map<string, vector<array<uint8_t,16>>> =====
static void test_stl_nested(WBAES &wb, int &fails) {
    std::map<std::string, std::vector<std::array<uint8_t,16>>> vault;
    const char *users[] = {"alice", "bob", "carol"};
    uint8_t plain[3][3][16];   // plaintext 记录
    for (int u = 0; u < 3; u++) {
        std::vector<std::array<uint8_t,16>> blocks;
        for (int b = 0; b < 3; b++) {
            std::array<uint8_t,16> blk{};
            for (int j = 0; j < 16; j++) { plain[u][b][j] = (uint8_t)(u*50+b*10+j); blk[j] = plain[u][b][j]; }
            wb.encrypt(blk.data(), blk.data());
            blocks.push_back(blk);
        }
        vault[users[u]] = blocks;
    }
    int ok = (vault.size() == 3);
    for (int u = 0; u < 3 && ok; u++) {
        auto &blocks = vault[users[u]];
        ok = ok && (blocks.size() == 3);
        for (int b = 0; b < 3; b++) {
            uint8_t dec[16];
            wb.decrypt(blocks[b].data(), dec);
            if (memcmp(dec, plain[u][b], 16) != 0) { ok = 0; break; }
        }
    }
    printf("[C++6 stl-nested-map-vec] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 2. 智能指针链: unique_ptr<Derived> → shared_ptr<Base> → weak_ptr 观测 =====
struct CryptoBase {
    virtual ~CryptoBase() = default;
    virtual void transform(uint8_t *d) = 0;
};
struct EncryptNode : CryptoBase {
    WBAES *wb_;
    explicit EncryptNode(WBAES *w) : wb_(w) {}
    void transform(uint8_t *d) override { wb_->encrypt(d, d); }
};
struct DecryptNode : CryptoBase {
    WBAES *wb_;
    explicit DecryptNode(WBAES *w) : wb_(w) {}
    void transform(uint8_t *d) override { wb_->decrypt(d, d); }
};
// Pipeline: shared_ptr 链
class Pipeline {
    std::vector<std::shared_ptr<CryptoBase>> nodes_;
public:
    void add(std::shared_ptr<CryptoBase> n) { nodes_.push_back(n); }
    void run(uint8_t *d) { for (auto &n : nodes_) n->transform(d); }
};
static void test_smart_ptr_chain(WBAES &wb, int &fails) {
    uint8_t d[16];
    for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0x10 + i);
    uint8_t orig[16]; memcpy(orig, d, 16);

    // pipeline: enc → enc → dec → dec = identity
    Pipeline p;
    auto enc1 = std::make_shared<EncryptNode>(&wb);
    auto enc2 = std::make_shared<EncryptNode>(&wb);
    auto dec1 = std::make_shared<DecryptNode>(&wb);
    auto dec2 = std::make_shared<DecryptNode>(&wb);
    p.add(enc1); p.add(enc2); p.add(dec1); p.add(dec2);
    p.run(d);
    int ok = memcmp(d, orig, 16) == 0;

    // weak_ptr 观测 (不拥有)
    std::weak_ptr<CryptoBase> weak = enc1;
    ok = ok && !weak.expired() && weak.lock() == enc1;
    enc1.reset();
    ok = ok && !weak.expired();   // pipeline 仍持有
    printf("[C++6 smartptr-chain] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 3. 工厂 + 策略 + 单例注册表 =====
enum class Mode { ECB_Enc, ECB_Dec };
class CryptoFactory {
    std::unordered_map<int, std::function<std::shared_ptr<CryptoBase>(WBAES*)>> makers_;
    CryptoFactory() = default;
public:
    static CryptoFactory &instance() { static CryptoFactory f; return f; }
    void registerMaker(int id, std::function<std::shared_ptr<CryptoBase>(WBAES*)> f) { makers_[id] = std::move(f); }
    std::shared_ptr<CryptoBase> create(int id, WBAES *wb) {
        auto it = makers_.find(id);
        return it == makers_.end() ? nullptr : it->second(wb);
    }
};
static void test_factory(WBAES &wb, int &fails) {
    auto &f = CryptoFactory::instance();
    f.registerMaker((int)Mode::ECB_Enc, [](WBAES *w) -> std::shared_ptr<CryptoBase> {
        return std::make_shared<EncryptNode>(w); });
    f.registerMaker((int)Mode::ECB_Dec, [](WBAES *w) -> std::shared_ptr<CryptoBase> {
        return std::make_shared<DecryptNode>(w); });

    uint8_t pt[16];
    for (int i = 0; i < 16; i++) pt[i] = i;
    uint8_t orig[16]; memcpy(orig, pt, 16);

    auto enc = f.create((int)Mode::ECB_Enc, &wb);
    auto dec = f.create((int)Mode::ECB_Dec, &wb);
    int ok = enc && dec;
    if (ok) {
        enc->transform(pt);
        int ciphered = memcmp(pt, orig, 16) != 0;
        dec->transform(pt);
        ok = ciphered && memcmp(pt, orig, 16) == 0;
    }
    auto none = f.create(999, &wb);
    ok = ok && (none == nullptr);
    printf("[C++6 factory-registry] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 4. 线程池: 8 线程并发加密 200 块 =====
class ThreadPool {
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> jobs_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};
public:
    explicit ThreadPool(int n) {
        for (int i = 0; i < n; i++)
            workers_.emplace_back([this] {
                for (;;) {
                    std::function<void()> job;
                    {
                        std::unique_lock<std::mutex> lk(mu_);
                        cv_.wait(lk, [this]{ return stop_ || !jobs_.empty(); });
                        if (stop_ && jobs_.empty()) return;
                        job = std::move(jobs_.front()); jobs_.pop();
                    }
                    job();
                }
            });
    }
    ~ThreadPool() {
        { std::lock_guard<std::mutex> lk(mu_); stop_ = true; }
        cv_.notify_all();
        for (auto &t : workers_) t.join();
    }
    void post(std::function<void()> j) {
        { std::lock_guard<std::mutex> lk(mu_); jobs_.push(std::move(j)); }
        cv_.notify_one();
    }
};
static void test_thread_pool(WBAES &wb, int &fails) {
    constexpr int N = 200, NT = 8;
    static uint8_t plain[N][16], data[N][16];
    std::atomic<int> done{0};
    {
        ThreadPool pool(NT);
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < 16; j++) plain[i][j] = data[i][j] = (uint8_t)(i + j);
            pool.post([&wb, &done, i] {
                wb.encrypt(data[i], data[i]);
                done++;
            });
        }
    }   // pool 析构 → join 全部
    int ok = (done == N);
    // 全部解密验证
    for (int i = 0; i < N && ok; i++) {
        wb.decrypt(data[i], data[i]);
        if (memcmp(data[i], plain[i], 16) != 0) ok = 0;
    }
    printf("[C++6 threadpool-8t] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 5. 异常安全: RAII guard + 异常传播 =====
struct CryptoError : std::runtime_error { using std::runtime_error::runtime_error; };
class ScopedKey {
    WBAES &wb_;
    bool active_;
public:
    explicit ScopedKey(WBAES &wb) : wb_(wb), active_(true) {}
    ~ScopedKey() noexcept = default;   // WBAES 无真实释放 — 演示 RAII 形态
    void require(bool cond, const char *msg) {
        if (!cond) throw CryptoError(msg);
    }
};
static void test_exception_safety(WBAES &wb, int &fails) {
    int ok = 1;
    uint8_t d[16];
    for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0xF0 - i);
    uint8_t orig[16]; memcpy(orig, d, 16);
    // 1) 正常路径
    try {
        ScopedKey sk(wb);
        sk.require(true, "ok");
        wb.encrypt(d, d);
        wb.decrypt(d, d);
        ok = ok && (memcmp(d, orig, 16) == 0);
    } catch (...) { ok = 0; }
    // 2) 异常路径: 中途 throw, 栈展开不崩, 加密状态不变
    int caught = 0;
    try {
        ScopedKey sk(wb);
        wb.encrypt(d, d);
        sk.require(false, "boom");
        wb.decrypt(d, d);   // 不可达
    } catch (const CryptoError &e) {
        caught = (strcmp(e.what(), "boom") == 0);
    } catch (...) {}
    ok = ok && caught;
    wb.decrypt(d, d);   // 还原 (enc 已执行, dec 被跳过)
    ok = ok && (memcmp(d, orig, 16) == 0);
    printf("[C++6 exception-raii] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 6. variant + visit 分派 =====
static void test_variant(WBAES &wb, int &fails) {
    std::variant<std::monostate, EncryptNode*, DecryptNode*, int> cmd;
    uint8_t d[16];
    for (int i = 0; i < 16; i++) d[i] = i;
    uint8_t orig[16]; memcpy(orig, d, 16);
    int ok = 1;

    EncryptNode en(&wb); DecryptNode dn(&wb);
    cmd = &en;
    std::visit([&](auto &&arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, EncryptNode*>) arg->transform(d);
        else if constexpr (std::is_same_v<T, DecryptNode*>) arg->transform(d);
    }, cmd);
    ok = ok && (memcmp(d, orig, 16) != 0);   // 已加密
    cmd = &dn;
    std::visit([&](auto &&arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, DecryptNode*>) arg->transform(d);
    }, cmd);
    ok = ok && (memcmp(d, orig, 16) == 0);   // 已还原
    cmd = 42;
    int unchanged = 1;
    std::visit([&](auto &&arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, int>) unchanged = (arg == 42);
    }, cmd);
    ok = ok && unchanged;
    printf("[C++6 variant-visit] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

int main() {
    static WBAES wb;
    wb.init();
    int fails = 0;
    test_stl_nested(wb, fails);
    test_smart_ptr_chain(wb, fails);
    test_factory(wb, fails);
    test_thread_pool(wb, fails);
    test_exception_safety(wb, fails);
    test_variant(wb, fails);
    printf(fails ? "C++6 TOTAL: %d FAILS\n" : "C++6 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
