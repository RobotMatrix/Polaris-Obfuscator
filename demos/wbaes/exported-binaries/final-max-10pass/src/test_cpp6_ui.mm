// test_cpp6_ui.mm — C++ v6 测试 (STL/智能指针/工厂/线程池/异常/variant) + UIKit 结果页
#import <UIKit/UIKit.h>
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
#include <variant>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

static char g_results[8192];

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
class Pipeline {
    std::vector<std::shared_ptr<CryptoBase>> nodes_;
public:
    void add(std::shared_ptr<CryptoBase> n) { nodes_.push_back(n); }
    void run(uint8_t *d) { for (auto &n : nodes_) n->transform(d); }
};
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
struct CryptoError : std::runtime_error { using std::runtime_error::runtime_error; };
class ScopedKey {
    WBAES &wb_;
public:
    explicit ScopedKey(WBAES &wb) : wb_(wb) {}
    void require(bool cond, const char *msg) { if (!cond) throw CryptoError(msg); }
};

static WBAES *g_wbp = nullptr;
static void run_all_tests(void) {
    static WBAES wb;
    wb.init();
    g_wbp = &wb;
    int fails = 0;
    char line[160];
    #define CHECK(name, okval) do { \
        snprintf(line, sizeof(line), "[C++6 %s] %s\n", name, (okval) ? "PASS" : "FAIL"); \
        strcat(g_results, line); if (!(okval)) fails++; } while(0)

    // 1. STL nested
    {
        std::map<std::string, std::vector<std::array<uint8_t,16>>> vault;
        const char *users[] = {"alice", "bob", "carol"};
        uint8_t plain[3][3][16];
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
        CHECK("stl-nested-map-vec", ok);
    }

    // 2. smartptr
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0x10 + i);
        uint8_t orig[16]; memcpy(orig, d, 16);
        Pipeline p;
        auto enc1 = std::make_shared<EncryptNode>(&wb);
        auto enc2 = std::make_shared<EncryptNode>(&wb);
        auto dec1 = std::make_shared<DecryptNode>(&wb);
        auto dec2 = std::make_shared<DecryptNode>(&wb);
        p.add(enc1); p.add(enc2); p.add(dec1); p.add(dec2);
        p.run(d);
        int ok = memcmp(d, orig, 16) == 0;
        std::weak_ptr<CryptoBase> weak = enc1;
        ok = ok && !weak.expired() && weak.lock() == enc1;
        enc1.reset();
        ok = ok && !weak.expired();
        CHECK("smartptr-chain", ok);
    }

    // 3. factory
    {
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
        CHECK("factory-registry", ok);
    }

    // 4. threadpool
    {
        constexpr int N = 200, NT = 8;
        static uint8_t plain[N][16], data[N][16];
        std::atomic<int> done{0};
        {
            ThreadPool pool(NT);
            for (int i = 0; i < N; i++) {
                for (int j = 0; j < 16; j++) plain[i][j] = data[i][j] = (uint8_t)(i + j);
                pool.post([&done, i] {
                    g_wbp->encrypt(data[i], data[i]);
                    done++;
                });
            }
        }
        int ok = (done == N);
        for (int i = 0; i < N && ok; i++) {
            wb.decrypt(data[i], data[i]);
            if (memcmp(data[i], plain[i], 16) != 0) ok = 0;
        }
        CHECK("threadpool-8t", ok);
    }

    // 5. exception
    {
        int ok = 1;
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = (uint8_t)(0xF0 - i);
        uint8_t orig[16]; memcpy(orig, d, 16);
        try {
            ScopedKey sk(wb);
            sk.require(true, "ok");
            wb.encrypt(d, d);
            wb.decrypt(d, d);
            ok = ok && (memcmp(d, orig, 16) == 0);
        } catch (...) { ok = 0; }
        int caught = 0;
        try {
            ScopedKey sk(wb);
            wb.encrypt(d, d);
            sk.require(false, "boom");
            wb.decrypt(d, d);
        } catch (const CryptoError &e) {
            caught = (strcmp(e.what(), "boom") == 0);
        } catch (...) {}
        ok = ok && caught;
        wb.decrypt(d, d);
        ok = ok && (memcmp(d, orig, 16) == 0);
        CHECK("exception-raii", ok);
    }

    // 6. variant
    {
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
        }, cmd);
        ok = ok && (memcmp(d, orig, 16) != 0);
        cmd = &dn;
        std::visit([&](auto &&arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, DecryptNode*>) arg->transform(d);
        }, cmd);
        ok = ok && (memcmp(d, orig, 16) == 0);
        cmd = 42;
        int unchanged = 1;
        std::visit([&](auto &&arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, int>) unchanged = (arg == 42);
        }, cmd);
        ok = ok && unchanged;
        CHECK("variant-visit", ok);
    }

    #undef CHECK
    char tail[96];
    snprintf(tail, sizeof(tail), "\n=== C++6 %s (%d fails) ===", fails ? "FAIL" : "ALL PASS", fails);
    strcat(g_results, tail);
}

@interface CPP6ViewController : UIViewController
@property (strong, nonatomic) UITextView *resultView;
@end
@implementation CPP6ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, 340, 40)];
    title.text = @"WBAES C++ v6 — STL/并发/模式测试";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:18];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    self.resultView = [[UITextView alloc] initWithFrame:CGRectMake(10, 110, 355, 700)];
    self.resultView.textColor = [UIColor lightGrayColor];
    self.resultView.backgroundColor = [UIColor darkGrayColor];
    self.resultView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    self.resultView.editable = NO;
    self.resultView.text = @"running...";
    [self.view addSubview:self.resultView];

    g_results[0] = 0;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        run_all_tests();
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *text = [NSString stringWithUTF8String:g_results];
            self.resultView.text = text;
            self.resultView.textColor = strstr(g_results, "FAIL") ? [UIColor redColor] : [UIColor greenColor];
        });
    });
}
@end

@interface CPP6AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation CPP6AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[CPP6ViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([CPP6AppDelegate class]));
    }
}
