// test_objcpp_ui.mm — ObjC++ UI 白盒测试 (C++ 模板/STL/异常 + ObjC 混合)
#import <UIKit/UIKit.h>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <cstring>
#include <cstdint>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

static char g_results[4096];

// C++ 模板类
template <size_t N>
struct Block {
    uint8_t data[N];
    void encryptWith(WBAES &wb) {
        for (size_t i = 0; i < N; i += 16) wb.encrypt(data + i, data + i);
    }
    void decryptWith(WBAES &wb) {
        for (size_t i = 0; i < N; i += 16) wb.decrypt(data + i, data + i);
    }
};

// C++ virtual
class VirtualCrypto {
public:
    virtual ~VirtualCrypto() = default;
    virtual NSData *transform(NSData *input) = 0;
};
class ConcreteCrypto : public VirtualCrypto {
public:
    WBAES wb_;
private:
public:
    ConcreteCrypto() { wb_.init(); }
    NSData *transform(NSData *input) override {
        uint8_t in[16], out[16];
        [input getBytes:in length:16];
        wb_.encrypt(in, out);
        return [NSData dataWithBytes:out length:16];
    }
};

// ObjC 类 (使用 C++ 成员)
@interface CryptoVaultV2 : NSObject
- (NSData *)encryptData:(NSData *)data;
- (NSData *)decryptData:(NSData *)data;
@end
@implementation CryptoVaultV2 {
    std::unique_ptr<ConcreteCrypto> crypto_;
}
- (instancetype)init {
    self = [super init];
    if (self) crypto_ = std::make_unique<ConcreteCrypto>();
    return self;
}
- (NSData *)encryptData:(NSData *)data { return crypto_->transform(data); }
- (NSData *)decryptData:(NSData *)data {
    // decrypt 需要 reverse — 用同一 wb 的 decrypt
    uint8_t in[16], out[16];
    [data getBytes:in length:16];
    crypto_->wb_.decrypt(in, out);
    return [NSData dataWithBytes:out length:16];
}
@end

@interface TestViewControllerV2 : UIViewController
@end
@implementation TestViewControllerV2

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    g_results[0] = 0;
    int fails = 0;

    static WBAES wb;   // 704KB — 必须 static (栈会溢出)
    wb.init();
    WBAES *wb_ptr = &wb;   // lambda 捕获指针 (static 不能按引用捕获)

    // C++ CRTP
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        wb.encrypt(d, d);
        wb.decrypt(d, d);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = 0;
        char line[128];
        snprintf(line, sizeof(line), "C++ encrypt/decrypt: %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // C++ Block<64>
    {
        Block<64> blk;
        for (int i = 0; i < 64; i++) blk.data[i] = i;
        blk.encryptWith(wb);
        blk.decryptWith(wb);
        int ok = 1;
        for (int i = 0; i < 64; i++) if (blk.data[i] != i) ok = 0;
        char line[128];
        snprintf(line, sizeof(line), "C++ Block<64>: %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // C++ STL vector
    {
        std::vector<uint8_t> vec(16);
        for (int i = 0; i < 16; i++) vec[i] = i * 3;
        for (size_t i = 0; i < vec.size(); i += 16)
            wb.encrypt(vec.data() + i, vec.data() + i);
        for (size_t i = 0; i < vec.size(); i += 16)
            wb.decrypt(vec.data() + i, vec.data() + i);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (vec[i] != (uint8_t)(i*3)) ok = 0;
        char line[128];
        snprintf(line, sizeof(line), "C++ STL-vector: %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // C++ virtual + ObjC
    {
        CryptoVaultV2 *vault = [[CryptoVaultV2 alloc] init];
        uint8_t pt[16];
        for (int i = 0; i < 16; i++) pt[i] = i;
        NSData *ptData = [NSData dataWithBytes:pt length:16];
        NSData *ct = [vault encryptData:ptData];
        NSData *rt = [vault decryptData:ct];
        BOOL ok = memcmp(rt.bytes, pt, 16) == 0;
        char line[128];
        snprintf(line, sizeof(line), "ObjC++ virtual: %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // C++ lambda
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i * 13;
        auto enc = [wb_ptr](uint8_t *x) { wb_ptr->encrypt(x, x); };
        auto dec = [wb_ptr](uint8_t *x) { wb_ptr->decrypt(x, x); };
        enc(d); dec(d);
        int ok = 1;
        for (int i = 0; i < 16; i++) if (d[i] != (uint8_t)(i*13)) ok = 0;
        char line[128];
        snprintf(line, sizeof(line), "C++ lambda: %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 总结
    {
        char line[128];
        snprintf(line, sizeof(line), "\n=== %s (%d fails) ===\n", fails ? "FAIL" : "ALL PASS", fails);
        strcat(g_results, line);
    }

    // UI
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, 340, 40)];
    title.text = @"WBAES ObjC++ Test";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:18];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    UITextView *resultView = [[UITextView alloc] initWithFrame:CGRectMake(10, 110, 355, 700)];
    resultView.textColor = [UIColor greenColor];
    resultView.backgroundColor = [UIColor darkGrayColor];
    resultView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    resultView.editable = NO;
    resultView.text = [NSString stringWithUTF8String:g_results];
    [self.view addSubview:resultView];
}

@end

@interface AppDelegateV2 : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation AppDelegateV2
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[TestViewControllerV2 alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegateV2 class]));
    }
}
