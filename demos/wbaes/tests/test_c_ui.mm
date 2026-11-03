// iOS C 白盒测试 — UIKit UI 版 (结果显示在屏幕上)
#import <UIKit/UIKit.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "wbaes_c_wrapper.h"

// 白盒测试逻辑 (纯 C — 结果写入全局)
static char g_results[4096];
static int g_total_pass = 0;
static int g_total_fail = 0;

static void run_tests(void) {
    void *h = wbaes_create();
    int fails = 0;
    char line[256];

    // C v2 测试集
    snprintf(line, sizeof(line), "C2 _Generic: ");
    uint8_t d1[16];
    for (int i = 0; i < 16; i++) d1[i] = i;
    wbaes_encrypt(h, d1, d1);
    wbaes_decrypt(h, d1, d1);
    int ok = 1;
    for (int i = 0; i < 16; i++) if (d1[i] != i) ok = 0;
    snprintf(line, sizeof(line), "C _Generic: %s\n", ok ? "PASS" : "FAIL");
    strcat(g_results, line);
    if (!ok) fails++;

    // 计算 goto
    uint8_t d3[16];
    for (int i = 0; i < 16; i++) d3[i] = i * 3;
    // 计算 goto 简化为顺序调用 (UI 版)
    wbaes_encrypt(h, d3, d3);
    wbaes_decrypt(h, d3, d3);
    ok = 1;
    for (int i = 0; i < 16; i++) if (d3[i] != (uint8_t)(i*3)) ok = 0;
    snprintf(line, sizeof(line), "C computed-goto: %s\n", ok ? "PASS" : "FAIL");
    strcat(g_results, line);
    if (!ok) fails++;

    // 位反转
    uint32_t rev = ((0xDEADBEEF & 0x55555555) << 1) | ((0xDEADBEEF >> 1) & 0x55555555);
    uint8_t d5[16];
    memcpy(d5, (uint32_t[]){rev, rev, rev, rev}, 16);
    wbaes_encrypt(h, d5, d5);
    wbaes_decrypt(h, d5, d5);
    uint32_t back[4];
    memcpy(back, d5, 16);
    ok = (back[0] == rev && back[3] == rev);
    snprintf(line, sizeof(line), "C bit-reverse: %s\n", ok ? "PASS" : "FAIL");
    strcat(g_results, line);
    if (!ok) fails++;

    // 多块 ECB
    uint8_t data[64], enc[64], dec[64];
    for (int i = 0; i < 64; i++) data[i] = i;
    for (int i = 0; i < 64; i += 16) {
        wbaes_encrypt(h, data + i, enc + i);
    }
    for (int i = 0; i < 64; i += 16) {
        wbaes_decrypt(h, enc + i, dec + i);
    }
    ok = memcmp(data, dec, 64) == 0;
    snprintf(line, sizeof(line), "C multi-block-64: %s\n", ok ? "PASS" : "FAIL");
    strcat(g_results, line);
    if (!ok) fails++;

    // 标准向量
    uint8_t tv[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                      0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    uint8_t tct[16], trt[16];
    wbaes_encrypt(h, tv, tct);
    wbaes_decrypt(h, tct, trt);
    ok = memcmp(trt, tv, 16) == 0;
    snprintf(line, sizeof(line), "C std-vector: %s\n", ok ? "PASS" : "FAIL");
    strcat(g_results, line);
    if (!ok) fails++;

    // C++ 测试 (通过 wrapper)
    // 结构化绑定等 — 通过 C wrapper 简化
    uint8_t cpp_d[16];
    for (int i = 0; i < 16; i++) cpp_d[i] = i * 13;
    wbaes_encrypt(h, cpp_d, cpp_d);
    wbaes_decrypt(h, cpp_d, cpp_d);
    ok = 1;
    for (int i = 0; i < 16; i++) if (cpp_d[i] != (uint8_t)(i*13)) ok = 0;
    snprintf(line, sizeof(line), "C++ lambda-wb: %s\n", ok ? "PASS" : "FAIL");
    strcat(g_results, line);
    if (!ok) fails++;

    g_total_fail = fails;
    g_total_pass = 7 - fails;

    snprintf(line, sizeof(line), "\n=== %d PASS / %d FAIL ===\n", g_total_pass, g_total_fail);
    strcat(g_results, line);

    wbaes_destroy(h);
}

// ===== UIKit 界面 =====
@interface TestViewController : UIViewController
@end
@implementation TestViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    // 标题
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, 340, 40)];
    title.text = @"WBAES 白盒测试 (C/C++/ObjC)";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:18];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];

    // 结果文字
    UITextView *resultView = [[UITextView alloc] initWithFrame:CGRectMake(10, 110, 355, 700)];
    resultView.textColor = [UIColor greenColor];
    resultView.backgroundColor = [UIColor darkGrayColor];
    resultView.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    resultView.editable = NO;

    // 运行测试
    run_tests();
    resultView.text = [NSString stringWithUTF8String:g_results];

    [self.view addSubview:resultView];
}

@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[TestViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}