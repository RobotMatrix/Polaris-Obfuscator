// test_c6_ui.mm — C v6 测试 (多文件项目) + UIKit 结果页
#import <UIKit/UIKit.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

extern "C" {
#include "c_project/hashtable.h"
#include "c_project/crc32.h"
#include "c_project/base64.h"
#include "c_project/bignum.h"
}

#define WBAES_NO_MAIN 1
#define WBAES_BAKED 1   // 发布路径: 十轮全表 (kHyTab, iPhone8 env 16384/6/128), 无 S 盒/无轮密钥异或
#include "demo_wbaes.cpp"
#undef WBAES_NO_MAIN
#undef WBAES_BAKED

static char g_results[8192];
static WBAES g_wb;

// ===== 双向链表 =====
typedef struct DListNode {
    struct DListNode *prev, *next;
    uint8_t data[16];
    uint32_t crc;
} DListNode;
static DListNode *list_push(DListNode *tail, const uint8_t *data) {
    DListNode *n = (DListNode *)calloc(1, sizeof(*n));
    memcpy(n->data, data, 16);
    n->crc = crc32(data, 16);
    if (tail) { tail->next = n; n->prev = tail; }
    return n;
}

static void run_all_tests(void) {
    g_wb.init();
    int fails = 0;
    int ok;
    char line[160];

    // 0. DEBUG: 固定向量自检上屏 (定位真机 UI 上下文失败用, 排查后删除)
    {
        uint8_t pt[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                          0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
        uint8_t ct_exp[16] = {0xde,0x23,0x99,0x2a,0xa3,0xc7,0x42,0x7f,
                              0x3a,0xd4,0x0f,0xda,0x83,0x73,0x0d,0x07};
        uint8_t ct1[16], ct2[16], rt[16];
        g_wb.encrypt(pt, ct1);
        g_wb.encrypt(pt, ct2);
        g_wb.decrypt(ct1, rt);
        snprintf(line, sizeof(line),
                 "[DBG] v=%s rt=%s det=%d ready=%d psn=%08x env=%08x ct=%02x%02x%02x%02x\n",
                 memcmp(ct1, ct_exp, 16) == 0 ? "P" : "F",
                 memcmp(rt, pt, 16) == 0 ? "P" : "F",
                 memcmp(ct1, ct2, 16) == 0,
                 g_s5_ready, g_poison, g_env,
                 ct1[0], ct1[1], ct1[2], ct1[3]);
        strcat(g_results, line);
    }

    // 1. hashtable
    {
        struct Hashtable *ht = ht_create();
        const char *keys[] = {"alpha", "beta", "gamma", "delta", "session_key", "iv_2026"};
        uint8_t plain[6][16], enc[6][16], dec[6][16];
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 16; j++) plain[i][j] = (uint8_t)(i * 31 + j);
            g_wb.encrypt(plain[i], enc[i]);
            ht_set(ht, keys[i], enc[i]);
        }
        ok = (ht_count(ht) == 6);
        for (int i = 0; i < 6; i++) {
            uint8_t *v = ht_get(ht, keys[i]);
            if (!v || memcmp(v, enc[i], 16) != 0) ok = 0;
            else { g_wb.decrypt(v, dec[i]); if (memcmp(dec[i], plain[i], 16) != 0) ok = 0; }
        }
        ok = ok && (ht_del(ht, "alpha") == 1) && (ht_count(ht) == 5);
        uint8_t over[16] = {0xEE};
        g_wb.encrypt(over, over);
        ht_set(ht, "beta", over);
        ok = ok && (memcmp(ht_get(ht, "beta"), over, 16) == 0);
        ht_free(ht);
        snprintf(line, sizeof(line), "[C6 hashtable-enc] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 2. bignum
    {
        uint8_t ab[32], bb[32];
        for (int i = 0; i < 32; i++) { ab[i] = i * 7 + 1; bb[i] = 0xA5 ^ i; }
        struct BigNum a, b, x;
        bn_from_bytes(&a, ab); bn_from_bytes(&b, bb);
        bn_xor(&x, &a, &b);
        uint8_t xb[32]; bn_to_bytes(&x, xb);
        uint8_t enc[32], dec[32];
        g_wb.encrypt(xb, enc); g_wb.encrypt(xb+16, enc+16);
        g_wb.decrypt(enc, dec); g_wb.decrypt(enc+16, dec+16);
        struct BigNum x2;
        bn_from_bytes(&x2, dec);
        struct BigNum back;
        bn_xor(&back, &x2, &b);
        ok = bn_cmp(&back, &a) == 0;
        ok = ok && !bn_is_zero(&x);
        bn_add_word(&a, 1);
        ok = ok && (bn_cmp(&a, &back) == 1);
        snprintf(line, sizeof(line), "[C6 bignum-xor] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 3. base64
    {
        uint8_t pt[20], enc[20], dec[20];
        for (int i = 0; i < 20; i++) pt[i] = (uint8_t)(0xC0 + i);
        g_wb.encrypt(pt, enc);
        char b64[64];
        b64_encode(enc, 16, b64);
        uint8_t back[48];
        size_t m = b64_decode(b64, back);
        ok = (m == 16) && (memcmp(back, enc, 16) == 0);
        g_wb.decrypt(back, dec);
        ok = ok && (memcmp(dec, pt, 16) == 0);
        b64_encode(pt, 20, b64);
        m = b64_decode(b64, back);
        ok = ok && (m == 20) && (memcmp(back, pt, 20) == 0);
        snprintf(line, sizeof(line), "[C6 base64-roundtrip] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 4. crc32
    {
        uint8_t data[64];
        for (int i = 0; i < 64; i++) data[i] = (uint8_t)(i * 3 + 11);
        uint32_t crc_plain = crc32(data, 64);
        for (int i = 0; i < 4; i++) g_wb.encrypt(data + i*16, data + i*16);
        uint32_t crc_enc = crc32(data, 64);
        for (int i = 0; i < 4; i++) g_wb.decrypt(data + i*16, data + i*16);
        uint32_t crc_back = crc32(data, 64);
        ok = (crc_plain == crc_back) && (crc_plain != crc_enc);
        snprintf(line, sizeof(line), "[C6 crc32-integrity] %s (%08x)\n", ok ? "PASS" : "FAIL", crc_plain);
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 5. dlist
    {
        DListNode *head = NULL, *tail = NULL;
        uint8_t plain[5][16];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 16; j++) plain[i][j] = (uint8_t)(i * 100 + j);
            tail = list_push(tail, plain[i]);
            if (!head) head = tail;
            g_wb.encrypt(tail->data, tail->data);
        }
        ok = 1;
        int i = 0;
        for (DListNode *n = head; n; n = n->next, i++) {
            uint8_t dec[16];
            g_wb.decrypt(n->data, dec);
            if (memcmp(dec, plain[i], 16) != 0) ok = 0;
            if (crc32(dec, 16) != n->crc) ok = 0;
        }
        ok = ok && (i == 5);
        i = 4;
        for (DListNode *n = tail; n; n = n->prev, i--) {
            uint8_t dec[16];
            g_wb.decrypt(n->data, dec);
            if (memcmp(dec, plain[i], 16) != 0) ok = 0;
        }
        ok = ok && (i == -1);
        for (DListNode *n = head; n; ) { DListNode *nx = n->next; free(n); n = nx; }
        snprintf(line, sizeof(line), "[C6 dlist-enc-crc] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    snprintf(line, sizeof(line), "\n=== C6 %s (%d fails) ===", fails ? "FAIL" : "ALL PASS", fails);
    strcat(g_results, line);
}

@interface C6ViewController : UIViewController
@property (strong, nonatomic) UITextView *resultView;
@end
@implementation C6ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, 340, 40)];
    title.text = @"WBAES C v6 — 多文件项目测试";
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
    // 后台线程跑测试 (WBAES init 704KB + 计算, 避免卡主线程)
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

@interface C6AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation C6AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[C6ViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([C6AppDelegate class]));
    }
}
