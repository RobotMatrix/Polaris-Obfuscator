// test_c7_ui.mm — C v7 测试 (FSM/矩阵/解析器/位图/堆) + UIKit 结果页
#import <UIKit/UIKit.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

#define WBAES_NO_MAIN 1
#define WBAES_BAKED 1   // 发布路径: 十轮全表 (kHyTab, iPhone8 env 16384/6/128), 无 S 盒/无轮密钥异或
#include "demo_wbaes.cpp"
#undef WBAES_NO_MAIN
#undef WBAES_BAKED

static char g_results[8192];
static WBAES g_wb;

typedef enum { ST_IDLE, ST_HDR, ST_BODY, ST_DONE, ST_ERR } FsmState;
typedef struct Fsm Fsm;
typedef void (*StateFn)(Fsm *, uint8_t byte);
struct Fsm {
    StateFn state;
    uint8_t buf[16];
    int pos, len;
    int done, err;
};
static void st_hdr(Fsm *f, uint8_t b);
static void st_body(Fsm *f, uint8_t b);
static void st_done(Fsm *f, uint8_t b);
static void st_idle(Fsm *f, uint8_t b) {
    if (b == 0xAA) { f->state = st_hdr; f->pos = 0; }
}
static void st_hdr(Fsm *f, uint8_t b) {
    f->len = b;
    f->state = st_body;
    f->pos = 0;
}
static void st_body(Fsm *f, uint8_t b) {
    if (f->pos < 16) f->buf[f->pos++] = b;
    if (f->pos >= f->len || f->pos >= 16) f->state = st_done, f->done = 1;
}
static void st_done(Fsm *f, uint8_t b) { (void)b; (void)f; }

typedef struct Parser Parser;
struct Parser { const char *s; int pos; int depth; };
static void skip_ws(Parser *p) { while (p->s[p->pos] == ' ') p->pos++; }
static int parse_expr(Parser *p, uint8_t *val16, int encrypt);
static int parse_primary(Parser *p, uint8_t *val16, int encrypt) {
    skip_ws(p);
    if (p->s[p->pos] == '(') {
        p->pos++; p->depth++;
        int r = parse_expr(p, val16, encrypt);
        skip_ws(p);
        if (p->s[p->pos] == ')') { p->pos++; p->depth--; }
        else r = 0;
        return r;
    }
    if (strncmp(p->s + p->pos, "enc(", 4) == 0) {
        p->pos += 4; p->depth++;
        int r = parse_expr(p, val16, 1);
        skip_ws(p);
        if (p->s[p->pos] == ')') { p->pos++; p->depth--; }
        else r = 0;
        return r;
    }
    if (strncmp(p->s + p->pos, "dec(", 4) == 0) {
        p->pos += 4; p->depth++;
        int r = parse_expr(p, val16, 0);
        skip_ws(p);
        if (p->s[p->pos] == ')') { p->pos++; p->depth--; }
        else r = 0;
        return r;
    }
    int v = 0, n = 0;
    while (p->s[p->pos] >= '0' && p->s[p->pos] <= '9') {
        v = v * 10 + (p->s[p->pos] - '0'); p->pos++; n++;
    }
    if (!n) return 0;
    for (int i = 0; i < 16; i++) val16[i] = (uint8_t)(v + i);
    return 1;
}
static int parse_expr(Parser *p, uint8_t *val16, int encrypt) {
    if (!parse_primary(p, val16, 0)) return 0;
    if (encrypt) g_wb.encrypt(val16, val16);
    return 1;
}

typedef struct { uint8_t data[16]; int prio; } HeapNode;
static HeapNode heap[32];
static int heap_n = 0;
static void heap_push(int prio, const uint8_t *data) {
    int i = heap_n++;
    heap[i].prio = prio;
    g_wb.encrypt(data, heap[i].data);
    while (i > 0) {
        int p = (i - 1) / 2;
        if (heap[p].prio <= heap[i].prio) break;
        HeapNode t = heap[p]; heap[p] = heap[i]; heap[i] = t;
        i = p;
    }
}
static int heap_pop(HeapNode *out) {
    if (!heap_n) return 0;
    *out = heap[0];
    heap[0] = heap[--heap_n];
    int i = 0;
    for (;;) {
        int l = 2*i+1, r = 2*i+2, m = i;
        if (l < heap_n && heap[l].prio < heap[m].prio) m = l;
        if (r < heap_n && heap[r].prio < heap[m].prio) m = r;
        if (m == i) break;
        HeapNode t = heap[m]; heap[m] = heap[i]; heap[i] = t;
        i = m;
    }
    return 1;
}

static void run_all_tests(void) {
    g_wb.init();
    int fails = 0;
    int ok;
    char line[160];

    // 1. fsm
    {
        Fsm f = { st_idle, {0}, 0, 0, 0, 0 };
        uint8_t plain[16], enc[16];
        for (int i = 0; i < 16; i++) plain[i] = (uint8_t)(i * 9 + 3);
        g_wb.encrypt(plain, enc);
        uint8_t frame[18] = { 0xAA, 16 };
        memcpy(frame + 2, enc, 16);
        for (int i = 0; i < 18; i++) f.state(&f, frame[i]);
        uint8_t dec[16];
        g_wb.decrypt(f.buf, dec);
        ok = f.done && (f.pos == 16) && (memcmp(dec, plain, 16) == 0);
        snprintf(line, sizeof(line), "[C7 fsm-protocol] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 2. matrix
    {
        uint8_t m[4][16], backup[4][16];
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 16; c++) { m[r][c] = (uint8_t)(r * 16 + c); backup[r][c] = m[r][c]; }
        for (int r = 0; r < 4; r++) g_wb.encrypt(m[r], m[r]);
        uint32_t enc_cs = 0;
        for (int r = 0; r < 4; r++) for (int c = 0; c < 16; c++) enc_cs = enc_cs * 31 + m[r][c];
        for (int r = 0; r < 4; r++) g_wb.decrypt(m[r], m[r]);
        ok = memcmp(m, backup, 64) == 0;
        snprintf(line, sizeof(line), "[C7 matrix4x4] %s (enc_cs=%08x)\n", ok ? "PASS" : "FAIL", enc_cs);
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 3. parser
    {
        uint8_t v[16];
        Parser p1 = { "enc(dec(42))", 0, 0 };
        ok = parse_expr(&p1, v, 0) && (p1.depth == 0);
        uint8_t chk[16];
        for (int i = 0; i < 16; i++) chk[i] = (uint8_t)(42 + i);
        ok = ok && (memcmp(v, chk, 16) != 0);
        g_wb.decrypt(v, v);
        ok = ok && (memcmp(v, chk, 16) == 0);
        Parser p2 = { "77", 0, 0 };
        uint8_t v2[16];
        ok = ok && parse_expr(&p2, v2, 0);
        for (int i = 0; i < 16 && ok; i++) if (v2[i] != (uint8_t)(77 + i)) ok = 0;
        snprintf(line, sizeof(line), "[C7 rd-parser] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 4. bitmap
    {
        uint8_t bm[16];
        memset(bm, 0, 16);
        #define BM_SET(i) (bm[(i)/8] |= (1 << ((i) % 8)))
        #define BM_GET(i) (bm[(i)/8] & (1 << ((i) % 8)))
        int pages[] = { 0, 7, 63, 64, 127 };
        for (int k = 0; k < 5; k++) BM_SET(pages[k]);
        ok = 1;
        for (int k = 0; k < 5; k++) ok = ok && BM_GET(pages[k]);
        uint8_t bm_enc[16];
        g_wb.encrypt(bm, bm_enc);
        ok = ok && (memcmp(bm, bm_enc, 16) != 0);
        uint8_t bm_back[16];
        g_wb.decrypt(bm_enc, bm_back);
        ok = ok && (memcmp(bm_back, bm, 16) == 0);
        uint8_t pagebuf[16];
        for (int i = 0; i < 16; i++) pagebuf[i] = (uint8_t)(0x20 + i);
        g_wb.encrypt(pagebuf, pagebuf);
        g_wb.decrypt(pagebuf, pagebuf);
        for (int i = 0; i < 16; i++) if (pagebuf[i] != (uint8_t)(0x20 + i)) ok = 0;
        snprintf(line, sizeof(line), "[C7 bitmap-pages] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    // 5. heap
    {
        heap_n = 0;
        int prios[] = { 42, 7, 99, 1, 55 };
        uint8_t datas[5][16];
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 16; j++) datas[i][j] = (uint8_t)(i * 11 + j);
        for (int i = 0; i < 5; i++) heap_push(prios[i], datas[i]);
        int expect[] = { 3, 1, 0, 4, 2 };
        ok = 1;
        for (int k = 0; k < 5; k++) {
            HeapNode n;
            if (!heap_pop(&n)) { ok = 0; break; }
            g_wb.decrypt(n.data, n.data);
            if (memcmp(n.data, datas[expect[k]], 16) != 0) { ok = 0; break; }
        }
        ok = ok && (heap_n == 0);
        snprintf(line, sizeof(line), "[C7 heap-enc] %s\n", ok ? "PASS" : "FAIL");
        strcat(g_results, line);
        if (!ok) fails++;
    }

    snprintf(line, sizeof(line), "\n=== C7 %s (%d fails) ===", fails ? "FAIL" : "ALL PASS", fails);
    strcat(g_results, line);
}

@interface C7ViewController : UIViewController
@property (strong, nonatomic) UITextView *resultView;
@end
@implementation C7ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(20, 60, 340, 40)];
    title.text = @"WBAES C v7 — 深层结构测试";
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

@interface C7AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end
@implementation C7AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    self.window.rootViewController = [[C7ViewController alloc] init];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([C7AppDelegate class]));
    }
}
