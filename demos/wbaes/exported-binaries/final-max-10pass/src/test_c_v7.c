// test_c_v7.c — C 深层: 函数指针状态机/4x4 矩阵/递归下降解析器/位图/二叉堆 × 白盒 AES
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define WBAES_NO_MAIN 1
#include "../demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

static WBAES g_wb;
static int fails = 0;

// ===== 1. 函数指针状态机 (协议帧处理器) =====
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
    f->state = (StateFn)st_body;
    f->pos = 0;
}
static void st_body(Fsm *f, uint8_t b) {
    if (f->pos < 16) f->buf[f->pos++] = b;
    if (f->pos >= f->len || f->pos >= 16) f->state = (StateFn)st_done, f->done = 1;
}
static void st_done(Fsm *f, uint8_t b) { (void)b; (void)f; }
static void test_fsm(void) {
    // 帧: AA 10 <16B 密文> → FSM 解析 → 解密验证
    Fsm f = { st_idle, {0}, 0, 0, 0, 0 };
    uint8_t plain[16], enc[16];
    for (int i = 0; i < 16; i++) plain[i] = (uint8_t)(i * 9 + 3);
    g_wb.encrypt(plain, enc);
    uint8_t frame[18] = { 0xAA, 16 };
    memcpy(frame + 2, enc, 16);
    for (int i = 0; i < 18; i++) f.state(&f, frame[i]);
    uint8_t dec[16];
    g_wb.decrypt(f.buf, dec);
    int ok = f.done && (f.pos == 16) && (memcmp(dec, plain, 16) == 0);
    printf("[C7 fsm-protocol] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 2. 4x4 矩阵: 行/列加密扫描 =====
static void test_matrix(void) {
    uint8_t m[4][16], backup[4][16];   // 每行一个完整 AES 块
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 16; c++) { m[r][c] = (uint8_t)(r * 16 + c); backup[r][c] = m[r][c]; }
    // 按行加密扫描
    for (int r = 0; r < 4; r++) g_wb.encrypt(m[r], m[r]);
    // 行间校验和 (密文态)
    uint32_t enc_cs = 0;
    for (int r = 0; r < 4; r++) for (int c = 0; c < 16; c++) enc_cs = enc_cs * 31 + m[r][c];
    for (int r = 0; r < 4; r++) g_wb.decrypt(m[r], m[r]);
    int ok = memcmp(m, backup, 64) == 0;
    printf("[C7 matrix4x4] %s (enc_cs=%08x)\n", ok ? "PASS" : "FAIL", enc_cs);
    if (!ok) fails++;
}

// ===== 3. 递归下降解析器: expr = number | (expr) | enc(expr) =====
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
        int r = parse_expr(p, val16, 1);   // 子表达式结果加密
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
    // number: 填充 val16
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
static void test_parser(void) {
    uint8_t v[16];
    Parser p1 = { "enc(dec(42))", 0, 0 };
    int ok = parse_expr(&p1, v, 0) && (p1.depth == 0);
    // enc(dec(42)) = 42 加密后 → 需再解密
    uint8_t chk[16];
    for (int i = 0; i < 16; i++) chk[i] = (uint8_t)(42 + i);
    ok = ok && (memcmp(v, chk, 16) != 0);   // 处于密文态
    g_wb.decrypt(v, v);
    ok = ok && (memcmp(v, chk, 16) == 0);
    // 纯数字
    Parser p2 = { "77", 0, 0 };
    uint8_t v2[16];
    ok = ok && parse_expr(&p2, v2, 0);
    for (int i = 0; i < 16 && ok; i++) if (v2[i] != (uint8_t)(77 + i)) ok = 0;
    printf("[C7 rd-parser] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 4. 位图 (bitmap) 加密标记页 =====
static void test_bitmap(void) {
    uint8_t bm[16];   // 128 页
    memset(bm, 0, 16);
    #define BM_SET(i) (bm[(i)/8] |= (1 << ((i) % 8)))
    #define BM_GET(i) (bm[(i)/8] & (1 << ((i) % 8)))
    // 页 0/7/63/64/127 加密
    int pages[] = { 0, 7, 63, 64, 127 };
    for (int k = 0; k < 5; k++) BM_SET(pages[k]);
    int ok = 1;
    for (int k = 0; k < 5; k++) ok = ok && BM_GET(pages[k]);
    // 位图本身加密存储 (16B = 1 块)
    uint8_t bm_enc[16];
    g_wb.encrypt(bm, bm_enc);
    ok = ok && (memcmp(bm, bm_enc, 16) != 0);
    uint8_t bm_back[16];
    g_wb.decrypt(bm_enc, bm_back);
    ok = ok && (memcmp(bm_back, bm, 16) == 0);
    // 位图页数据加密
    uint8_t pagebuf[16];
    for (int i = 0; i < 16; i++) pagebuf[i] = (uint8_t)(0x20 + i);
    g_wb.encrypt(pagebuf, pagebuf);
    g_wb.decrypt(pagebuf, pagebuf);
    for (int i = 0; i < 16; i++) if (pagebuf[i] != (uint8_t)(0x20 + i)) ok = 0;
    printf("[C7 bitmap-pages] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

// ===== 5. 二叉堆 (优先队列) 加密元素 =====
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
static void test_heap(void) {
    heap_n = 0;
    // prio 乱序 push 5 项 (数据各异), 按 prio pop 后数据顺序正确
    int prios[] = { 42, 7, 99, 1, 55 };
    uint8_t datas[5][16];
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 16; j++) datas[i][j] = (uint8_t)(i * 11 + j);
    for (int i = 0; i < 5; i++) heap_push(prios[i], datas[i]);
    // pop 顺序应为 prio: 1,7,42,55,99 → 数据 idx: 3,1,0,4,2
    int expect[] = { 3, 1, 0, 4, 2 };
    int ok = 1;
    for (int k = 0; k < 5; k++) {
        HeapNode n;
        if (!heap_pop(&n)) { ok = 0; break; }
        g_wb.decrypt(n.data, n.data);
        if (memcmp(n.data, datas[expect[k]], 16) != 0) { ok = 0; break; }
    }
    ok = ok && (heap_n == 0);
    printf("[C7 heap-enc] %s\n", ok ? "PASS" : "FAIL");
    if (!ok) fails++;
}

int main(void) {
    g_wb.init();
    test_fsm();
    test_matrix();
    test_parser();
    test_bitmap();
    test_heap();
    printf(fails ? "C7 TOTAL: %d FAILS\n" : "C7 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
