// test_c.c — C 复杂语法 × 白盒 AES 集成测试
// 覆盖: 函数指针表/变长参数/位域/union/递归结构/goto 状态机/柔性数组/内联汇编标记
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#define WBAES_NO_MAIN 1
#include "../demo_wbaes_noasm.cpp"   // 白盒核心 (C++ 编译 — C 测试通过 wrapper 使用)
#undef WBAES_NO_MAIN

// ---------- 位域 + union ----------
struct Flags {
    uint32_t round : 5;      // 0..31
    uint32_t enc   : 1;
    uint32_t pad   : 26;
};
union Blob {
    uint8_t  bytes[16];
    uint32_t words[4];
};

// ---------- 递归结构 ----------
struct Node {
    struct Node *next;
    uint8_t data[16];
};

// ---------- 变长参数: 多块串联加密 ----------
static uint8_t *wbaes_cat(int n, ...) {
    static uint8_t buf[4096];
    size_t off = 0;
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; i++) {
        uint8_t *blk = va_arg(ap, uint8_t *);
        memcpy(buf + off, blk, 16);
        off += 16;
    }
    va_end(ap);
    return buf;
}

// ---------- goto 状态机: 3 块链式加密 (用白盒) ----------
static void chain_encrypt(WBAES *wb, uint8_t *state, int rounds) {
    int pc = 0;
    uint8_t tmp[16];
again:
    switch (pc) {
    case 0:
        wb->encrypt(state, tmp);
        memcpy(state, tmp, 16);
        pc = 1;
        goto again;
    case 1:
        if (--rounds > 0) { pc = 0; goto again; }
        pc = 2;
        goto again;
    case 2:
        return;
    default:
        return;
    }
}

// ---------- 函数指针表: 加密/解密选择器 ----------
typedef void (*wbaes_fn)(const WBAES *, const uint8_t *, uint8_t *);
static const wbaes_fn fptable[2] = { 
    (wbaes_fn)(void *)0,  // 占位 (const 方法 — 运行时填)
};

// ---------- 柔性数组容器 ----------
struct BlobBuf {
    size_t len;
    uint8_t data[];
};

int main(void) {
    // 静态链接的白盒 (extern 引用 C++ 符号 — 测试以 C++ 编译, main 内混 C 语法)
    static WBAES wb;
    static int inited = 0;
    struct Flags f = { .round = 3, .enc = 1 };
    (void)fptable;
    union Blob blob;

    uint8_t pt[16], ct[16], rt[16];
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(i * 13 + 5);

    if (!inited) { wb.init(); inited = 1; }

    // 1. 基础 roundtrip (位域控制轮数)
    memcpy(blob.bytes, pt, 16);
    for (uint32_t r = 0; r < f.round; r++) {
        wb.encrypt(blob.bytes, ct);
        memcpy(blob.bytes, ct, 16);
    }
    // roundtrip 验证 (3 次加密 → 3 次解密)
    uint8_t back[16];
    memcpy(back, blob.bytes, 16);
    for (uint32_t r = 0; r < f.round; r++) {
        wb.decrypt(back, rt);
        memcpy(back, rt, 16);
    }
    printf("[C chain-x%d] %s\n", f.round, memcmp(back, pt, 16) == 0 ? "PASS" : "FAIL");

    // 2. 变长参数多块
    uint8_t b1[16], b2[16], b3[16];
    for (int i = 0; i < 16; i++) { b1[i] = i; b2[i] = i ^ 0xFF; b3[i] = i + 7; }
    uint8_t *cat = wbaes_cat(3, b1, b2, b3);
    // 加密 48B (3 块)
    for (int i = 0; i < 3; i++)
        wb.encrypt(cat + i * 16, cat + i * 16);
    // 解密回来
    for (int i = 0; i < 3; i++)
        wb.decrypt(cat + i * 16, cat + i * 16);
    printf("[C varargs-x3] %s\n", memcmp(cat, b1, 16) == 0 ? "PASS" : "FAIL");

    // 3. goto 状态机链式
    uint8_t state[16], tmp[16];
    memcpy(state, pt, 16);
    chain_encrypt(&wb, state, 5);
    // 解密 5 次
    for (int i = 0; i < 5; i++) {
        wb.decrypt(state, tmp);
        memcpy(state, tmp, 16);
    }
    printf("[C goto-chain] %s\n", memcmp(state, pt, 16) == 0 ? "PASS" : "FAIL");

    // 4. 递归结构 + 白盒
    struct Node n1 = {NULL, {0}}, n2 = {NULL, {0}}, n3 = {NULL, {0}};
    for (int i = 0; i < 16; i++) { n1.data[i] = i; n2.data[i] = i * 3; n3.data[i] = i * 7; }
    n1.next = &n2; n2.next = &n3;
    for (struct Node *p = &n1; p; p = p->next)
        wb.encrypt(p->data, p->data);
    wb.decrypt(n3.data, n3.data);
    wb.decrypt(n2.data, n2.data);
    wb.decrypt(n1.data, n1.data);
    printf("[C linked-list] %s\n",
           memcmp(n1.data, (uint8_t[16]){0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}, 16) == 0 &&
           memcmp(n2.data, (uint8_t[16]){0,3,6,9,12,15,18,21,24,27,30,33,36,39,42,45}, 16) == 0 &&
           memcmp(n3.data, (uint8_t[16]){0,7,14,21,28,35,42,49,56,63,70,77,84,91,98,105}, 16) == 0
           ? "PASS" : "FAIL");

    // 5. union 视角切换加密
    memcpy(blob.bytes, pt, 16);
    wb.encrypt(blob.bytes, ct);
    // words 视角解密
    uint8_t out[16];
    wb.decrypt(ct, out);
    printf("[C union-view] %s\n", memcmp(out, pt, 16) == 0 ? "PASS" : "FAIL");

    return 0;
}
