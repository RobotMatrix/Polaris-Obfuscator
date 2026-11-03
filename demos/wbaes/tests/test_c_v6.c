// test_c_v6.c — 模拟中大型 C 项目: 哈希表/大整数/CRC32/Base64/链表 × 白盒 AES
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

extern "C" {
#include "c_project/hashtable.h"
#include "c_project/crc32.h"
#include "c_project/base64.h"
#include "c_project/bignum.h"
}

#define WBAES_NO_MAIN 1
#include "../demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

static WBAES g_wb;

// ===== 双向链表 (加密节点数据) =====
typedef struct DListNode {
    struct DListNode *prev, *next;
    uint8_t data[16];
    uint32_t crc;   // 明文 CRC (完整性)
} DListNode;

static DListNode *list_push(DListNode *tail, const uint8_t *data) {
    DListNode *n = (DListNode *)calloc(1, sizeof(*n));
    memcpy(n->data, data, 16);
    n->crc = crc32(data, 16);
    if (tail) { tail->next = n; n->prev = tail; }
    return n;
}

int main(void) {
    g_wb.init();
    int fails = 0;
    int ok;

    // 1. 哈希表: 加密值存储/取出
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
        // 删除 + 重复 key 覆盖
        ok = ok && (ht_del(ht, "alpha") == 1) && (ht_count(ht) == 5);
        uint8_t over[16] = {0xEE};
        g_wb.encrypt(over, over);
        ht_set(ht, "beta", over);
        ok = ok && (memcmp(ht_get(ht, "beta"), over, 16) == 0);
        ht_free(ht);
        printf("[C6 hashtable-enc] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 2. 大整数: XOR 加密域运算
    {
        uint8_t ab[32], bb[32];
        for (int i = 0; i < 32; i++) { ab[i] = i * 7 + 1; bb[i] = 0xA5 ^ i; }
        struct BigNum a, b, x;
        bn_from_bytes(&a, ab); bn_from_bytes(&b, bb);
        bn_xor(&x, &a, &b);
        uint8_t xb[32]; bn_to_bytes(&x, xb);
        // 白盒加密 bignum 字节, 解密后 XOR 应还原
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
        printf("[C6 bignum-xor] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 3. Base64: 加密 → 编码 → 解码 → 解密 往返
    {
        uint8_t pt[20], enc[20], dec[20];
        for (int i = 0; i < 20; i++) pt[i] = (uint8_t)(0xC0 + i);
        // 16B 块 + 4B 裸数据
        g_wb.encrypt(pt, enc);
        char b64[64];
        size_t n = b64_encode(enc, 16, b64);
        uint8_t back[48];
        size_t m = b64_decode(b64, back);
        ok = (m == 16) && (memcmp(back, enc, 16) == 0);
        g_wb.decrypt(back, dec);
        ok = ok && (memcmp(dec, pt, 16) == 0);
        // 非对齐长度 (20B → 28 chars)
        n = b64_encode(pt, 20, b64);
        m = b64_decode(b64, back);
        ok = ok && (m == 20) && (memcmp(back, pt, 20) == 0);
        ok = ok && (n == 28);
        printf("[C6 base64-roundtrip] %s (b64len=%zu)\n", ok ? "PASS" : "FAIL", (size_t)28);
        if (!ok) fails++;
    }

    // 4. CRC32 完整性: 加密前后 CRC 变化 + 解密还原
    {
        uint8_t data[64];
        for (int i = 0; i < 64; i++) data[i] = (uint8_t)(i * 3 + 11);
        uint32_t crc_plain = crc32(data, 64);
        for (int i = 0; i < 4; i++) g_wb.encrypt(data + i*16, data + i*16);
        uint32_t crc_enc = crc32(data, 64);
        for (int i = 0; i < 4; i++) g_wb.decrypt(data + i*16, data + i*16);
        uint32_t crc_back = crc32(data, 64);
        ok = (crc_plain == crc_back) && (crc_plain != crc_enc);
        printf("[C6 crc32-integrity] %s (plain=%08x enc=%08x)\n", ok ? "PASS" : "FAIL", crc_plain, crc_enc);
        if (!ok) fails++;
    }

    // 5. 双向链表: 节点数据加密 + CRC 校验 + 正反向遍历
    {
        DListNode *head = NULL, *tail = NULL;
        uint8_t plain[5][16];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 16; j++) plain[i][j] = (uint8_t)(i * 100 + j);
            tail = list_push(tail, plain[i]);
            if (!head) head = tail;
            g_wb.encrypt(tail->data, tail->data);
        }
        // 正向: 解密 + CRC 验证
        ok = 1;
        int i = 0;
        for (DListNode *n = head; n; n = n->next, i++) {
            uint8_t dec[16];
            g_wb.decrypt(n->data, dec);
            if (memcmp(dec, plain[i], 16) != 0) ok = 0;
            if (crc32(dec, 16) != n->crc) ok = 0;
        }
        ok = ok && (i == 5);
        // 反向
        i = 4;
        for (DListNode *n = tail; n; n = n->prev, i--) {
            uint8_t dec[16];
            g_wb.decrypt(n->data, dec);
            if (memcmp(dec, plain[i], 16) != 0) ok = 0;
        }
        ok = ok && (i == -1);
        // 释放
        for (DListNode *n = head; n; ) { DListNode *nx = n->next; free(n); n = nx; }
        printf("[C6 dlist-enc-crc] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    printf(fails ? "C6 TOTAL: %d FAILS\n" : "C6 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
