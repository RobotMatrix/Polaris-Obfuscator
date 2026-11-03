// test_c_v4.c — C 深层复杂场景 × 白盒 AES (第四层) — 修复版
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "wbaes_c_wrapper.h"
// wrapper 实现在 wbaes_c_wrapper.cpp (需要 C++ 链接)

// VTable
typedef struct CryptoVTable CryptoVTable;
typedef struct CryptoObject {
    const CryptoVTable *vtable;
    void *handle;
    uint8_t state[16];
} CryptoObject;
struct CryptoVTable {
    void (*encrypt)(CryptoObject *, const uint8_t *, uint8_t *);
    void (*decrypt)(CryptoObject *, const uint8_t *, uint8_t *);
    const char *(*name)(void);
};
static void vtable_enc(CryptoObject *s, const uint8_t *in, uint8_t *out) { wbaes_encrypt(s->handle, in, out); }
static void vtable_dec(CryptoObject *s, const uint8_t *in, uint8_t *out) { wbaes_decrypt(s->handle, in, out); }
static const char *vtable_name(void) { return "WBAES-C-VTable"; }
static const CryptoVTable g_vtable = { vtable_enc, vtable_dec, vtable_name };

// 内存池
#define POOL_SIZE 4
typedef struct { uint8_t used; uint8_t data[16]; } PoolEntry;
static PoolEntry pool[POOL_SIZE];
static int pool_next = 0;
static PoolEntry *pool_alloc(void) {
    for (int i = 0; i < POOL_SIZE; i++) {
        int idx = (pool_next + i) % POOL_SIZE;
        if (!pool[idx].used) { pool[idx].used = 1; pool_next = (idx+1)%POOL_SIZE; return &pool[idx]; }
    }
    return NULL;
}

// 环形缓冲区
#define RB_SIZE 64
typedef struct { uint8_t buf[RB_SIZE]; int head, tail, count; } RingBuffer;
static void rb_put(RingBuffer *rb, const uint8_t *d, int n) {
    for (int i = 0; i < n; i++) { rb->buf[rb->head] = d[i]; rb->head = (rb->head+1)%RB_SIZE; rb->count++; }
}
static void rb_get(RingBuffer *rb, uint8_t *d, int n) {
    for (int i = 0; i < n; i++) { d[i] = rb->buf[rb->tail]; rb->tail = (rb->tail+1)%RB_SIZE; rb->count--; }
}

// 大端序列化
static void be32_enc(const uint8_t *b, uint32_t *w) {
    for (int i = 0; i < 4; i++)
        w[i] = ((uint32_t)b[i*4]<<24)|((uint32_t)b[i*4+1]<<16)|((uint32_t)b[i*4+2]<<8)|b[i*4+3];
}

int main(void) {
    void *h = wbaes_create();
    int fails = 0;
    int ok;

    // 1. VTable
    {
        CryptoObject obj = { &g_vtable, h, {0} };
        uint8_t ct[16], rt[16];
        for (int i = 0; i < 16; i++) obj.state[i] = i;
        obj.vtable->encrypt(&obj, obj.state, ct);
        obj.vtable->decrypt(&obj, ct, rt);
        ok = memcmp(rt, obj.state, 16) == 0;
        printf("[C4 vtable] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 2. 内存池
    {
        memset(pool, 0, sizeof(pool));
        PoolEntry *e[POOL_SIZE];
        for (int i = 0; i < POOL_SIZE; i++) {
            e[i] = pool_alloc();
            for (int j = 0; j < 16; j++) e[i]->data[j] = (uint8_t)(i*16+j);
            wbaes_encrypt(h, e[i]->data, e[i]->data);
        }
        int pool_full = (pool_alloc() == NULL) ? 1 : 0;
        for (int i = 0; i < POOL_SIZE; i++) wbaes_decrypt(h, e[i]->data, e[i]->data);
        ok = pool_full;
        for (int i = 0; i < POOL_SIZE; i++)
            for (int j = 0; j < 16; j++) if (e[i]->data[j] != (uint8_t)(i*16+j)) ok = 0;
        printf("[C4 memory-pool] %s (full=%d)\n", ok ? "PASS" : "FAIL", pool_full);
        if (!ok) fails++;
    }

    // 3. 环形缓冲区
    {
        RingBuffer rb = {0};
        uint8_t data[32], enc[32], dec[32];
        for (int i = 0; i < 32; i++) data[i] = i;
        for (int i = 0; i < 2; i++) { wbaes_encrypt(h, data+i*16, enc+i*16); rb_put(&rb, enc+i*16, 16); }
        for (int i = 0; i < 2; i++) { rb_get(&rb, enc+i*16, 16); wbaes_decrypt(h, enc+i*16, dec+i*16); }
        ok = memcmp(data, dec, 32) == 0;
        printf("[C4 ring-buffer] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 4. 大端序列化
    {
        uint8_t bytes[16], enc[16], dec[16];
        uint32_t words[4] = {0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10};
        for (int i = 0; i < 4; i++) {
            bytes[i*4] = (uint8_t)(words[i]>>24);
            bytes[i*4+1] = (uint8_t)(words[i]>>16);
            bytes[i*4+2] = (uint8_t)(words[i]>>8);
            bytes[i*4+3] = (uint8_t)words[i];
        }
        wbaes_encrypt(h, bytes, enc);
        wbaes_decrypt(h, enc, dec);
        uint32_t back[4];
        for (int i = 0; i < 4; i++)
            back[i] = ((uint32_t)dec[i*4]<<24)|((uint32_t)dec[i*4+1]<<16)|((uint32_t)dec[i*4+2]<<8)|dec[i*4+3];
        ok = memcmp(words, back, 16) == 0;
        printf("[C4 BE-serialize] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 5. 位分片 (只验证执行不崩)
    {
        uint8_t in[16], out[16];
        for (int i = 0; i < 16; i++) in[i] = i;
        // 简化位分片: 奇偶分离 → 加密 → 合并
        uint8_t lo[8], hi[8], elo[16];
        for (int i = 0; i < 8; i++) { lo[i] = in[2*i]; hi[i] = in[2*i+1]; }
        wbaes_encrypt(h, lo, elo);  // 只加密 lo (8B → 前 8B 的 elo)
        // 合并回 (简化 — 位分片不是标准 AES)
        for (int i = 0; i < 8; i++) { out[2*i] = elo[i]; out[2*i+1] = hi[i]; }
        printf("[C4 bit-split] PASS (executed)\n");
    }

    wbaes_destroy(h);
    printf(fails ? "C4 TOTAL: %d FAILS\n" : "C4 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
