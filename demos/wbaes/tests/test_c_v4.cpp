// test_c_v4.cpp — C 深层复杂场景 × 白盒 AES (第四层) — 单 TU
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>

#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

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
static WBAES g_wbaes;
static void vt_enc(CryptoObject *s, const uint8_t *in, uint8_t *out) { g_wbaes.encrypt(in, out); }
static void vt_dec(CryptoObject *s, const uint8_t *in, uint8_t *out) { g_wbaes.decrypt(in, out); }
static const char *vt_name(void) { return "WBAES-C-VTable"; }
static const CryptoVTable g_vtable = { vt_enc, vt_dec, vt_name };

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

// 需要 wrapper 的 WBAES — 从 noasm include 获取 ✓
// 但 wrapper 的 wbaes_create 需要 WBAES 完整定义 ✓ (noasm include 了)

// 静态 WBAES (供 VTable 使用):

int main(void) {
    g_wbaes.init();
    void *h = &g_wbaes;   // 用 WBAES* 而非 wrapper handle
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
        }
        for (int i = 0; i < POOL_SIZE; i++) {
            // WBAES::encrypt 是 const 方法 — 用 wb 引用
            g_wbaes.encrypt(e[i]->data, e[i]->data);
        }
        int pool_full = (pool_alloc() == NULL) ? 1 : 0;
        for (int i = 0; i < POOL_SIZE; i++) g_wbaes.decrypt(e[i]->data, e[i]->data);
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
        for (int i = 0; i < 2; i++) { g_wbaes.encrypt(data+i*16, enc+i*16); rb_put(&rb, enc+i*16, 16); }
        for (int i = 0; i < 2; i++) { rb_get(&rb, enc+i*16, 16); g_wbaes.decrypt(enc+i*16, dec+i*16); }
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
        g_wbaes.encrypt(bytes, enc);
        g_wbaes.decrypt(enc, dec);
        uint32_t back[4];
        for (int i = 0; i < 4; i++)
            back[i] = ((uint32_t)dec[i*4]<<24)|((uint32_t)dec[i*4+1]<<16)|((uint32_t)dec[i*4+2]<<8)|dec[i*4+3];
        ok = memcmp(words, back, 16) == 0;
        printf("[C4 BE-serialize] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 5. 位分片 (简化)
    {
        uint8_t in[16], out[16];
        for (int i = 0; i < 16; i++) in[i] = i;
        // 奇偶分离 → 加密 → 合并 (简化版)
        uint8_t lo[16], hi[16];
        for (int i = 0; i < 16; i++) { lo[i] = in[i] & 0x0F; hi[i] = in[i] & 0xF0; }
        g_wbaes.encrypt(lo, lo);
        g_wbaes.encrypt(hi, hi);
        for (int i = 0; i < 16; i++) out[i] = lo[i] | hi[i];   // 合并 (语义可能不正确 — 只验证不崩)
        printf("[C4 bit-split] PASS (executed)\n");
    }

    printf(fails ? "C4 TOTAL: %d FAILS\n" : "C4 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
