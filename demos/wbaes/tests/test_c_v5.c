// test_c_v5.c — C 宏/对齐/枚举位标志/序列化 × 白盒 AES (第五层)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "wbaes_c_wrapper.h"

// ===== 宏函数生成加密代码 =====
#define WBAES_ENC_DEC(name, operation) \
    static void name(void *h, uint8_t *d) { operation(h, d, d); }
WBAES_ENC_DEC(my_encrypt, wbaes_encrypt)
WBAES_ENC_DEC(my_decrypt, wbaes_decrypt)

// ===== 静态断言 (C11) =====
_Static_assert(sizeof(uint32_t) == 4, "uint32_t must be 4 bytes");
_Static_assert(16 % 16 == 0, "block size must be multiple of 16");

// ===== 对齐控制 =====
_Alignas(64) static uint8_t aligned_buf[64];

// ===== 枚举位标志 =====
enum CryptoFlags {
    CF_NONE       = 0,
    CF_ENCRYPT    = 1 << 0,
    CF_DECRYPT    = 1 << 1,
    CF_CHAIN      = 1 << 2,
    CF_PIPELINE   = 1 << 3,
    CF_ALL        = CF_ENCRYPT | CF_DECRYPT | CF_CHAIN | CF_PIPELINE
};

// ===== 二进制序列化 (紧凑结构体) =====
#pragma pack(push, 1)
struct SerializedBlock {
    uint16_t magic;      // 0xWBAE → 简化
    uint8_t  version;
    uint8_t  block_idx;
    uint8_t  data[16];
    uint32_t checksum;
};
#pragma pack(pop)

// FNV-1a 校验
static uint32_t fnv1a(const uint8_t *d, size_t n) {
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < n; i++) h = (h ^ d[i]) * 0x01000193;
    return h;
}

int main(void) {
    void *h = wbaes_create();
    int fails = 0;
    int ok;

    // 1. 宏函数生成的加解密
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        my_encrypt(h, d);
        my_decrypt(h, d);
        ok = 1;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = 0;
        printf("[C5 macro-fn] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 2. 对齐缓冲区加密
    {
        for (int i = 0; i < 64; i++) aligned_buf[i] = i;
        // 加密 4 块
        for (int i = 0; i < 64; i += 16)
            wbaes_encrypt(h, aligned_buf + i, aligned_buf + i);
        // 解密
        for (int i = 0; i < 64; i += 16)
            wbaes_decrypt(h, aligned_buf + i, aligned_buf + i);
        ok = 1;
        for (int i = 0; i < 64; i++) if (aligned_buf[i] != i) ok = 0;
        printf("[C5 aligned-buf] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 3. 枚举位标志控制加密策略
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        int flags = CF_ENCRYPT | CF_CHAIN;
        if (flags & CF_ENCRYPT) wbaes_encrypt(h, d, d);
        if (flags & CF_DECRYPT) wbaes_decrypt(h, d, d);
        if (flags & CF_CHAIN) { wbaes_encrypt(h, d, d); }
        // flags = ENCRYPT|CHAIN → enc + enc = double enc → decrypt 还原需 double dec
        wbaes_decrypt(h, d, d);
        wbaes_decrypt(h, d, d);
        ok = 1;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = 0;
        printf("[C5 enum-flags] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 4. 序列化结构体 → 白盒加密 → 反序列化
    {
        struct SerializedBlock blk;
        memset(&blk, 0, sizeof(blk));
        blk.magic = 0xBBAE;
        blk.version = 2;
        blk.block_idx = 0;
        for (int i = 0; i < 16; i++) blk.data[i] = i;
        blk.checksum = fnv1a(blk.data, 16);

        // 白盒加密整个结构体 (按 16B 块)
        size_t total = sizeof(struct SerializedBlock);
        uint8_t *raw = (uint8_t *)&blk;
        for (size_t i = 0; i + 16 <= total; i += 16)
            wbaes_encrypt(h, raw + i, raw + i);
        // 解密
        for (size_t i = 0; i + 16 <= total; i += 16)
            wbaes_decrypt(h, raw + i, raw + i);
        // 验证 checksum
        ok = (fnv1a(blk.data, 16) == blk.checksum);
        printf("[C5 serialize] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 5. 白盒加密 FNV 校验 (完整性)
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        uint32_t pre_hash = fnv1a(d, 16);
        wbaes_encrypt(h, d, d);
        uint32_t enc_hash = fnv1a(d, 16);
        wbaes_decrypt(h, d, d);
        uint32_t post_hash = fnv1a(d, 16);
        ok = (pre_hash == post_hash);   // 加解密后数据不变
        int enc_diff = (enc_hash != pre_hash);   // 加密后数据确实变了
        printf("[C5 fnv-integrity] %s (changed=%d)\n", ok ? "PASS" : "FAIL", enc_diff);
        if (!ok) fails++;
    }

    wbaes_destroy(h);
    printf(fails ? "C5 TOTAL: %d FAILS\n" : "C5 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
