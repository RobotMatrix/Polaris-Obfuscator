#include <cstdio>
#include <cstring>
#include <cstdint>
#define WBAES_NO_MAIN 1
#include "demo_wbaes_noasm.cpp"
#undef WBAES_NO_MAIN

// FNV-1a
static uint32_t fnv1a(const uint8_t *d, size_t n) {
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < n; i++) h = (h ^ d[i]) * 0x01000193;
    return h;
}

// 枚举位标志
enum CryptoFlags {
    CF_NONE     = 0,
    CF_ENCRYPT  = 1 << 0,
    CF_DECRYPT  = 1 << 1,
    CF_CHAIN    = 1 << 2,
    CF_PIPELINE = 1 << 3,
};

// 对齐缓冲区
alignas(64) static uint8_t aligned_buf[64];

// 静态断言
static_assert(sizeof(uint32_t) == 4, "size check");
static_assert(16 % 16 == 0, "block check");

// 宏函数
#define WBAES_OP(name, op) \
    void name(WBAES &wb, uint8_t *d) { wb.op(d, d); }
WBAES_OP(do_encrypt, encrypt)
WBAES_OP(do_decrypt, decrypt)

int main() {
    WBAES wb; wb.init();
    int fails = 0;
    int ok;

    // 1. 宏函数
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        do_encrypt(wb, d);
        do_decrypt(wb, d);
        ok = 1;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = 0;
        printf("[C5 macro-fn] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 2. 对齐缓冲区
    {
        for (int i = 0; i < 64; i++) aligned_buf[i] = i;
        for (int i = 0; i < 64; i += 16) wb.encrypt(aligned_buf + i, aligned_buf + i);
        for (int i = 0; i < 64; i += 16) wb.decrypt(aligned_buf + i, aligned_buf + i);
        ok = 1;
        for (int i = 0; i < 64; i++) if (aligned_buf[i] != i) ok = 0;
        printf("[C5 aligned-buf] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 3. 枚举位标志
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        int flags = CF_ENCRYPT | CF_CHAIN;
        if (flags & CF_ENCRYPT) wb.encrypt(d, d);
        if (flags & CF_CHAIN) wb.encrypt(d, d);
        // enc + enc = double enc — 需要双解密
        wb.decrypt(d, d); wb.decrypt(d, d);
        ok = 1;
        for (int i = 0; i < 16; i++) if (d[i] != i) ok = 0;
        printf("[C5 enum-flags] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 4. FNV 完整性
    {
        uint8_t d[16];
        for (int i = 0; i < 16; i++) d[i] = i;
        uint32_t pre = fnv1a(d, 16);
        wb.encrypt(d, d);
        uint32_t enc_h = fnv1a(d, 16);
        wb.decrypt(d, d);
        uint32_t post = fnv1a(d, 16);
        ok = (pre == post) && (enc_h != pre);
        printf("[C5 fnv-integrity] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    // 5. 静态断言编译期
    printf("[C5 static-assert] PASS (compiled)\n");

    // 6. 序列化
    {
        struct Blk {
            uint16_t magic;
            uint8_t version;
            uint8_t idx;
            uint8_t data[16];
            uint32_t checksum;
        } blk = {};
        blk.magic = 0xBBAE; blk.version = 2; blk.idx = 0;
        for (int i = 0; i < 16; i++) blk.data[i] = i;
        blk.checksum = fnv1a(blk.data, 16);
        // 加密 data 字段
        wb.encrypt(blk.data, blk.data);
        // 解密
        wb.decrypt(blk.data, blk.data);
        // 验证 checksum
        ok = (fnv1a(blk.data, 16) == blk.checksum);
        printf("[C5 serialize] %s\n", ok ? "PASS" : "FAIL");
        if (!ok) fails++;
    }

    printf(fails ? "C5 TOTAL: %d FAILS\n" : "C5 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
