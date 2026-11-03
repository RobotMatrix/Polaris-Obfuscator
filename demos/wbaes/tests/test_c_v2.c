// test_c_v2.c — C 冷门/复杂语法 × 白盒 AES (C wrapper 版, 供 iOS 真机)
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include "wbaes_c_wrapper.h"

static void *g_handle = NULL;

// _Generic 泛型宏
#define wbaes_op(x) _Generic((x), \
    uint8_t *:  wbaes_enc_u8, \
    default:    wbaes_enc_u8 \
)(x)
static void wbaes_enc_u8(uint8_t *d) { wbaes_encrypt(g_handle, d, d); }

// 信号处理
static jmp_buf g_jmp;
static volatile sig_atomic_t g_signal_caught = 0;
static void sig_handler(int sig) { (void)sig; g_signal_caught = 1; longjmp(g_jmp, 1); }

// 计算 goto
static void dispatch_goto(uint8_t *data, int op) {
    static const void *dispatch[] = {&&op_enc, &&op_dec, &&op_double};
    goto *dispatch[op % 3];
op_enc:
    wbaes_encrypt(g_handle, data, data);
    goto done;
op_dec:
    wbaes_decrypt(g_handle, data, data);
    goto done;
op_double:
    wbaes_encrypt(g_handle, data, data);
    wbaes_encrypt(g_handle, data, data);
    goto done;
done:
    return;
}

// 函数指针
static void do_enc(uint8_t *d) { wbaes_encrypt(g_handle, d, d); }
static void do_dec(uint8_t *d) { wbaes_decrypt(g_handle, d, d); }
typedef void (*WBOp)(uint8_t *);

// 嵌套 union
struct Hdr { uint8_t tag; uint8_t len; uint16_t crc; };
struct Packet {
    union { struct Hdr s; uint32_t raw; } header;
    uint8_t payload[16];
};

// 位反转
static uint32_t bit_reverse(uint32_t v) {
    v = ((v & 0x55555555) << 1) | ((v >> 1) & 0x55555555);
    v = ((v & 0x33333333) << 2) | ((v >> 2) & 0x33333333);
    v = ((v & 0x0F0F0F0F) << 4) | ((v >> 4) & 0x0F0F0F0F);
    return ((v & 0x00FF00FF) << 8) | ((v >> 8) & 0x00FF00FF);
}

int main(void) {
    g_handle = wbaes_create();
    int fails = 0;
    int ok;

    // 1. _Generic
    uint8_t d1[16];
    for (int i = 0; i < 16; i++) d1[i] = i;
    wbaes_op(d1);
    wbaes_decrypt(g_handle, d1, d1);
    ok = 1;
    for (int i = 0; i < 16; i++) if (d1[i] != i) ok = 0;
    if (!ok) fails++;
    printf("[C2 _Generic] %s\n", ok ? "PASS" : "FAIL");

    // 2. setjmp/signal
    uint8_t d2[16];
    for (int i = 0; i < 16; i++) d2[i] = i ^ 0xFF;
    if (setjmp(g_jmp) == 0) {
        wbaes_encrypt(g_handle, d2, d2);
        signal(SIGUSR1, sig_handler);
        raise(SIGUSR1);
    } else {
        wbaes_decrypt(g_handle, d2, d2);
    }
    ok = 1;
    for (int i = 0; i < 16; i++) if (d2[i] != (uint8_t)(i^0xFF)) ok = 0;
    if (!ok) fails++;
    printf("[C2 setjmp/signal] %s (caught=%d)\n", ok ? "PASS" : "FAIL", g_signal_caught);

    // 3. 计算 goto
    uint8_t d3[16];
    for (int i = 0; i < 16; i++) d3[i] = i * 3;
    dispatch_goto(d3, 0);
    wbaes_decrypt(g_handle, d3, d3);
    ok = 1;
    for (int i = 0; i < 16; i++) if (d3[i] != (uint8_t)(i*3)) ok = 0;
    if (!ok) fails++;
    printf("[C2 computed-goto] %s\n", ok ? "PASS" : "FAIL");

    // 4. 嵌套 union
    struct Packet pkt;
    pkt.header.s.tag = 0xAB;
    pkt.header.s.len = 16;
    pkt.header.s.crc = 0x1234;
    memcpy(pkt.payload, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16);
    wbaes_encrypt(g_handle, pkt.payload, pkt.payload);
    wbaes_decrypt(g_handle, pkt.payload, pkt.payload);
    ok = (pkt.header.s.tag == 0xAB) &&
         memcmp(pkt.payload, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16) == 0;
    if (!ok) fails++;
    printf("[C2 nested-union] %s\n", ok ? "PASS" : "FAIL");

    // 5. 位反转
    uint32_t rev = bit_reverse(0xDEADBEEF);
    uint8_t d5[16];
    memcpy(d5, (uint32_t[]){rev, rev, rev, rev}, 16);
    wbaes_encrypt(g_handle, d5, d5);
    wbaes_decrypt(g_handle, d5, d5);
    uint32_t back[4];
    memcpy(back, d5, 16);
    ok = (back[0] == rev && back[3] == rev);
    if (!ok) fails++;
    printf("[C2 bit-reverse] %s (rev=%08x)\n", ok ? "PASS" : "FAIL", rev);

    // 6. 原子
    volatile int atomic_counter = 0;
    __sync_fetch_and_add(&atomic_counter, 1);
    int ac = atomic_counter;
    if (ac != 1) fails++;
    printf("[C2 atomic-sync] %s (ac=%d)\n", ac == 1 ? "PASS" : "FAIL", ac);

    // 7. 函数指针矩阵
    static const WBOp ops[2][2] = {{do_enc, do_dec}, {do_dec, do_enc}};
    uint8_t d7[16];
    for (int i = 0; i < 16; i++) d7[i] = i;
    ops[0][0](d7);
    ops[0][1](d7);
    ok = 1;
    for (int i = 0; i < 16; i++) if (d7[i] != i) ok = 0;
    if (!ok) fails++;
    printf("[C2 fn-ptr-2d] %s\n", ok ? "PASS" : "FAIL");

    wbaes_destroy(g_handle);
    printf(fails ? "C2 TOTAL: %d FAILS\n" : "C2 TOTAL: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
