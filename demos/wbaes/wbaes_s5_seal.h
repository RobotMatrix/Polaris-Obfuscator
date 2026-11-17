#pragma once
#include <cstdint>

// 16 组，每组 5 字节：mask, share0, share1, dummy, flag。共 80 字节。
// share0 ^ share1 才是密钥字节，运行时不做这个异或。
inline uint8_t wbaes_s5_stream(int i) {
    uint32_t x = 0xC3A5E791u ^ (uint32_t)i * 0x45D9F3Bu;
    x = (x ^ (x >> 16)) * 0x7FEB352Du;
    x = (x ^ (x >> 15)) * 0x846CA68Bu;
    x ^= x >> 16;
    return (uint8_t)x;
}
