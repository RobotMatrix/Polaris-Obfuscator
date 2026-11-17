#pragma once
#include <cstdint>
static inline uint32_t hy_mask_seed(const uint8_t k[16]) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++) { h ^= k[i]; h *= 16777619u; }
    return h ? h : 0x9E3779B9u;
}
static inline uint8_t hy_mask_next(uint32_t *s) {
    uint32_t x = *s; x ^= x << 13; x ^= x >> 17; x ^= x << 5; *s = x;
    return (uint8_t)(x >> 24);
}
