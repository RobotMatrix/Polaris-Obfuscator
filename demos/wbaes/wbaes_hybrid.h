#pragma once
#include <cstdint>

// 中间轮表：加密 8 轮，解密 9 轮。
// 8 个槽全部执行（Dummy Shuffling 在前）。每条份额是 32 字的小程序，不是成对异或。
static const int HY_ENC_ROUNDS = 8;
static const int HY_DEC_ROUNDS = 9;
static const int HY_SLOTS = 8;
static const int HY_IDS = 512;
static const int HY_PROG = 32;
static const int HY_POOL_N = HY_IDS * HY_PROG;

inline int hy_share_id(int id) {
    return (id * 77 + 13) & (HY_IDS - 1);
}
inline uint32_t hy_env_mix(int pagesize, int ncpu, int cls) {
    return (uint32_t)pagesize ^ ((uint32_t)ncpu << 16) ^ ((uint32_t)cls * 0x01000193u) ^ 0xA5C31E87u;
}
inline int hy_real_slot(uint32_t env) {
    uint32_t x = env * 0x9E3779B1u;
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    return (int)(x & (HY_SLOTS - 1));
}
inline uint32_t hy_step(uint32_t acc, uint32_t op, uint32_t imm) {
    unsigned n = imm & 31u;
    switch (op & 7u) {
    case 0: return acc ^ imm;
    case 1: return acc + imm;
    case 2: return n ? ((acc << n) | (acc >> (32u - n))) : acc;
    case 3: return acc * (imm | 1u);
    case 4: return acc ^ (acc >> ((imm & 15u) + 1u));
    case 5: return ~acc ^ imm;
    case 6: return (acc ^ imm) + (acc << 1);
    default: return acc ^ (imm * 0x9E3779B1u);
    }
}
inline int hy_id(int slot, int which, int byte, int sh) {
    return ((slot * 2 + which) * 16 + byte) * 2 + sh;
}

inline uint8_t hy_s4(uint8_t x) {
    static const uint8_t S[16] = {
        0x6, 0xB, 0x5, 0xC, 0x1, 0xF, 0x0, 0xE, 0x9, 0x2, 0x7, 0xD, 0xA, 0x4, 0x3, 0x8};
    return S[x & 15];
}
inline uint8_t hy_nl(uint8_t z) {
    uint8_t hi = (uint8_t)(z >> 4), lo = (uint8_t)(z & 15);
    lo = (uint8_t)(lo ^ hy_s4(hi));
    hi = (uint8_t)(hi ^ hy_s4(lo));
    lo = (uint8_t)(lo ^ hy_s4(hi));
    return (uint8_t)((hi << 4) | lo);
}

inline uint32_t hy_enc_at(const uint32_t *t, int round, int row, int col, int z) {
    return t[(((round * 4 + row) * 4 + col) << 8) | (z & 255)];
}
inline uint32_t hy_dec_at(const uint32_t *t, int round, int row, int col, int z) {
    return t[(((round * 4 + row) * 4 + col) << 8) | (z & 255)];
}

inline uint8_t hy_share_byte(const uint32_t *pool, int id, uint32_t env) {
    const uint32_t *sl = pool + (size_t)hy_share_id(id) * HY_PROG;
    uint32_t acc = env ^ 0xA5C31E87u;
    for (int i = 0; i < 15; i++) acc = hy_step(acc, sl[i], sl[16 + i]);
    acc ^= sl[31];
    return (uint8_t)(acc >> 24);
}
