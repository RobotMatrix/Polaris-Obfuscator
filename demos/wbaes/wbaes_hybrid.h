#pragma once
#include <cstdint>
#include <cstring>

// 轮密钥只出现在表项里。运行时按列取两对字节，再取一张联合表。
// 下标经过 16 位 Feistel，和明文下标不是同一套排列。
static const int HY_MC_ROUNDS = 9;
static const int HY_DEC_STEPS = 9;
static const uint32_t HY_N = 65536u;
static const uint32_t HY_U32 = HY_N * 4u;
static const uint32_t HY_U8 = HY_N;
static const uint32_t HY_U16 = HY_N * 2u;
static const uint32_t HY_COL = HY_U32 + HY_U32 + 4u * HY_U8;
static const uint32_t HY_ROUND = 4u * HY_COL;
static const uint32_t HY_MC = HY_MC_ROUNDS * HY_ROUND;
static const uint32_t HY_PAIRS = 8u * HY_U16;
static const uint32_t HY_ENC_BYTES = HY_MC + HY_PAIRS;
static const uint32_t HY_DEC_ENTRY = HY_PAIRS;
static const uint32_t HY_DEC_STEP = HY_ROUND + HY_PAIRS;
static const uint32_t HY_DEC_BYTES = HY_DEC_ENTRY + HY_DEC_STEPS * HY_DEC_STEP + HY_PAIRS;
static const uint32_t HY_OFF_DEC = HY_ENC_BYTES;
static const uint32_t HY_TOTAL = HY_ENC_BYTES + HY_DEC_BYTES;

inline uint32_t hy_env_mix(int pagesize, int ncpu, int cls) {
    return (uint32_t)pagesize ^ ((uint32_t)ncpu << 16) ^ ((uint32_t)cls * 0x01000193u) ^ 0xA5C31E87u;
}

inline uint8_t hy_s4(uint8_t x) {
    static const uint8_t S[16] = {
        0x6, 0xB, 0x5, 0xC, 0x1, 0xF, 0x0, 0xE, 0x9, 0x2, 0x7, 0xD, 0xA, 0x4, 0x3, 0x8};
    return S[x & 15];
}

inline uint8_t hy_f8(uint8_t x, uint32_t k, int round) {
    x ^= (uint8_t)(k >> ((round & 3) * 8));
    x = (uint8_t)((hy_s4(x & 15) << 4) | hy_s4(x >> 4));
    x = (uint8_t)(x + (uint8_t)(0x3Du + (unsigned)round * 17u));
    x = (uint8_t)((x << 3) | (x >> 5));
    x ^= (uint8_t)(k >> 16);
    x ^= (uint8_t)(hy_s4(x >> 4) << 4);
    return x;
}

inline uint16_t hy_scatter(uint16_t x, uint32_t env, uint32_t tag) {
    uint32_t k = env ^ (tag * 0x9E3779B1u) ^ 0xA5C31E87u;
    uint8_t L = (uint8_t)(x & 255u);
    uint8_t R = (uint8_t)(x >> 8);
    for (int i = 0; i < 4; i++) {
        uint8_t f = hy_f8(R, k, i);
        uint8_t nL = R;
        R = (uint8_t)(L ^ f);
        L = nL;
    }
    return (uint16_t)(((uint16_t)L << 8) | R);
}

inline uint32_t hy_tag(int dir, int round, int col, int kind) {
    return ((uint32_t)dir << 24) | ((uint32_t)round << 16) | ((uint32_t)col << 8) | (uint32_t)kind;
}

inline int hy_sr_src(int dst) {
    int row = dst & 3;
    int col = dst >> 2;
    return row + 4 * ((col + row) & 3);
}
inline int hy_isr_src(int dst) {
    int row = dst & 3;
    int col = dst >> 2;
    return row + 4 * ((col - row + 4) & 3);
}

inline uint32_t hy_enc_col(int round, int col) {
    return (uint32_t)round * HY_ROUND + (uint32_t)col * HY_COL;
}
inline uint32_t hy_enc_final() { return HY_MC; }

inline uint32_t hy_dec_entry() { return HY_OFF_DEC; }
inline uint32_t hy_dec_mc(int step) {
    return HY_OFF_DEC + HY_DEC_ENTRY + (uint32_t)step * HY_DEC_STEP;
}
inline uint32_t hy_dec_sb(int step) { return hy_dec_mc(step) + HY_ROUND; }
inline uint32_t hy_dec_tail() {
    return HY_OFF_DEC + HY_DEC_ENTRY + HY_DEC_STEPS * HY_DEC_STEP;
}

inline uint32_t hy_load32(const uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag) {
    uint16_t s = hy_scatter(logical, env, tag);
    const uint8_t *p = tab + off + (uint32_t)s * 4u;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint8_t hy_load8(const uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag) {
    uint16_t s = hy_scatter(logical, env, tag);
    return tab[off + s];
}
inline uint16_t hy_load16(const uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag) {
    uint16_t s = hy_scatter(logical, env, tag);
    const uint8_t *p = tab + off + (uint32_t)s * 2u;
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

inline void hy_store32(uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag, uint32_t w) {
    uint16_t s = hy_scatter(logical, env, tag);
    uint8_t *p = tab + off + (uint32_t)s * 4u;
    p[0] = (uint8_t)w;
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}
inline void hy_store8(uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag, uint8_t v) {
    uint16_t s = hy_scatter(logical, env, tag);
    tab[off + s] = v;
}
inline void hy_store16(uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag, uint16_t w) {
    uint16_t s = hy_scatter(logical, env, tag);
    uint8_t *p = tab + off + (uint32_t)s * 2u;
    p[0] = (uint8_t)w;
    p[1] = (uint8_t)(w >> 8);
}

inline int hy_pick(int src_kind, int dst) {
    if (src_kind == 1) return hy_sr_src(dst);
    if (src_kind == 2) return hy_isr_src(dst);
    return dst;
}

inline void hy_mc_round(const uint8_t *tab, uint32_t base, int round, int dir, int src_kind,
                        const uint8_t in[16], uint8_t out[16], uint32_t env) {
    for (int col = 0; col < 4; col++) {
        uint8_t b0 = in[hy_pick(src_kind, 0 + 4 * col)];
        uint8_t b1 = in[hy_pick(src_kind, 1 + 4 * col)];
        uint8_t b2 = in[hy_pick(src_kind, 2 + 4 * col)];
        uint8_t b3 = in[hy_pick(src_kind, 3 + 4 * col)];
        uint32_t off = base + (uint32_t)col * HY_COL;
        uint32_t left = hy_load32(tab, off, (uint16_t)(b0 | (b1 << 8)), env, hy_tag(dir, round, col, 0));
        uint32_t right = hy_load32(tab, off + HY_U32, (uint16_t)(b2 | (b3 << 8)), env, hy_tag(dir, round, col, 1));
        for (int row = 0; row < 4; row++) {
            uint8_t pl = (uint8_t)((left >> (8 * row)) & 255);
            uint8_t pr = (uint8_t)((right >> (8 * row)) & 255);
            uint32_t zoff = off + HY_U32 + HY_U32 + (uint32_t)row * HY_U8;
            out[row + 4 * col] = hy_load8(tab, zoff, (uint16_t)(pl | (pr << 8)), env, hy_tag(dir, round, col, 2 + row));
        }
    }
}

// wiring: 0 直接按下标, 1 ShiftRows 源, 2 InvShiftRows 源。输出按 0,1 / 2,3 ... 成对写回。
inline void hy_pair_map(const uint8_t *tab, uint32_t base, const uint8_t in[16], uint8_t out[16],
                        uint32_t env, int dir, int round, int wiring) {
    for (int p = 0; p < 8; p++) {
        int i0 = p * 2;
        int i1 = i0 + 1;
        int s0 = i0, s1 = i1;
        if (wiring == 1) {
            s0 = hy_sr_src(i0);
            s1 = hy_sr_src(i1);
        } else if (wiring == 2) {
            s0 = hy_isr_src(i0);
            s1 = hy_isr_src(i1);
        }
        uint16_t w = hy_load16(tab, base + (uint32_t)p * HY_U16,
                               (uint16_t)(in[s0] | (in[s1] << 8)), env, hy_tag(dir, round, p, 16 + wiring));
        out[i0] = (uint8_t)w;
        out[i1] = (uint8_t)(w >> 8);
    }
}
