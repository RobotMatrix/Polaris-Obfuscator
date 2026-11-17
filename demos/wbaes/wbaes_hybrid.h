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
static const uint32_t HY_TABLES = HY_ENC_BYTES + HY_DEC_BYTES;

// Round-family schedule. The generator writes one family byte per (direction,
// round) here, inside the sealed table, so the reader never assumes that all
// nine rounds share one shape. Masked on disk like every other table byte.
static const uint32_t HY_SCHED_OFF = HY_TABLES;
static const uint32_t HY_SCHED_STRIDE = 16u;
static const uint32_t HY_SCHED_BYTES = 64u;
static const uint32_t HY_TOTAL = HY_TABLES + HY_SCHED_BYTES;

// Families. Every one computes the same round function; they differ in how the
// linear layer and the key constant are carried into the table path.
static const int HY_FAM_PAIR = 0; // two 16-bit pair tables + four recode byte tables
static const int HY_FAM_T32 = 1;  // four 32-bit byte-indexed tables XORed + recode
static const int HY_FAM_T8 = 2;   // 16 coefficient byte tables XOR-accumulated + recode
static const int HY_FAM_T32K = 3; // four 32-bit tables, key+offset in one output, no recode

// Table kinds inside one column slot. Distinct per family so the tag - and with
// it the index scatter - never repeats between shapes.
static const int HY_K_PAIR_L = 0;  // 0,1 pair halves; 2..5 recode rows
static const int HY_K_PAIR_Z = 2;
static const int HY_K_T32_W = 16;  // 16..19 wide
static const int HY_K_T32_R = 20;  // 20..23 recode
static const int HY_K_T8_C = 32;   // 32..47 coefficient tables
static const int HY_K_T8_R = 48;   // 48..51 recode
static const int HY_K_T32K_W = 64; // 64..67 wide

// Sub-layout inside one column slot. All four families fit in HY_COL, so the
// slot geometry (and therefore the seal, the mask walk and HY_TOTAL per round)
// stays what it was.
static const uint32_t HY_W1024 = 1024u; // 256 byte-indexed uint32 entries
static const uint32_t HY_W256 = 256u;
static const uint32_t HY_T32_R_OFF = 4u * HY_W1024;
static const uint32_t HY_T8_R_OFF = 16u * HY_W256;

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

// 256-entry tables are indexed by one byte, so they cannot use hy_scatter's
// 16-bit Feistel. An odd multiplier mod 256 is a bijection and costs one
// multiply; positions inside a small table are permuted per tag just like the
// 64K tables are.
inline uint8_t hy_scatter8(uint8_t x, uint32_t env, uint32_t tag) {
    uint32_t k = env ^ (tag * 0x9E3779B1u) ^ 0xA5C31E87u;
    uint32_t a = (k | 1u) & 255u;
    uint32_t b = (k >> 8) & 255u;
    return (uint8_t)(a * (uint32_t)x + b);
}
inline uint32_t hy_load32t(const uint8_t *tab, uint32_t off, uint8_t logical, uint32_t env, uint32_t tag) {
    const uint8_t *p = tab + off + (uint32_t)hy_scatter8(logical, env, tag) * 4u;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint8_t hy_load8t(const uint8_t *tab, uint32_t off, uint8_t logical, uint32_t env, uint32_t tag) {
    return tab[off + hy_scatter8(logical, env, tag)];
}
inline void hy_store32t(uint8_t *tab, uint32_t off, uint8_t logical, uint32_t env, uint32_t tag, uint32_t w) {
    uint8_t *p = tab + off + (uint32_t)hy_scatter8(logical, env, tag) * 4u;
    p[0] = (uint8_t)w;
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}
inline void hy_store8t(uint8_t *tab, uint32_t off, uint8_t logical, uint32_t env, uint32_t tag, uint8_t v) {
    tab[off + hy_scatter8(logical, env, tag)] = v;
}

// One column of one round, whatever shape the schedule picked for that round.
inline void hy_mc_round(const uint8_t *tab, uint32_t base, int round, int dir, int src_kind,
                        const uint8_t in[16], uint8_t out[16], uint32_t env) {
    const int fam = (int)tab[HY_SCHED_OFF + (uint32_t)dir * HY_SCHED_STRIDE + (uint32_t)round];
    for (int col = 0; col < 4; col++) {
        const uint32_t cb = base + (uint32_t)col * HY_COL;
        uint8_t b[4];
        for (int k = 0; k < 4; k++) b[k] = in[hy_pick(src_kind, k + 4 * col)];
        if (fam == HY_FAM_T32 || fam == HY_FAM_T32K) {
            const int kw = (fam == HY_FAM_T32K) ? HY_K_T32K_W : HY_K_T32_W;
            uint32_t w = 0;
            for (int k = 0; k < 4; k++)
                w ^= hy_load32t(tab, cb + (uint32_t)k * HY_W1024, b[k], env,
                                hy_tag(dir, round, col, kw + k));
            if (fam == HY_FAM_T32K) {
                // Key word and output offset are already in one table's 32-bit
                // output: this round has no key step and no recode step.
                for (int row = 0; row < 4; row++) out[row + 4 * col] = (uint8_t)(w >> (8 * row));
            } else {
                for (int row = 0; row < 4; row++)
                    out[row + 4 * col] =
                        hy_load8t(tab, cb + HY_T32_R_OFF + (uint32_t)row * HY_W256,
                                  (uint8_t)(w >> (8 * row)), env,
                                  hy_tag(dir, round, col, HY_K_T32_R + row));
            }
        } else if (fam == HY_FAM_T8) {
            uint8_t acc[4] = {0, 0, 0, 0};
            for (int k = 0; k < 4; k++)
                for (int row = 0; row < 4; row++)
                    acc[row] ^= hy_load8t(tab, cb + (uint32_t)(k * 4 + row) * HY_W256, b[k], env,
                                          hy_tag(dir, round, col, HY_K_T8_C + k * 4 + row));
            for (int row = 0; row < 4; row++)
                out[row + 4 * col] =
                    hy_load8t(tab, cb + HY_T8_R_OFF + (uint32_t)row * HY_W256, acc[row], env,
                              hy_tag(dir, round, col, HY_K_T8_R + row));
        } else {
            uint32_t left = hy_load32(tab, cb, (uint16_t)(b[0] | (b[1] << 8)), env,
                                      hy_tag(dir, round, col, HY_K_PAIR_L));
            uint32_t right = hy_load32(tab, cb + HY_U32, (uint16_t)(b[2] | (b[3] << 8)), env,
                                       hy_tag(dir, round, col, HY_K_PAIR_L + 1));
            for (int row = 0; row < 4; row++) {
                uint8_t pl = (uint8_t)((left >> (8 * row)) & 255);
                uint8_t pr = (uint8_t)((right >> (8 * row)) & 255);
                uint32_t zoff = cb + HY_U32 + HY_U32 + (uint32_t)row * HY_U8;
                out[row + 4 * col] = hy_load8(tab, zoff, (uint16_t)(pl | (pr << 8)), env,
                                              hy_tag(dir, round, col, HY_K_PAIR_Z + row));
            }
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
