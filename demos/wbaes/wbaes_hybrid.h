#pragma once
#include <cstdint>
#include <cstring>

// 轮密钥只出现在表项里。运行时按列取两对字节，再取一张联合表。
// 下标经过 16 位 Feistel，和明文下标不是同一套排列。
//
// F4 (this generation's only shape): 16-bit column combining.
//
// MixColumns is GF(2)-linear, so a column's partial sums can be paired on the
// lane axis *and* on the output-row axis: each (row pair, lane pair) is a
// 2^16-index table of 16-bit values, and the two halves of a row pair meet in
// one 16-bit XOR.
//
//     Y01 = T[rp0][b0|b1<<8] ^ T[rp0][b2|b3<<8]      rows 0,1
//     Y23 = T[rp1][b0|b1<<8] ^ T[rp1][b2|b3<<8]      rows 2,3
//
// The value encoding E is a per-build invertible affine map on GF(2)^16, the
// same on both halves of a row pair, so E(u) ^ E(v) = E(u ^ v) and E's constant
// cancels. The four 2^16-index decode tables take the 16-bit XOR, apply E^-1, add
// the column's round-key constant and the output bijection. No 8-bit combine
// exists anywhere on the data path.
//
// The encoding has to be affine, and that is arithmetic rather than a choice: if
// E0, E1 are bijections on 16 bits and some M satisfies M(E0(u) ^ E1(v)) = u ^ v
// for all u, v, then M = E0^-1 = E1^-1 and E0(u ^ v) = E0(u) ^ E0(v). A nonlinear
// 16-bit encoding cannot be undone by any 2^16-index table. The consequence is
// measured, not hidden: the pair table is exactly XOR-separable
// (T[a][b] == X[a] ^ Y[b] over all 2^16 entries), one axis of it is still one key
// byte, and the key falls out at 4,096 affine-consistency tests (0.08 s of
// algebra). This generation is shipped for speed, with that written down:
// attacks/residual/W16-EXPERIMENT.md, README 5.29.
//
// The 32-bit recoding is unchanged from dl5: a column's four output bytes leave
// the round through three rounds of (per-byte random bijection, fixed 4x4 MDS,
// per-round constant). See hy_spn_fwd.
static const int HY_MC_ROUNDS = 9;
static const int HY_DEC_STEPS = 9;
static const uint32_t HY_N = 65536u;
static const uint32_t HY_U32 = HY_N * 4u;
static const uint32_t HY_U16 = HY_N * 2u;

// One column slot per (direction, round, column). Byte layout:
//   [0, 524288)        4 x 2^16-entry pair tables of 16-bit values:
//                      k=0 rows 0,1 lanes 0,1   k=1 rows 0,1 lanes 2,3
//                      k=2 rows 2,3 lanes 0,1   k=3 rows 2,3 lanes 2,3
//   [524288, 528384)   unused: the 4 KiB alignment gap of the shipped stride,
//                      kept so HY_COL and the VM's 288 offsets do not move
//   [528384, 536576)   the recoding: 12 forward + 12 inverse 256-entry tables and
//                      the twelve per-round constants (HY_SPN_*)
//   [536576, 798720)   4 x 2^16-index decode tables, one per output row
// The slot is the same 798,720 B as the eight-bit generations: a shorter one
// would save 294,912 B (0.42 %) and invalidate every offset the VM computes.
static const uint32_t HY_SPN_OFF = 528384u;
static const uint32_t HY_SPN_ROUNDS = 3u;
static const uint32_t HY_SPN_SI_OFF = 12u * 256u; // inverse S-boxes, after 12 forward ones
static const uint32_t HY_SPN_C_OFF = 24u * 256u;  // twelve constants (read directly)
static const uint32_t HY_SPN_BYTES = 8192u;
static const uint32_t HY_BDY_OFF = HY_SPN_OFF + HY_SPN_BYTES;
static const uint32_t HY_COL = HY_BDY_OFF + 4u * HY_N;
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
// round) here, inside the sealed table. In this generation every byte is
// HY_FAM_W16; it is still data because the VM reads it to pick its lane
// addressing, and because a zero byte there must move the addresses rather than
// be quietly ignored.
// The tail of the block carries the layout words the HSV bytecode reads through
// Tld: base and round stride per direction, column stride, and the two lane
// strides. They sit at 4-byte-aligned offsets because Tld only reads aligned words.
static const uint32_t HY_SCHED_OFF = HY_TABLES;
static const uint32_t HY_SCHED_STRIDE = 16u;
static const uint32_t HY_SCHED_BYTES = 64u;
static const uint32_t HY_TOTAL = HY_TABLES + HY_SCHED_BYTES;

// The one shape. It has to be nonzero: the VM's `brz fam, pair-layout` branch is
// what tells it this round gives every lane its own table at `k * lane_stride`,
// and the lane-stride word is one 2^16-entry pair table (HY_W16_TAB). The four
// earlier families each put their partial sums in 8-bit tables at this column
// stride, so none of them can express a 16-bit combine; they are gone rather
// than left as branches no build can reach.
static const int HY_FAM_W16 = 4;

// Table kinds inside one column slot. Distinct per table so the tag - and with
// it the index scatter - never repeats between tables.
static const int HY_K_SPN_S = 112; // 112..123 forward S-boxes (round i, byte j)
static const int HY_K_SPN_SI = 124;// 124..135 inverse S-boxes
static const int HY_K_W16_L = 200; // 200..203 the four 16-bit-output pair tables
static const int HY_K_W16_D = 208; // 208..211 the four 2^16-index decode tables

// Sub-layout inside one column slot.
static const uint32_t HY_W256 = 256u;
static const uint32_t HY_W16_TAB = HY_U16; // one pair table: 2^16 entries x 2 B
static_assert(HY_SPN_OFF + HY_SPN_BYTES <= HY_BDY_OFF, "recoding tables do not fit");
static_assert(HY_BDY_OFF + 4u * HY_N <= HY_COL, "decode tables do not fit");
static_assert(4u * HY_W16_TAB <= HY_SPN_OFF, "the pair tables must end before the recoding region");
static_assert(HY_BDY_OFF + 4u * HY_N == HY_COL, "the decode tables are the last region of the slot");

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

inline uint8_t hy_load8(const uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag) {
    uint16_t s = hy_scatter(logical, env, tag);
    return tab[off + s];
}
inline uint16_t hy_load16(const uint8_t *tab, uint32_t off, uint16_t logical, uint32_t env, uint32_t tag) {
    uint16_t s = hy_scatter(logical, env, tag);
    const uint8_t *p = tab + off + (uint32_t)s * 2u;
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
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
inline uint8_t hy_load8t(const uint8_t *tab, uint32_t off, uint8_t logical, uint32_t env, uint32_t tag) {
    return tab[off + hy_scatter8(logical, env, tag)];
}
inline void hy_store8t(uint8_t *tab, uint32_t off, uint8_t logical, uint32_t env, uint32_t tag, uint8_t v) {
    tab[off + hy_scatter8(logical, env, tag)] = v;
}

// ---- the 32-bit nonlinear recoding -----------------------------------------
//
// An SPN over the four bytes of one column: three rounds of (XOR per-round
// constant, per-byte random bijection, fixed 4x4 MDS mix). The per-byte
// bijections live in the table blob, masked and scattered like every other
// table; the MDS is the circulant (1,4,3,7), which is MDS over GF(2^8) and whose
// inverse is the circulant (11,11,9,8).
//
// Why its inverse is not a set of per-lane arrays: inverting R means inverting a
// *linear* 4x4 mix, which mixes all four bytes of the column, between every pair
// of byte-wise inverse S-boxes. No arrangement of four independent 256-entry
// maps on the lane values expresses that. The inverse is never derived from the
// table either: the generator composes the *forward* S-boxes into table values it
// writes, and the runtime applies R^-1 from the stored inverse S-boxes.
inline uint8_t hy_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }

inline uint8_t hy_mulc(uint8_t x, uint8_t c) {
    switch (c) {
    case 1: return x;
    case 2: return hy_xtime(x);
    case 3: return (uint8_t)(x ^ hy_xtime(x));
    case 4: return hy_xtime(hy_xtime(x));
    case 7: return (uint8_t)(x ^ hy_xtime(x) ^ hy_xtime(hy_xtime(x)));
    case 8: return hy_xtime(hy_xtime(hy_xtime(x)));
    case 9: return (uint8_t)(hy_xtime(hy_xtime(hy_xtime(x))) ^ x);
    case 11: return (uint8_t)(hy_xtime(hy_xtime(hy_xtime(x))) ^ hy_xtime(x) ^ x);
    case 12: return (uint8_t)(hy_xtime(hy_xtime(hy_xtime(x))) ^ hy_xtime(hy_xtime(x)));
    case 13: return (uint8_t)(hy_xtime(hy_xtime(hy_xtime(x))) ^ hy_xtime(hy_xtime(x)) ^ x);
    case 14: return (uint8_t)(hy_xtime(hy_xtime(hy_xtime(x))) ^ hy_xtime(hy_xtime(x)) ^ hy_xtime(x));
    default: break;
    }
    uint8_t p = 0; // generic fallback; no coefficient of the shipped MDS reaches it
    for (int i = 0; i < 8; i++) {
        if (c & 1) p ^= x;
        x = hy_xtime(x);
        c = (uint8_t)(c >> 1);
    }
    return p;
}

// forward mix: M[r][k] = W[(k - r) mod 4], W = (1,4,3,7)
inline void hy_mds(uint8_t y[4]) {
    static const uint8_t W[4] = {1, 4, 3, 7};
    uint8_t t[4];
    for (int r = 0; r < 4; r++) {
        uint8_t a = 0;
        for (int k = 0; k < 4; k++) a = (uint8_t)(a ^ hy_mulc(y[k], W[(k - r + 4) & 3]));
        t[r] = a;
    }
    memcpy(y, t, 4);
}
// inverse mix: M^-1[r][k] = V[(k - r) mod 4], V = (11,11,9,8)
inline void hy_mds_inv(uint8_t y[4]) {
    static const uint8_t V[4] = {11, 11, 9, 8};
    uint8_t t[4];
    for (int r = 0; r < 4; r++) {
        uint8_t a = 0;
        for (int k = 0; k < 4; k++) a = (uint8_t)(a ^ hy_mulc(y[k], V[(k - r + 4) & 3]));
        t[r] = a;
    }
    memcpy(y, t, 4);
}

inline void hy_spn_fwd(const uint8_t *tab, uint32_t cb, int dir, int round, int col,
                       uint8_t y[4], uint32_t env) {
    for (uint32_t i = 0; i < HY_SPN_ROUNDS; i++) {
        for (int j = 0; j < 4; j++) {
            const uint8_t c = tab[cb + HY_SPN_OFF + HY_SPN_C_OFF + i * 4u + (uint32_t)j];
            y[j] = hy_load8t(tab, cb + HY_SPN_OFF + (i * 4u + (uint32_t)j) * HY_W256,
                             (uint8_t)(y[j] ^ c), env,
                             hy_tag(dir, round, col, HY_K_SPN_S + (int)(i * 4u) + j));
        }
        hy_mds(y);
    }
}

inline void hy_spn_inv(const uint8_t *tab, uint32_t cb, int dir, int round, int col,
                       uint8_t y[4], uint32_t env) {
    for (int i = (int)HY_SPN_ROUNDS - 1; i >= 0; i--) {
        hy_mds_inv(y);
        for (int j = 0; j < 4; j++) {
            const uint8_t c = tab[cb + HY_SPN_OFF + HY_SPN_C_OFF + (uint32_t)i * 4u + (uint32_t)j];
            y[j] = (uint8_t)(hy_load8t(tab, cb + HY_SPN_OFF + HY_SPN_SI_OFF +
                                           ((uint32_t)i * 4u + (uint32_t)j) * HY_W256,
                                       y[j], env,
                                       hy_tag(dir, round, col, HY_K_SPN_SI + i * 4 + j)) ^ c);
        }
    }
}

// Undo the recoding left by the round that produced `s`: pbase is that round's
// column-0 base and (dir, round) are its schedule coordinates, because the
// inverse S-boxes and constants belong to it. Callers: the encryption loop before
// every round after the first and before the final whitening pair map; the
// decryption loop after every round, before the pair map that follows it.
inline void hy_rec_undo(const uint8_t *tab, uint32_t pbase, int dir, int round,
                        uint8_t s[16], uint32_t env) {
    for (int col = 0; col < 4; col++) {
        uint8_t y[4];
        for (int j = 0; j < 4; j++) y[j] = s[4 * col + j];
        hy_spn_inv(tab, pbase + (uint32_t)col * HY_COL, dir, round, col, y, env);
        for (int j = 0; j < 4; j++) s[4 * col + j] = y[j];
    }
}

// One column of one round. The shape is fixed, so this is the whole round
// function: four pair lookups, two 16-bit XORs, four decode lookups, then the
// 32-bit recoding.
//
// lane16 (optional) is the 16-entry offset table the HSV bytecode produced for
// this (dir, round): entry 4*col+k is the byte offset of column col's pair table
// k, and entry 4*col+0 is that column's slot base. The reader then takes every
// table address from the VM instead of computing it; the generator passes nullptr
// and keeps deriving the same numbers itself.
inline void hy_mc_round(const uint8_t *tab, uint32_t base, int round, int dir, int src_kind,
                        const uint8_t in[16], uint8_t out[16], uint32_t env,
                        const uint32_t *lane16 = nullptr) {
    for (int col = 0; col < 4; col++) {
        const uint32_t cb = lane16 ? lane16[4 * col] : base + (uint32_t)col * HY_COL;
        // One 2^16-entry pair table per (row pair, lane pair), HY_W16_TAB apart.
        uint32_t lk[4];
        for (int k = 0; k < 4; k++)
            lk[k] = lane16 ? lane16[4 * col + k] : cb + (uint32_t)k * HY_W16_TAB;
        uint8_t b[4];
        for (int k = 0; k < 4; k++) b[k] = in[hy_pick(src_kind, k + 4 * col)];
        const uint32_t bdy = cb + HY_BDY_OFF;
        const uint16_t l01 = (uint16_t)(b[0] | (b[1] << 8));
        const uint16_t r01 = (uint16_t)(b[2] | (b[3] << 8));
        const uint16_t wl01 = hy_load16(tab, lk[0], l01, env, hy_tag(dir, round, col, HY_K_W16_L));
        const uint16_t wr01 = hy_load16(tab, lk[1], r01, env, hy_tag(dir, round, col, HY_K_W16_L + 1));
        const uint16_t wl23 = hy_load16(tab, lk[2], l01, env, hy_tag(dir, round, col, HY_K_W16_L + 2));
        const uint16_t wr23 = hy_load16(tab, lk[3], r01, env, hy_tag(dir, round, col, HY_K_W16_L + 3));
        // The two halves of a row pair meet here: E(u) ^ E(v) = E(u ^ v), 16 bits.
        const uint16_t x01 = (uint16_t)(wl01 ^ wr01);
        const uint16_t x23 = (uint16_t)(wl23 ^ wr23);
        out[0 + 4 * col] = hy_load8(tab, bdy, x01, env,
                                    hy_tag(dir, round, col, HY_K_W16_D));
        out[1 + 4 * col] = hy_load8(tab, bdy + 1u * HY_N, x01, env,
                                    hy_tag(dir, round, col, HY_K_W16_D + 1));
        out[2 + 4 * col] = hy_load8(tab, bdy + 2u * HY_N, x23, env,
                                    hy_tag(dir, round, col, HY_K_W16_D + 2));
        out[3 + 4 * col] = hy_load8(tab, bdy + 3u * HY_N, x23, env,
                                    hy_tag(dir, round, col, HY_K_W16_D + 3));
        // Cross-lane nonlinear recoding: the four output bytes of the column are a
        // 32-bit word and they leave the round SPN-encoded.
        uint8_t y[4];
        for (int j = 0; j < 4; j++) y[j] = out[4 * col + j];
        hy_spn_fwd(tab, cb, dir, round, col, y, env);
        for (int j = 0; j < 4; j++) out[4 * col + j] = y[j];
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
