#pragma once
#include <cstdint>
#include <cstring>

// 轮密钥只出现在表项里。运行时按列取两对字节，再取一张联合表。
// 下标经过 16 位 Feistel，和明文下标不是同一套排列。
//
// dl5 (cross-lane nonlinear recoding). Two structural changes to the round tail,
// each with the attack it is meant to stop:
//
//   * every 64K pair-decode table now carries a random 8-bit bijection on its
//     *output*: Q[a][b] = Z(D0[a] ^ D1[b]). The table is no longer a rank-1 XOR
//     tensor, so one row plus one column no longer reproduces it
//     (bge_attack.py step 1);
//   * the boundary is a 64K two-byte table, Q2[u][v] = P[Zl^-1(u) ^ Zr^-1(v) ^ rk].
//     Its index depends on two bytes and neither Z^-1 exists as a table of its
//     own, so an address no longer inverts to a key-dependent byte
//     (dca_attack.py experiment B).
//
// The four output bytes of a column are a 32-bit word; they leave the round
// through a 32-bit nonlinear recoding (3 rounds of per-byte random bijection,
// fixed 4x4 MDS, per-round constant) that mixes all four bytes. See hy_spn_fwd.
static const int HY_MC_ROUNDS = 9;
static const int HY_DEC_STEPS = 9;
static const uint32_t HY_N = 65536u;
static const uint32_t HY_U32 = HY_N * 4u;
static const uint32_t HY_U8 = HY_N;
static const uint32_t HY_U16 = HY_N * 2u;

// One column slot per (direction, round, column). Byte layout:
//   [0, 4096)          F1/F3: four 32-bit lane tables (256 x 4 B, 1024 B apart)
//                      F2:    sixteen coefficient tables (16 x 256 x 1 B)
//                      F0:    the two 16-bit-indexed pair tables (2 x 256 KiB)
//   [4096, 528384)     F1/F2/F3 only: eight 64K pair-decode tables, 2 per output row
//   [528384, 536576)   the recoding: 12 forward + 12 inverse 256-entry tables and
//                      the twelve per-round constants (HY_SPN_*)
//   [536576, 798720)   four 64K two-byte boundary tables, one per output row
// F0 never reads the pair-decode region and F1/F2/F3 never read the F0 front, so
// the two front layouts overlap only where the other family does not look.
static const uint32_t HY_LANE_OFF = 0u;
static const uint32_t HY_Q_OFF = 4096u;
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
// round) here, inside the sealed table, so the reader never assumes that all
// nine rounds share one shape. Masked on disk like every other table byte.
// The tail of the block carries the layout words the HSV bytecode reads through
// Tld: base and round stride per direction, column stride, and the two lane
// strides. They sit at 4-byte-aligned offsets because Tld only reads aligned words.
static const uint32_t HY_SCHED_OFF = HY_TABLES;
static const uint32_t HY_SCHED_STRIDE = 16u;
static const uint32_t HY_SCHED_BYTES = 64u;
static const uint32_t HY_TOTAL = HY_TABLES + HY_SCHED_BYTES;

// Families. Every one computes the same round function; they differ in how the
// linear layer and the key constant are carried into the table path.
static const int HY_FAM_PAIR = 0; // two 16-bit-indexed pair tables + 64K boundary
static const int HY_FAM_T32 = 1;  // four 32-bit byte-indexed tables + pair decode
static const int HY_FAM_T8 = 2;   // 16 coefficient byte tables + pair decode
static const int HY_FAM_T32K = 3; // four 32-bit tables, column key folded in

// Table kinds inside one column slot. Distinct per family so the tag - and with
// it the index scatter - never repeats between shapes.
static const int HY_K_PAIR_L = 0;  // 0,1 pair halves (16-bit index, 32-bit word)
static const int HY_K_T32_W = 16;  // 16..19 wide lane tables
static const int HY_K_T8_C = 32;   // 32..47 coefficient tables
static const int HY_K_T32K_W = 64; // 64..67 wide lane tables
static const int HY_K_T32_Q = 80;  // 80..87 pair decode, two lookups per row
static const int HY_K_T8_Q = 88;   // 88..95
static const int HY_K_T32K_Q = 96; // 96..103
static const int HY_K_SPN_S = 112; // 112..123 forward S-boxes (round i, byte j)
static const int HY_K_SPN_SI = 124;// 124..135 inverse S-boxes
static const int HY_K_BDY_PAIR = 136; // 136..139 F0 two-byte boundary
static const int HY_K_BDY_T32 = 144;  // 144..147 F1
static const int HY_K_BDY_T8 = 152;   // 152..155 F2
static const int HY_K_BDY_T32K = 160;// 160..163 F3

// Sub-layout inside one column slot.
static const uint32_t HY_W1024 = 1024u; // 256 byte-indexed uint32 entries
static const uint32_t HY_W256 = 256u;
static_assert(HY_Q_OFF + 8u * HY_N <= HY_SPN_OFF, "pair-decode tables do not fit the column slot");
static_assert(HY_SPN_OFF + HY_SPN_BYTES <= HY_BDY_OFF, "recoding tables do not fit");
static_assert(HY_BDY_OFF + 4u * HY_N <= HY_COL, "boundary tables do not fit");
// F0's 512 KiB front deliberately overlaps the lane and pair-decode regions of the
// other three families: no family reads another family's region, and the round's
// family byte comes from the sealed schedule block. What must not overlap is
// anything inside one family, which is why the recoding and boundary regions sit
// above the front.
static_assert(2u * HY_U32 <= HY_SPN_OFF, "F0 front must end before the recoding region");

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

// One column of one round, whatever shape the schedule picked for that round.
// F1/F2/F3 read their lanes through a random bijection per (row,k) and decode two
// lanes at a time in a 64K table that then passes through another random
// bijection; the two halves meet in a 64K two-byte boundary table. F0 keeps its
// two 16-bit-indexed pair tables, but its 256-entry inverse tables are gone: the
// same two-byte boundary table performs that inversion.
//
// lane16 (optional) is the 16-entry offset table the HSV bytecode produced for
// this (dir, round): entry 4*col+k is the byte offset of column col's lane-k
// table, and entry 4*col+0 is that column's slot base. The reader then takes
// every lane-table address from the VM instead of computing it; the generator
// passes nullptr and keeps deriving the same numbers itself.
inline void hy_mc_round(const uint8_t *tab, uint32_t base, int round, int dir, int src_kind,
                        const uint8_t in[16], uint8_t out[16], uint32_t env,
                        const uint32_t *lane16 = nullptr) {
    const int fam = (int)tab[HY_SCHED_OFF + (uint32_t)dir * HY_SCHED_STRIDE + (uint32_t)round];
    for (int col = 0; col < 4; col++) {
        const uint32_t cb = lane16 ? lane16[4 * col] : base + (uint32_t)col * HY_COL;
        // Lane-table base per input row k. The stride is the family's: F0 reads
        // lanes 0,1 from the left pair table and lanes 2,3 from the right one;
        // the other families give every lane its own table HY_W1024 apart (F2's
        // 256-byte coefficient tables sit at k*4*HY_W256, the same distance).
        uint32_t lk[4];
        for (int k = 0; k < 4; k++)
            lk[k] = lane16 ? lane16[4 * col + k]
                           : (fam == HY_FAM_PAIR ? ((k >= 2) ? cb + HY_U32 : cb)
                                                 : cb + (uint32_t)k * HY_W1024);
        uint8_t b[4];
        for (int k = 0; k < 4; k++) b[k] = in[hy_pick(src_kind, k + 4 * col)];
        const uint32_t bdy = cb + HY_BDY_OFF;
        if (fam == HY_FAM_PAIR) {
            const uint32_t left = hy_load32(tab, lk[0], (uint16_t)(b[0] | (b[1] << 8)), env,
                                            hy_tag(dir, round, col, HY_K_PAIR_L));
            const uint32_t right = hy_load32(tab, lk[2], (uint16_t)(b[2] | (b[3] << 8)), env,
                                             hy_tag(dir, round, col, HY_K_PAIR_L + 1));
            for (int row = 0; row < 4; row++) {
                const uint8_t pl = (uint8_t)((left >> (8 * row)) & 255);
                const uint8_t pr = (uint8_t)((right >> (8 * row)) & 255);
                out[row + 4 * col] = hy_load8(tab, bdy + (uint32_t)row * HY_N,
                                              (uint16_t)(pl | (pr << 8)), env,
                                              hy_tag(dir, round, col, HY_K_BDY_PAIR + row));
            }
        } else if (fam == HY_FAM_T8) {
            uint8_t v[4][4];
            for (int k = 0; k < 4; k++)
                for (int row = 0; row < 4; row++)
                    v[k][row] = hy_load8t(tab, lk[k] + (uint32_t)row * HY_W256, b[k], env,
                                          hy_tag(dir, round, col, HY_K_T8_C + k * 4 + row));
            for (int row = 0; row < 4; row++) {
                const uint8_t pl = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row) * HY_N,
                                            (uint16_t)(v[0][row] | (v[1][row] << 8)), env,
                                            hy_tag(dir, round, col, HY_K_T8_Q + 2 * row));
                const uint8_t pr = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + 1) * HY_N,
                                            (uint16_t)(v[2][row] | (v[3][row] << 8)), env,
                                            hy_tag(dir, round, col, HY_K_T8_Q + 2 * row + 1));
                out[row + 4 * col] = hy_load8(tab, bdy + (uint32_t)row * HY_N,
                                              (uint16_t)(pl | (pr << 8)), env,
                                              hy_tag(dir, round, col, HY_K_BDY_T8 + row));
            }
        } else {
            const int kw = (fam == HY_FAM_T32K) ? HY_K_T32K_W : HY_K_T32_W;
            const int qb = (fam == HY_FAM_T32K) ? HY_K_T32K_Q : HY_K_T32_Q;
            const int bk = (fam == HY_FAM_T32K) ? HY_K_BDY_T32K : HY_K_BDY_T32;
            uint32_t w[4];
            for (int k = 0; k < 4; k++)
                w[k] = hy_load32t(tab, lk[k], b[k], env,
                                  hy_tag(dir, round, col, kw + k));
            for (int row = 0; row < 4; row++) {
                const uint8_t a0 = (uint8_t)(w[0] >> (8 * row)), a1 = (uint8_t)(w[1] >> (8 * row));
                const uint8_t a2 = (uint8_t)(w[2] >> (8 * row)), a3 = (uint8_t)(w[3] >> (8 * row));
                const uint8_t pl = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row) * HY_N,
                                            (uint16_t)(a0 | (a1 << 8)), env,
                                            hy_tag(dir, round, col, qb + 2 * row));
                const uint8_t pr = hy_load8(tab, cb + HY_Q_OFF + (uint32_t)(2 * row + 1) * HY_N,
                                            (uint16_t)(a2 | (a3 << 8)), env,
                                            hy_tag(dir, round, col, qb + 2 * row + 1));
                out[row + 4 * col] = hy_load8(tab, bdy + (uint32_t)row * HY_N,
                                              (uint16_t)(pl | (pr << 8)), env,
                                              hy_tag(dir, round, col, bk + row));
            }
        }
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
