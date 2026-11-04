// 烘焙数据面：首尾两轮逐字节吸收份额，中间轮只查表。
// 表的输出编码已经烤进下一张表的下标，运行时不做逆变换。
static uint32_t g_s5_st = 0x6D2B79F5u;

static uint8_t s5_rnd8() {
    g_s5_st = g_s5_st * 1664525u + 1013904223u;
    return (uint8_t)(g_s5_st >> 16);
}
static uint8_t s5_xtime(uint8_t x) {
    uint8_t hi = (uint8_t)(x & 0x80);
    x = (uint8_t)(x << 1);
    if (hi) x ^= (uint8_t)(GF_MOD_HI ^ GF_MOD_LO);
    return x;
}
static uint8_t s5_aff_c() { return (uint8_t)(SBOX_C_HI ^ SBOX_C_LO); }
static uint8_t s5_aff_lin(uint8_t b) {
    return (uint8_t)(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4));
}
static uint8_t s5_aff_inv_lin(uint8_t b) {
    return (uint8_t)(rotl8(b, 1) ^ rotl8(b, 3) ^ rotl8(b, 6));
}
static uint8_t s5_poison_byte(int i) {
    return (uint8_t)(g_poison >> ((i & 3) * 8));
}
__attribute__((noinline))
static void s5_shr_mul(const uint8_t a[2], const uint8_t b[2], uint8_t o[2]) {
    uint8_t r = s5_rnd8();
    uint8_t z0 = (uint8_t)(gmul(a[0], b[0]) ^ r);
    uint8_t z1 = (uint8_t)(gmul(a[1], b[1]) ^ r ^ gmul(a[0], b[1]) ^ gmul(a[1], b[0]));
    o[0] = z0;
    o[1] = z1;
}
static void s5_shr_sq(const uint8_t a[2], uint8_t o[2]) {
    o[0] = gmul(a[0], a[0]);
    o[1] = gmul(a[1], a[1]);
}
__attribute__((noinline))
static void s5_shr_inv(const uint8_t a[2], uint8_t o[2]) {
    uint8_t x2[2], x4[2], x8[2], x16[2], x32[2], x64[2], x128[2], p[2];
    s5_shr_sq(a, x2);
    s5_shr_sq(x2, x4);
    s5_shr_sq(x4, x8);
    s5_shr_sq(x8, x16);
    s5_shr_sq(x16, x32);
    s5_shr_sq(x32, x64);
    s5_shr_sq(x64, x128);
    s5_shr_mul(x128, x64, p);
    s5_shr_mul(p, x32, p);
    s5_shr_mul(p, x16, p);
    s5_shr_mul(p, x8, p);
    s5_shr_mul(p, x4, p);
    s5_shr_mul(p, x2, o);
}
static void s5_sub(volatile uint8_t s[16][2], int inv) {
    for (int i = 0; i < 16; i++) {
        uint8_t in[2] = {s[i][0], s[i][1]};
        uint8_t o[2];
        if (!inv) {
            s5_shr_inv(in, o);
            s[i][0] = (uint8_t)(s5_aff_lin(o[0]) ^ s5_aff_c());
            s[i][1] = s5_aff_lin(o[1]);
        } else {
            uint8_t t[2] = {(uint8_t)(s5_aff_inv_lin(in[0]) ^ 0x05), s5_aff_inv_lin(in[1])};
            s5_shr_inv(t, o);
            s[i][0] = o[0];
            s[i][1] = o[1];
        }
    }
}
static void s5_shift(volatile uint8_t s[16][2], int inv) {
    uint8_t t[16][2];
    for (int i = 0; i < 16; i++) {
        t[i][0] = s[i][0];
        t[i][1] = s[i][1];
    }
    for (int row = 0; row < 4; row++) {
        int k = inv ? (4 - row) : row;
        for (int col = 0; col < 4; col++) {
            int src = row + 4 * ((col + k) % 4);
            int dst = row + 4 * col;
            s[dst][0] = t[src][0];
            s[dst][1] = t[src][1];
        }
    }
}
static void s5_mix(volatile uint8_t s[16][2], int inv) {
    for (int c = 0; c < 4; c++) {
        uint8_t a[4][2];
        for (int r = 0; r < 4; r++) {
            a[r][0] = s[r + 4 * c][0];
            a[r][1] = s[r + 4 * c][1];
        }
        for (int sh = 0; sh < 2; sh++) {
            uint8_t a0 = a[0][sh], a1 = a[1][sh], a2 = a[2][sh], a3 = a[3][sh];
            if (!inv) {
                s[0 + 4 * c][sh] = (uint8_t)(s5_xtime(a0) ^ s5_xtime(a1) ^ a1 ^ a2 ^ a3);
                s[1 + 4 * c][sh] = (uint8_t)(a0 ^ s5_xtime(a1) ^ s5_xtime(a2) ^ a2 ^ a3);
                s[2 + 4 * c][sh] = (uint8_t)(a0 ^ a1 ^ s5_xtime(a2) ^ s5_xtime(a3) ^ a3);
                s[3 + 4 * c][sh] = (uint8_t)(s5_xtime(a0) ^ a0 ^ a1 ^ a2 ^ s5_xtime(a3));
            } else {
                s[0 + 4 * c][sh] = (uint8_t)(gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09));
                s[1 + 4 * c][sh] = (uint8_t)(gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d));
                s[2 + 4 * c][sh] = (uint8_t)(gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b));
                s[3 + 4 * c][sh] = (uint8_t)(gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e));
            }
        }
    }
}

static void hy_absorb(volatile uint8_t *cell, int id) {
    uint8_t b = hy_share_byte(kSharePool, id, g_env);
    *cell ^= b;
}
static void hy_wipe(volatile uint8_t s[16][2]) {
    for (int i = 0; i < 16; i++) {
        s[i][0] = 0;
        s[i][1] = 0;
    }
}
static void hy_enc_cols(const uint32_t *tab, const uint8_t in[16], uint8_t out[16], int do_nl) {
    for (int col = 0; col < 4; col++) {
        uint32_t acc = 0;
        for (int row = 0; row < 4; row++) {
            int src_col = (col + row) % 4;
            uint8_t b = in[row + 4 * src_col];
            if (do_nl) b = hy_nl(b);
            acc ^= tab[(row * 4 + col) * 256 + b];
        }
        for (int row = 0; row < 4; row++) out[row + 4 * col] = (uint8_t)(acc >> (24 - 8 * row));
    }
}
static void hy_dec_cols(const uint32_t *tab, const uint8_t in[16], uint8_t out[16]) {
    for (int col = 0; col < 4; col++) {
        uint32_t acc = 0;
        for (int row = 0; row < 4; row++) {
            int src_col = (col - row + 4) % 4;
            acc ^= tab[(row * 4 + col) * 256 + in[row + 4 * src_col]];
        }
        for (int row = 0; row < 4; row++) out[row + 4 * col] = (uint8_t)(acc >> (24 - 8 * row));
    }
}

static void hy_enc_slot(const uint8_t pt[16], int slot, uint8_t ct[16], int poison) {
    volatile uint8_t s[16][2];
    g_s5_st ^= (uint32_t)(slot * 0x9E3779B1u) ^ g_env;
    for (int i = 0; i < 16; i++) {
        uint8_t m = s5_rnd8();
        if (poison) m ^= s5_poison_byte(i);
        s[i][0] = m;
        s[i][1] = (uint8_t)(m ^ pt[i]);
        hy_absorb(&s[i][0], hy_id(slot, 0, i, 0));
        hy_absorb(&s[i][1], hy_id(slot, 0, i, 1));
    }
    s5_sub(s, 0);
    s5_shift(s, 0);
    s5_mix(s, 0);
    uint8_t cur[16], nxt[16];
    for (int i = 0; i < 16; i++) cur[i] = (uint8_t)(s[i][0] ^ s[i][1]);
    hy_wipe(s);
    hy_enc_cols(kMidEnc, cur, nxt, 1);
    for (int r = 1; r < HY_ENC_ROUNDS; r++) {
        hy_enc_cols(kMidEnc + (size_t)r * 4 * 4 * 256, nxt, cur, 0);
        for (int i = 0; i < 16; i++) nxt[i] = cur[i];
    }
    for (int i = 0; i < 16; i++) {
        uint8_t m = s5_rnd8();
        s[i][0] = m;
        s[i][1] = (uint8_t)(m ^ nxt[i]);
    }
    s5_sub(s, 0);
    s5_shift(s, 0);
    for (int i = 0; i < 16; i++) {
        hy_absorb(&s[i][0], hy_id(slot, 1, i, 0));
        hy_absorb(&s[i][1], hy_id(slot, 1, i, 1));
        ct[i] = (uint8_t)(s[i][0] ^ s[i][1]);
    }
    hy_wipe(s);
}

static void hy_dec_slot(const uint8_t ct[16], int slot, uint8_t pt[16]) {
    volatile uint8_t s[16][2];
    g_s5_st ^= (uint32_t)(slot * 0x85EBCA77u) ^ g_env;
    for (int i = 0; i < 16; i++) {
        uint8_t m = s5_rnd8();
        s[i][0] = m;
        s[i][1] = (uint8_t)(m ^ ct[i]);
        hy_absorb(&s[i][0], hy_id(slot, 1, i, 0));
        hy_absorb(&s[i][1], hy_id(slot, 1, i, 1));
    }
    uint8_t cur[16], nxt[16];
    for (int i = 0; i < 16; i++) cur[i] = (uint8_t)(s[i][0] ^ s[i][1]);
    hy_wipe(s);
    for (int r = 0; r < HY_DEC_ROUNDS; r++) {
        hy_dec_cols(kMidDec + (size_t)r * 4 * 4 * 256, cur, nxt);
        for (int i = 0; i < 16; i++) cur[i] = nxt[i];
    }
    for (int i = 0; i < 16; i++) {
        uint8_t m = s5_rnd8();
        s[i][0] = m;
        s[i][1] = (uint8_t)(m ^ cur[i]);
    }
    s5_shift(s, 1);
    s5_sub(s, 1);
    for (int i = 0; i < 16; i++) {
        hy_absorb(&s[i][0], hy_id(slot, 0, i, 0));
        hy_absorb(&s[i][1], hy_id(slot, 0, i, 1));
        pt[i] = (uint8_t)(s[i][0] ^ s[i][1]);
    }
    hy_wipe(s);
}

static void hy_protect(const uint8_t in[16], uint8_t out[16], int dec) {
    int real = hy_real_slot(g_env);
    int rot = 0;
    for (int i = 0; i < 16; i++) rot = (rot + in[i] + (int)(g_env >> ((i & 3) * 8))) & (HY_SLOTS - 1);
    uint8_t got[HY_SLOTS][16];
    for (int slot = 0; slot < HY_SLOTS; slot++) {
        int dst = (slot + rot) & (HY_SLOTS - 1);
        if (dec) hy_dec_slot(in, slot, got[dst]);
        else hy_enc_slot(in, slot, got[dst], slot == real);
    }
    int pick = (real + rot) & (HY_SLOTS - 1);
    for (int i = 0; i < 16; i++) {
        uint8_t acc = 0;
        for (int slot = 0; slot < HY_SLOTS; slot++) {
            uint8_t sel = (slot == pick) ? 0xFF : 0x00;
            acc |= (uint8_t)(got[slot][i] & sel);
        }
        out[i] = acc;
    }
}
