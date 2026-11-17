// 烘焙路径的数据面：先洗牌，再在份额上做轮函数。
// 两个槽都执行。份额在轮密钥加里进入状态，不在这里拼回 16 字节密钥。
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
__attribute__((noinline))
static void s5_shr_and(const uint8_t a[2], const uint8_t b[2], uint8_t o[2]) {
    uint8_t r = s5_rnd8();
    uint8_t z0 = (uint8_t)((a[0] & b[0]) ^ r);
    uint8_t z1 = (uint8_t)((a[1] & b[1]) ^ r ^ (a[0] & b[1]) ^ (a[1] & b[0]));
    o[0] = z0;
    o[1] = z1;
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
static void s5_add_rk(volatile uint8_t s[16][2], volatile uint8_t rk[16][2]) {
    for (int i = 0; i < 16; i++) {
        s[i][0] ^= rk[i][0];
        s[i][1] ^= rk[i][1];
    }
}
static void s5_key_expand(volatile uint8_t key[16][2], volatile uint8_t rk[11][16][2]) {
    for (int i = 0; i < 16; i++) {
        rk[0][i][0] = key[i][0];
        rk[0][i][1] = key[i][1];
    }
    for (int round = 1; round <= 10; round++) {
        uint8_t t[4][2];
        for (int i = 0; i < 4; i++) {
            t[i][0] = rk[round - 1][12 + ((i + 1) % 4)][0];
            t[i][1] = rk[round - 1][12 + ((i + 1) % 4)][1];
        }
        for (int i = 0; i < 4; i++) {
            uint8_t in[2] = {t[i][0], t[i][1]};
            uint8_t o[2];
            s5_shr_inv(in, o);
            uint8_t rc = (i == 0) ? rcon_gen(round - 1) : 0;
            t[i][0] = (uint8_t)(s5_aff_lin(o[0]) ^ s5_aff_c() ^ rc);
            t[i][1] = s5_aff_lin(o[1]);
        }
        for (int i = 0; i < 16; i++) {
            if (i < 4) {
                rk[round][i][0] = (uint8_t)(rk[round - 1][i][0] ^ t[i][0]);
                rk[round][i][1] = (uint8_t)(rk[round - 1][i][1] ^ t[i][1]);
            } else {
                rk[round][i][0] = (uint8_t)(rk[round - 1][i][0] ^ rk[round][i - 4][0]);
                rk[round][i][1] = (uint8_t)(rk[round - 1][i][1] ^ rk[round][i - 4][1]);
            }
        }
    }
}
static void s5_aes_enc(volatile uint8_t s[16][2], volatile uint8_t rk[11][16][2]) {
    s5_add_rk(s, rk[0]);
    for (int r = 1; r <= 9; r++) {
        s5_sub(s, 0);
        s5_shift(s, 0);
        s5_mix(s, 0);
        s5_add_rk(s, rk[r]);
    }
    s5_sub(s, 0);
    s5_shift(s, 0);
    s5_add_rk(s, rk[10]);
}
static void s5_aes_dec(volatile uint8_t s[16][2], volatile uint8_t rk[11][16][2]) {
    s5_add_rk(s, rk[10]);
    for (int r = 9; r >= 1; r--) {
        s5_shift(s, 1);
        s5_sub(s, 1);
        s5_add_rk(s, rk[r]);
        s5_mix(s, 1);
    }
    s5_shift(s, 1);
    s5_sub(s, 1);
    s5_add_rk(s, rk[0]);
}

__attribute__((noinline))
static void s5_slot(const uint8_t pt[16], volatile uint8_t key_s[16][2], uint8_t ct[16][2],
                    int dec, int apply_poison) {
    volatile uint8_t rk[11][16][2];
    volatile uint8_t s[16][2];
    s5_key_expand(key_s, rk);
    for (int i = 0; i < 16; i++) {
        uint8_t mask = s5_rnd8();
        if (apply_poison) mask ^= s5_poison_byte(i);
        s[i][0] = mask;
        s[i][1] = (uint8_t)(mask ^ pt[i]);
    }
    if (dec) s5_aes_dec(s, rk);
    else s5_aes_enc(s, rk);
    for (int i = 0; i < 16; i++) {
        ct[i][0] = s[i][0];
        ct[i][1] = s[i][1];
        s[i][0] = 0;
        s[i][1] = 0;
    }
    for (int r = 0; r < 11; r++)
        for (int i = 0; i < 16; i++) {
            rk[r][i][0] = 0;
            rk[r][i][1] = 0;
        }
}

static void s5_load_shares(volatile uint8_t key_s[16][2], uint8_t dummy_key[16], uint8_t flag_secret[16]) {
    for (int i = 0; i < 16; i++) {
        const uint8_t *g = kS5Blob + i * 5;
        key_s[i][0] = (uint8_t)(g[1] ^ g[0] ^ wbaes_s5_stream(i));
        key_s[i][1] = (uint8_t)(g[2] ^ g[0] ^ wbaes_s5_stream(i + 16));
        dummy_key[i] = (uint8_t)(g[3] ^ wbaes_s5_stream(i + 32));
        flag_secret[i] = (uint8_t)(g[4] ^ wbaes_s5_stream(i + 48));
    }
}

static void s5_protect(const uint8_t in[16], uint8_t out[16], int dec) {
    volatile uint8_t key_s[16][2];
    uint8_t dummy_key[16], flag_secret[16];
    s5_load_shares(key_s, dummy_key, flag_secret);
    g_s5_st = 0x6D2B79F5u;
    int real_slot = 0;
    for (int i = 0; i < 16; i++) {
        g_s5_st = g_s5_st * 1664525u + 1013904223u + in[i] + flag_secret[i];
        real_slot ^= (flag_secret[i] ^ in[i]) & 1;
    }
    uint8_t ct_s[2][16][2];
    for (int slot = 0; slot < 2; slot++) {
        uint8_t pt_i[16];
        volatile uint8_t ks[16][2];
        int real = slot == real_slot;
        for (int i = 0; i < 16; i++) {
            if (real) {
                pt_i[i] = in[i];
                ks[i][0] = key_s[i][0];
                ks[i][1] = key_s[i][1];
            } else {
                pt_i[i] = (uint8_t)(flag_secret[i] ^ 0x5A);
                ks[i][0] = s5_rnd8();
                ks[i][1] = (uint8_t)(ks[i][0] ^ dummy_key[i]);
            }
        }
        s5_slot(pt_i, ks, ct_s[slot], dec, real);
        for (int i = 0; i < 16; i++) {
            ks[i][0] = 0;
            ks[i][1] = 0;
        }
    }
    uint8_t flag = real_slot == 0 ? 0xFF : 0x00;
    uint8_t f[2], n[2];
    f[0] = s5_rnd8();
    f[1] = (uint8_t)(f[0] ^ flag);
    n[0] = (uint8_t)(f[0] ^ 0xFF);
    n[1] = f[1];
    for (int i = 0; i < 16; i++) {
        uint8_t a[2] = {ct_s[0][i][0], ct_s[0][i][1]};
        uint8_t b[2] = {ct_s[1][i][0], ct_s[1][i][1]};
        uint8_t p[2], q[2];
        s5_shr_and(a, f, p);
        s5_shr_and(b, n, q);
        out[i] = (uint8_t)(p[0] ^ p[1] ^ q[0] ^ q[1]);
    }
    for (int i = 0; i < 16; i++) {
        key_s[i][0] = 0;
        key_s[i][1] = 0;
        dummy_key[i] = 0;
        flag_secret[i] = 0;
    }
}
