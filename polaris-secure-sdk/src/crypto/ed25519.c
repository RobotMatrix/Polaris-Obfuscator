// Ed25519 (RFC 8032) — 参考实现
// 设计取向: 正确性与可审计性优先。
//  - 字段算术: GF(2^255-19), 64 位平台 5×51 位肢体 (__int128 中间积)
//  - 标量归约: 逐位移位-条件减法 (慢于 Barrett 但显然正确, 无魔数)
//  - 点乘: 二进制 double-and-add, 非恒时 —— 参考实现已知限制, 见 docs/02
// 行为由 RFC 8032 测试向量验证 (tests/test_crypto_kat.cpp)。
#include "polaris_secure/crypto.h"

#include <cstring>

#if defined(__APPLE__)
#include <stdlib.h>
#elif defined(__linux__)
#include <stdio.h>
#include <unistd.h>
#if defined(__GLIBC__)
#include <sys/random.h>
#endif
#endif

namespace polaris_secure {
namespace prim {

// ===================== 平台 CSPRNG =====================
bool secure_random(uint8_t* out, size_t n) {
#if defined(__APPLE__)
    arc4random_buf(out, n);
    return true;
#elif defined(__linux__) && defined(__GLIBC__)
    for (size_t off = 0; off < n; off += 256) {
        size_t chunk = n - off < 256 ? n - off : 256;
        if (getentropy(out + off, chunk) != 0) return false;
    }
    return true;
#else
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t got = 0;
    while (got < n) {
        size_t r = fread(out + got, 1, n - got, f);
        if (r == 0) { fclose(f); return false; }
        got += r;
    }
    fclose(f);
    return true;
#endif
}

// ===================== 字段算术 GF(2^255 - 19) =====================
typedef uint64_t fe[5];
static const uint64_t MASK51 = 0x7FFFFFFFFFFFFULL;

static void fe_0(fe h) { h[0]=0;h[1]=0;h[2]=0;h[3]=0;h[4]=0; }
static void fe_1(fe h) { h[0]=1;h[1]=0;h[2]=0;h[3]=0;h[4]=0; }
static void fe_copy(fe h, const fe f) { for(int i=0;i<5;i++) h[i]=f[i]; }

static void fe_add(fe h, const fe f, const fe g) {
    for (int i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    // f + 2p - g (2p 肢体 = 2^52-38, 2^52-2 ×4)
    h[0] = f[0] + 0xFFFFFFFFFFFDAULL - g[0];
    for (int i = 1; i < 5; i++) h[i] = f[i] + 0xFFFFFFFFFFFFEULL - g[i];
}

static void fe_mul(fe h, const fe f, const fe g) {
    unsigned __int128 r0, r1, r2, r3, r4;
    unsigned __int128 f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    unsigned __int128 g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    unsigned __int128 f1_19=19*f1, f2_19=19*f2, f3_19=19*f3, f4_19=19*f4;

    r0 = f0*g0 + f1_19*g4 + f2_19*g3 + f3_19*g2 + f4_19*g1;
    r1 = f0*g1 + f1*g0 + f2_19*g4 + f3_19*g3 + f4_19*g2;
    r2 = f0*g2 + f1*g1 + f2*g0 + f3_19*g4 + f4_19*g3;
    r3 = f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4_19*g4;
    r4 = f0*g4 + f1*g3 + f2*g2 + f3*g1 + f4*g0;

    r1 += (r0 >> 51); r0 &= MASK51;
    r2 += (r1 >> 51); r1 &= MASK51;
    r3 += (r2 >> 51); r2 &= MASK51;
    r4 += (r3 >> 51); r3 &= MASK51;
    r0 += 19 * (uint64_t)(r4 >> 51); r4 &= MASK51;
    r1 += (r0 >> 51); r0 &= MASK51;

    h[0]=(uint64_t)r0; h[1]=(uint64_t)r1; h[2]=(uint64_t)r2;
    h[3]=(uint64_t)r3; h[4]=(uint64_t)r4;
}

static void fe_sq(fe h, const fe f) {
    unsigned __int128 r0,r1,r2,r3,r4;
    unsigned __int128 f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    unsigned __int128 f0_2=f0*2, f1_2=f1*2;
    unsigned __int128 f1_38=38*f1, f2_38=38*f2;
    unsigned __int128 f3_38=38*f3, f3_19=19*f3, f4_19=19*f4;

    r0 = f0*f0 + f1_38*f4 + f2_38*f3;
    r1 = f0_2*f1 + f2_38*f4 + f3_19*f3;
    r2 = f0_2*f2 + f1*f1 + f3_38*f4;
    r3 = f0_2*f3 + f1_2*f2 + f4_19*f4;
    r4 = f0_2*f4 + f1_2*f3 + f2*f2;

    r1 += (r0 >> 51); r0 &= MASK51;
    r2 += (r1 >> 51); r1 &= MASK51;
    r3 += (r2 >> 51); r2 &= MASK51;
    r4 += (r3 >> 51); r3 &= MASK51;
    r0 += 19 * (uint64_t)(r4 >> 51); r4 &= MASK51;
    r1 += (r0 >> 51); r0 &= MASK51;

    h[0]=(uint64_t)r0; h[1]=(uint64_t)r1; h[2]=(uint64_t)r2;
    h[3]=(uint64_t)r3; h[4]=(uint64_t)r4;
}

static void fe_mul_small(fe h, const fe f, uint64_t s) {
    unsigned __int128 r[5];
    for (int i = 0; i < 5; i++) r[i] = (unsigned __int128)f[i] * s;
    r[1] += r[0] >> 51; r[0] &= MASK51;
    r[2] += r[1] >> 51; r[1] &= MASK51;
    r[3] += r[2] >> 51; r[2] &= MASK51;
    r[4] += r[3] >> 51; r[3] &= MASK51;
    r[0] += 19 * (uint64_t)(r[4] >> 51); r[4] &= MASK51;
    r[1] += r[0] >> 51; r[0] &= MASK51;
    for (int i = 0; i < 5; i++) h[i] = (uint64_t)r[i];
}

static void fe_frombytes(fe h, const uint8_t* s) {
    // 按位装载 5×51 (清晰优先; 性能非关键路径)
    for (int i = 0; i < 5; i++) {
        uint64_t acc = 0;
        for (int b = 0; b < 51; b++) {
            int bit = i * 51 + b;
            if ((s[bit / 8] >> (bit % 8)) & 1) acc |= (uint64_t)1 << b;
        }
        h[i] = acc;
    }
    h[4] &= MASK51;  // 丢弃最高 sign 位
}

// 完全归约到 [0, p) 规范肢体 (< 2^51)
static void fe_reduce(fe out, const fe h) {
    uint64_t t[5], q;
    for (int i = 0; i < 5; i++) t[i] = h[i];
    q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;
    t[0] += 19 * q;
    t[1] += t[0] >> 51; t[0] &= MASK51;
    t[2] += t[1] >> 51; t[1] &= MASK51;
    t[3] += t[2] >> 51; t[2] &= MASK51;
    t[4] += t[3] >> 51; t[3] &= MASK51;
    t[4] &= MASK51;
    for (int i = 0; i < 5; i++) out[i] = t[i];
}

static void fe_tobytes(uint8_t* s, const fe h) {
    uint64_t t[5];
    fe_reduce(t, h);
    memset(s, 0, 32);
    for (int i = 0; i < 5; i++)
        for (int b = 0; b < 51; b++) {
            int bit = i * 51 + b;
            if ((t[i] >> b) & 1) s[bit / 8] |= (uint8_t)(1 << (bit % 8));
        }
}

static void fe_pow_bytes(fe out, const fe z, const uint8_t e32[32]) {
    // 通用平方-乘 (指数公开固定, 仅用于求逆/开方常数)
    fe r, base;
    fe_1(r);
    fe_copy(base, z);
    for (int i = 255; i >= 0; i--) {
        fe_sq(r, r);
        if ((e32[i / 8] >> (i % 8)) & 1) fe_mul(r, r, base);
    }
    fe_copy(out, r);
}

static void fe_invert(fe out, const fe z) {
    // z^(p-2), p-2 = 2^255-21 (LE: EB FF..FF 7F)
    static const uint8_t e[32] = {0xEB, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F};
    fe_pow_bytes(out, z, e);
}

static void fe_pow22523(fe out, const fe z) {
    // z^((p-5)/8), (p-5)/8 = 2^252-3 (LE: FD FF..FF 0F)
    static const uint8_t e[32] = {0xFD, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x0F};
    fe_pow_bytes(out, z, e);
}

// 取负: 输入可能处于弱归约态 (肢体可达 2^52.x), 先规范化再 0-f,
// 保证 fe_sub 的不减约定 (g 肢体 < 2^52) 成立。
static void fe_neg(fe h, const fe f) {
    fe t, zero;
    fe_reduce(t, f);
    fe_0(zero);
    fe_sub(h, zero, t);
}

static bool fe_iszero(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    uint8_t d = 0;
    for (int i = 0; i < 32; i++) d |= s[i];
    return d == 0;
}

// ===================== 标量算术 mod L =====================
// L = 2^252 + 27742317777372353535851937790883648493
static const uint64_t L_W[4] = {0x5812631A5CF5D3EDULL, 0x14DEF9DEA2F79CD6ULL, 0ULL,
                                0x1000000000000000ULL};
static const uint8_t L_BE[32] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
                                 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed};

static uint64_t load_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

// 512-bit (8×u64 LE) 归约 mod L: MSB 起逐位 r=2r+bit, r>=L 减 L。
static void sc_reduce512(uint8_t out32[32], const uint64_t s[8]) {
    uint64_t r[4] = {0, 0, 0, 0};
    for (int i = 511; i >= 0; i--) {
        uint64_t carry = (s[i / 64] >> (i % 64)) & 1;
        for (int j = 0; j < 4; j++) {
            uint64_t nc = r[j] >> 63;
            r[j] = (r[j] << 1) | carry;
            carry = nc;
        }
        // r >= L ? (r < 2L < 2^254, 无 256 位溢出)
        int cmp = 0;
        int j = 3;
        while (j >= 0 && r[j] == L_W[j]) j--;
        if (j < 0) cmp = 1;        // 相等
        else if (r[j] > L_W[j]) cmp = 1;
        if (cmp) {
            uint64_t borrow = 0;
            for (int k = 0; k < 4; k++) {
                uint64_t sub = L_W[k] + borrow;  // L_W[k] < 2^61, 无溢出
                uint64_t nb = r[k] < sub ? 1 : 0;
                r[k] = r[k] - sub;
                borrow = nb;
            }
        }
    }
    for (int k = 0; k < 4; k++) {
        out32[k*8+0]=(uint8_t)r[k];       out32[k*8+1]=(uint8_t)(r[k]>>8);
        out32[k*8+2]=(uint8_t)(r[k]>>16); out32[k*8+3]=(uint8_t)(r[k]>>24);
        out32[k*8+4]=(uint8_t)(r[k]>>32); out32[k*8+5]=(uint8_t)(r[k]>>40);
        out32[k*8+6]=(uint8_t)(r[k]>>48); out32[k*8+7]=(uint8_t)(r[k]>>56);
    }
}

// (a*b + c) mod L (a,b,c 均为 32B 小端标量)
static void sc_muladd(uint8_t out32[32], const uint8_t a32[32], const uint8_t b32[32],
                      const uint8_t c32[32]) {
    uint64_t a[4], b[4], p[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) { a[i] = load_le64(a32 + i * 8); b[i] = load_le64(b32 + i * 8); }
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            unsigned __int128 cur = (unsigned __int128)a[i] * b[j] + p[i + j] + carry;
            p[i + j] = (uint64_t)cur;
            carry = cur >> 64;
        }
        p[i + 4] += (uint64_t)carry;
    }
    {  // + c (c 为 32B 小端标量)
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t cval = load_le64(c32 + j * 8);
            unsigned __int128 cur = (unsigned __int128)p[j] + cval + carry;
            p[j] = (uint64_t)cur;
            carry = (uint64_t)(cur >> 64);
        }
        for (int j = 4; j < 8 && carry; j++) {
            uint64_t t = p[j] + 1;
            carry = (t == 0) ? 1 : 0;
            p[j] = t;
        }
    }
    sc_reduce512(out32, p);
}

static bool sc_is_canonical(const uint8_t s32[32]) {
    uint8_t s_be[32];
    for (int i = 0; i < 32; i++) s_be[i] = s32[31 - i];
    for (int i = 0; i < 32; i++) {
        if (s_be[i] != L_BE[i]) return s_be[i] < L_BE[i];
    }
    return false;  // S == L
}

// ===================== 群运算 (扩展扭曲 Edwards 坐标) =====================
typedef struct { fe X, Y, Z, T; } ge;

static fe CD, C2D;  // d 与 2d
static bool g_inited = false;

static void ensure_curve_consts() {
    if (g_inited) return;
    fe one, num, den, inv_den;
    fe_1(one);
    fe_mul_small(num, one, 121665);
    fe_neg(num, num);                 // -121665
    fe_mul_small(den, one, 121666);
    fe_invert(inv_den, den);
    fe_mul(CD, num, inv_den);         // d = -121665/121666
    fe_add(C2D, CD, CD);
    g_inited = true;
}

static void ge_identity(ge* p) { fe_0(p->X); fe_1(p->Y); fe_1(p->Z); fe_0(p->T); }

static void ge_add(ge* r, const ge* p, const ge* q) {
    fe A, B, C, D, E, F, G, H, t0, t1;
    fe_sub(t0, p->Y, p->X); fe_sub(t1, q->Y, q->X); fe_mul(A, t0, t1);
    fe_add(t0, p->Y, p->X); fe_add(t1, q->Y, q->X); fe_mul(B, t0, t1);
    fe_mul(t0, p->T, q->T); fe_mul(C, C2D, t0);
    fe_mul(t0, p->Z, q->Z); fe_add(D, t0, t0);
    fe_sub(E, B, A);
    fe_sub(F, D, C);
    fe_add(G, D, C);
    fe_add(H, B, A);
    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

static void ge_double(ge* r, const ge* p) { ge_add(r, p, p); }

static void ge_scalarmult(ge* r, const uint8_t scalar32[32], const ge* base) {
    ge acc, tmp;
    ge_identity(&acc);
    for (int i = 255; i >= 0; i--) {
        ge_double(&acc, &acc);
        if ((scalar32[i / 8] >> (i % 8)) & 1) {
            ge_add(&tmp, &acc, base);
            acc = tmp;
        }
    }
    *r = acc;
}

static void ge_tobytes(uint8_t* s, const ge* p) {
    fe zinv, x, y, xr;
    fe_invert(zinv, p->Z);
    fe_mul(x, p->X, zinv);
    fe_mul(y, p->Y, zinv);
    fe_tobytes(s, y);
    fe_reduce(xr, x);  // 奇偶位必须取自规范表示
    s[31] |= (uint8_t)((xr[0] & 1) << 7);
}

static bool ge_frombytes(ge* p, const uint8_t* s) {
    fe y, u, v, v3, v7, t0, t1, x, check, diff;
    fe_frombytes(y, s);
    int sign = s[31] >> 7;
    // u = y^2 - 1 ; v = d*y^2 + 1
    fe_sq(u, y);
    fe_1(t0);
    fe_sub(u, u, t0);
    fe_sq(v, y);
    fe_mul(v, v, CD);
    fe_1(t0);
    fe_add(v, v, t0);
    // v3 = v^3 ; v7 = v^7
    fe_sq(v3, v); fe_mul(v3, v3, v);
    fe_sq(v7, v3); fe_mul(v7, v7, v);
    // x = u * v^3 * (u * v^7)^((p-5)/8)
    fe_mul(t0, u, v7);
    fe_pow22523(t0, t0);
    fe_mul(x, u, v3);
    fe_mul(x, x, t0);
    // v*x^2 == u ?
    fe_sq(check, x);
    fe_mul(check, check, v);
    fe_sub(diff, check, u);
    if (!fe_iszero(diff)) {
        // v*x^2 == -u ? => x *= sqrt(-1)
        fe_neg(t1, u);
        fe_sub(diff, check, t1);
        if (!fe_iszero(diff)) return false;
        // sqrt(-1) = 2^((p-1)/4), (p-1)/4 = 2^253-5 (LE: FB FF..FF 1F)
        static const uint8_t e[32] = {0xFB, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x1F};
        fe two, base;
        fe_1(two); fe_add(two, two, two);
        fe_pow_bytes(base, two, e);
        fe_mul(x, x, base);
    }
    if (fe_iszero(x) && sign) return false;
    fe_reduce(x, x);  // 规范化后再取奇偶位
    if ((int)(x[0] & 1) != sign) fe_neg(x, x);
    fe_copy(p->X, x);
    fe_copy(p->Y, y);
    fe_1(p->Z);
    fe_mul(p->T, x, y);
    return true;
}

// 基点 B 编码 (RFC 8032): y = 4/5, Bx 为偶数 → 无符号位
static const uint8_t BASEBYTES[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66};

static void ge_base(ge* b) { ge_frombytes(b, BASEBYTES); }

// ===================== Ed25519 API =====================
void ed25519_keypair(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    ensure_curve_consts();
    uint8_t h[64], a[32];
    ge B, A;
    sha512(seed, 32, h);
    memcpy(a, h, 32);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    ge_base(&B);
    ge_scalarmult(&A, a, &B);
    ge_tobytes(pk, &A);
    memcpy(sk, seed, 32);  // sk = seed || pk
    memcpy(sk + 32, pk, 32);
    memset(h, 0, sizeof(h));
    memset(a, 0, sizeof(a));
}

bool ed25519_sign(uint8_t sig[64], const uint8_t* msg, size_t n, const uint8_t pk[32],
                  const uint8_t sk[64]) {
    ensure_curve_consts();
    uint8_t h[64], a[32], prefix[32], r[32], k[32], s[32], rb[32];
    uint64_t w[8];
    ge B, R;
    Sha512Ctx c;

    sha512(sk, 32, h);  // sk 前 32B = seed
    memcpy(a, h, 32);
    memcpy(prefix, h + 32, 32);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    // r = SHA512(prefix || M) mod L
    sha512_init(&c);
    sha512_update(&c, prefix, 32);
    sha512_update(&c, msg, n);
    sha512_final(&c, h);
    for (int i = 0; i < 8; i++) w[i] = load_le64(h + i * 8);
    sc_reduce512(r, w);

    ge_base(&B);
    ge_scalarmult(&R, r, &B);
    ge_tobytes(rb, &R);

    // k = SHA512(R || A || M) mod L
    sha512_init(&c);
    sha512_update(&c, rb, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, n);
    sha512_final(&c, h);
    for (int i = 0; i < 8; i++) w[i] = load_le64(h + i * 8);
    sc_reduce512(k, w);

    sc_muladd(s, k, a, r);  // S = k*a + r mod L
    memcpy(sig, rb, 32);
    memcpy(sig + 32, s, 32);
    memset(h, 0, sizeof(h));
    memset(a, 0, sizeof(a));
    return true;
}

bool ed25519_verify(const uint8_t sig[64], const uint8_t* msg, size_t n,
                    const uint8_t pk[32]) {
    ensure_curve_consts();
    if (!sc_is_canonical(sig + 32)) return false;

    ge A, R, B, sB, kA, sum;
    if (!ge_frombytes(&A, pk)) return false;
    if (!ge_frombytes(&R, sig)) return false;
    ge_base(&B);

    uint8_t k[32], h[64], w8[8];
    uint64_t w[8];
    Sha512Ctx c;
    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, n);
    sha512_final(&c, h);
    for (int i = 0; i < 8; i++) {
        memcpy(w8, h + i * 8, 8);
        w[i] = load_le64(w8);
    }
    (void)w8;
    sc_reduce512(k, w);

    // 校验 S*B == R + k*A
    ge_scalarmult(&sB, sig + 32, &B);
    ge_scalarmult(&kA, k, &A);
    ge_add(&sum, &R, &kA);
    uint8_t lhs[32], rhs[32];
    ge_tobytes(lhs, &sB);
    ge_tobytes(rhs, &sum);
    return constant_time_equal(lhs, rhs, 32);
}

}  // namespace prim
}  // namespace polaris_secure
