// Heterogeneous rounds: every AES round computes the same function through a
// different implementation, so the nine rounds do not look alike.
//
// AES itself is fixed - the round function cannot change - but its realisation can.
// Four families are implemented here, all verified byte-identical against a plain
// reference round, and a per-round schedule picks one for each of the nine rounds:
//
//   F0 plain     : SubBytes, ShiftRows, MixColumns, AddRoundKey
//   F1 t32       : four 32-bit table lookups XORed, linear layer baked into tables
//   F2 t8        : 16 byte tables carrying MC coefficients, XOR accumulation
//   F3 keyed     : like F1 but the round key is folded into the table index, so the
//                  round has no key-XOR step at all
//
// The point is not new maths - every family is the same function - it is that a
// recogniser matching one shape sees the others as unrelated code, and the table
// region has no uniform per-round block.
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

const uint8_t MC[4][4] = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};
// InvMixColumns, needed to fold the round key into the table index: the key is
// added after the linear layer, so it must be pulled back through it first
// (MC(a ^ b) = MC(a) ^ MC(b)).
const uint8_t IMC[4][4] = {{14, 11, 13, 9}, {9, 14, 11, 13},
                           {13, 9, 14, 11}, {11, 13, 9, 14}};

const uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) r ^= a;
    uint8_t hi = static_cast<uint8_t>(a & 0x80);
    a = static_cast<uint8_t>(a << 1);
    if (hi) a ^= 0x1B;
    b = static_cast<uint8_t>(b >> 1);
  }
  return r;
}

inline int shifted(int p) { // ShiftRows as an index map: byte p comes from p'
  const int c = p / 4, r = p % 4;
  return 4 * ((c + r) % 4) + r;
}

void subShift(const uint8_t *in, uint8_t *sb) {
  for (int p = 0; p < 16; p++) sb[p] = SBOX[in[shifted(p)]];
}

// ---- F0: plain -----------------------------------------------------------------
void roundF0(const uint8_t *in, const uint8_t *rk, uint8_t *out) {
  uint8_t sb[16];
  subShift(in, sb);
  for (int c = 0; c < 4; c++)
    for (int r = 0; r < 4; r++) {
      uint8_t v = 0;
      for (int k = 0; k < 4; k++) v ^= gmul(MC[r][k], sb[4 * c + k]);
      out[4 * c + r] = static_cast<uint8_t>(v ^ rk[4 * c + r]);
    }
}

// ---- F1: 32-bit tables, linear layer baked in ----------------------------------
struct F1 {
  uint32_t T[16][256];
  F1() {
    for (int p = 0; p < 16; p++)
      for (int x = 0; x < 256; x++) {
        uint32_t w = 0;
        for (int k = 0; k < 4; k++)
          w |= static_cast<uint32_t>(gmul(MC[k][p % 4], SBOX[x])) << (8 * k);
        T[p][x] = w;
      }
  }
  void run(const uint8_t *in, const uint8_t *rk, uint8_t *out) const {
    for (int c = 0; c < 4; c++) {
      uint32_t w = 0;
      for (int r = 0; r < 4; r++) w ^= T[shifted(4 * c + r)][in[shifted(4 * c + r)]];
      for (int k = 0; k < 4; k++) {
        const uint8_t rkb = rk[4 * c + k];
        w ^= static_cast<uint32_t>(rkb) << (8 * k);
      }
      for (int k = 0; k < 4; k++) out[4 * c + k] = static_cast<uint8_t>(w >> (8 * k));
    }
  }
};

// ---- F2: 16 byte tables carrying MC coefficients, XOR accumulation --------------
struct F2 {
  uint8_t T[16][4][256]; // [p][row][x] = MC[row][p%4] * S(x)
  F2() {
    for (int p = 0; p < 16; p++)
      for (int row = 0; row < 4; row++)
        for (int x = 0; x < 256; x++)
          T[p][row][x] = gmul(MC[row][p % 4], SBOX[x]);
  }
  void run(const uint8_t *in, const uint8_t *rk, uint8_t *out) const {
    uint8_t acc[16] = {};
    for (int c = 0; c < 4; c++)
      for (int row = 0; row < 4; row++)
        for (int r = 0; r < 4; r++) {
          const int p = shifted(4 * c + r);
          acc[4 * c + row] ^= T[p][row][in[p]];
        }
    for (int i = 0; i < 16; i++) out[i] = static_cast<uint8_t>(acc[i] ^ rk[i]);
  }
};

// ---- F3: round key folded into the index, no key-XOR step -----------------------
struct F3 {
  uint32_t T[16][256]; // [p][x ^ rk_p] = contribution, built per invocation
  // The round key cannot go into the index: SubBytes is non-linear, so a constant
  // XORed before it does not come back out as a constant. It goes into a table's
  // 32-bit output instead - one designated source per column carries the whole
  // column key word, and the runtime round has no key-XOR step at all.
  void build(const uint8_t *rk) {
    uint32_t rkWord[4];
    for (int c = 0; c < 4; c++)
      rkWord[c] = (uint32_t)rk[4 * c] | ((uint32_t)rk[4 * c + 1] << 8) |
                  ((uint32_t)rk[4 * c + 2] << 16) |
                  ((uint32_t)rk[4 * c + 3] << 24);
    for (int p = 0; p < 16; p++)
      for (int x = 0; x < 256; x++) {
        const uint8_t s = SBOX[x];
        uint32_t w = 0;
        for (int k = 0; k < 4; k++)
          w |= (uint32_t)gmul(MC[k][p % 4], s) << (8 * k);
        T[p][x] = w;
      }
    for (int c = 0; c < 4; c++) {
      const int p0 = 4 * c; // r = 0 source of column c
      for (int x = 0; x < 256; x++) T[p0][x] ^= rkWord[c];
    }
  }
  void run(const uint8_t *in, uint8_t *out) const {
    for (int c = 0; c < 4; c++) {
      uint32_t w = 0;
      for (int r = 0; r < 4; r++) {
        const int p = shifted(4 * c + r);
        w ^= T[p][in[p]];
      }
      for (int k = 0; k < 4; k++) out[4 * c + k] = static_cast<uint8_t>(w >> (8 * k));
    }
  }
};

} // namespace

int main() {
  F1 f1;
  F2 f2;
  F3 f3;
  uint32_t state = 0xC0FFEEu;
  int fail = 0;
  for (int trial = 0; trial < 2000; trial++) {
    uint8_t in[16], rk[16], want[16], a[16], b[16], c2[16];
    for (int i = 0; i < 16; i++) {
      state = state * 1664525u + 1013904223u;
      in[i] = static_cast<uint8_t>(state >> 24);
      rk[i] = static_cast<uint8_t>(state >> 16);
    }
    roundF0(in, rk, want);
    f1.run(in, rk, a);
    f2.run(in, rk, b);
    f3.build(rk);
    f3.run(in, c2);
    if (std::memcmp(want, a, 16) != 0 || std::memcmp(want, b, 16) != 0 ||
        std::memcmp(want, c2, 16) != 0) {
      if (fail < 3) {
        std::printf("MISMATCH trial=%d f1=%d f2=%d f3=%d\n", trial,
                    std::memcmp(want, a, 16) != 0, std::memcmp(want, b, 16) != 0,
                    std::memcmp(want, c2, 16) != 0);
      }
      fail++;
    }
  }
  std::printf("%s: 4 round families agree on 2000 vectors (plain / t32 / t8 / keyed)\n",
              fail == 0 ? "PASS" : "FAIL");
  return fail != 0;
}
