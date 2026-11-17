// Reference model for wide-trail (Chow-style) fusion of the AES round.
//
// Goal: the round function stops looking like "SubBytes, ShiftRows, MixColumns,
// AddRoundKey" and becomes "four 32-bit table lookups XORed together". There is no
// explicit MixColumns matrix in the table path - the linear map is baked into the
// tables' 32-bit outputs - so a reader of the code cannot recover the round
// structure from the operations, only from the (encoded) tables.
//
// This is the reference the production generator must reproduce; it is deliberately
// small and verifiable: the T-box path must agree with a plain AES-128 on random
// vectors, otherwise the construction is wrong and nothing downstream is worth
// building.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

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

uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) r ^= a;
    uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1B;
    b >>= 1;
  }
  return r;
}

// T[p][x]: contribution of state byte p (after SubBytes) to the 32-bit word of its
// target column. p = 4*column + row; ShiftRows sends (col,row) -> (col+row, row),
// i.e. byte p contributes to the column (p/4 + p%4) % 4.
struct FusionModel {
  uint32_t T[16][256];

  FusionModel() {
    for (int p = 0; p < 16; p++) {
      const int row = p % 4;
      for (int x = 0; x < 256; x++) {
        const uint8_t s = SBOX[x];
        uint32_t word = 0;
        for (int k = 0; k < 4; k++)
          word |= (uint32_t)gmul(MC[k][row], s) << (8 * k);
        T[p][x] = word;
      }
    }
  }

  // One round: four 32-bit lookups XORed per column, no matrix, no ShiftRows step.
  void round(const uint8_t *in, const uint8_t *rk, uint8_t *out) const {
    for (int c = 0; c < 4; c++) {
      uint32_t w = 0;
      for (int row = 0; row < 4; row++) {
        const int p = 4 * ((c + row) % 4) + row;
        w ^= T[p][in[p]];
      }
      const uint32_t rkw = (uint32_t)rk[4 * c] | ((uint32_t)rk[4 * c + 1] << 8) |
                           ((uint32_t)rk[4 * c + 2] << 16) |
                           ((uint32_t)rk[4 * c + 3] << 24);
      w ^= rkw;
      for (int k = 0; k < 4; k++)
        out[4 * c + k] = (uint8_t)(w >> (8 * k));
    }
  }
};

// Plain AES-128 round, for the cross-check.
void plainRound(const uint8_t *in, const uint8_t *rk, uint8_t *out) {
  uint8_t sb[16];
  for (int i = 0; i < 16; i++) sb[i] = SBOX[in[i]];
  uint8_t sr[16];
  for (int c = 0; c < 4; c++)
    for (int r = 0; r < 4; r++) sr[4 * c + r] = sb[4 * ((c + r) % 4) + r];
  for (int c = 0; c < 4; c++) {
    uint8_t col[4];
    for (int r = 0; r < 4; r++) {
      uint8_t v = 0;
      for (int k = 0; k < 4; k++) v ^= gmul(MC[r][k], sr[4 * c + k]);
      col[r] = v;
    }
    for (int r = 0; r < 4; r++) out[4 * c + r] = (uint8_t)(col[r] ^ rk[4 * c + r]);
  }
}

} // namespace

int main() {
  FusionModel model;
  uint32_t state = 0x12345678u;
  int fail = 0;
  for (int trial = 0; trial < 2000; trial++) {
    uint8_t in[16], rk[16], a[16], b[16];
    for (int i = 0; i < 16; i++) {
      state = state * 1664525u + 1013904223u;
      in[i] = (uint8_t)(state >> 24);
      rk[i] = (uint8_t)(state >> 16);
    }
    model.round(in, rk, a);
    plainRound(in, rk, b);
    if (std::memcmp(a, b, 16) != 0) {
      if (fail < 3) std::printf("MISMATCH trial=%d\n", trial);
      fail++;
    }
  }
  std::printf("%s: fused 32-bit T-box round == SubBytes+ShiftRows+MixColumns+AddRoundKey on 2000 vectors\n",
              fail == 0 ? "PASS" : "FAIL");
  return fail != 0;
}
