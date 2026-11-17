//===- psi.cpp - keyed nonlinear window functions -------------------------===//
#include "hsvm/psi.h"

#include "hsvm/params.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace hsvm {

namespace {

struct SplitMix {
  uint64_t s;
  explicit SplitMix(uint64_t seed) : s(seed) {}
  uint64_t next() {
    uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
};

uint8_t gfMulSlow(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1)
      p ^= a;
    const bool hi = (a & 0x80) != 0;
    a = static_cast<uint8_t>(a << 1);
    if (hi)
      a ^= 0x1B;
    b = static_cast<uint8_t>(b >> 1);
  }
  return p;
}

// S-box = A * inv(x) + c, with A a random invertible 8x8 GF(2) matrix.
uint8_t applyAffine(uint8_t x, const uint64_t rows[8], uint8_t c) {
  uint8_t out = c;
  for (int i = 0; i < 8; ++i) {
    const uint8_t row = static_cast<uint8_t>(rows[i]);
    if (static_cast<unsigned>(__builtin_popcount(static_cast<unsigned>(row & x))) & 1u)
      out ^= static_cast<uint8_t>(1u << i);
  }
  return out;
}

// Invertible block matrices over GF(2^8) for the SPN linear layer.
const uint8_t kM2[2][2] = {{2, 1}, {1, 2}};
const uint8_t kM3[3][3] = {{2, 1, 1}, {1, 2, 1}, {1, 1, 2}};
const uint8_t kM4[4][4] = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};

inline uint8_t xtime(uint8_t x) {
  return static_cast<uint8_t>((x << 1) ^ ((x >> 7) * 0x1B));
}

// Coefficients in the diffusion matrices are only 1, 2 and 3, so the forward
// path never needs the generic GF multiply. Keeping this specialisation matters:
// the generic routine is a 8-iteration bit loop and dominated the cost probe.
inline uint8_t mulCoef(uint8_t a, uint8_t c) {
  switch (c) {
  case 1:
    return a;
  case 2:
    return xtime(a);
  case 3:
    return static_cast<uint8_t>(xtime(a) ^ a);
  default:
    return gf256Mul(a, c);
  }
}

void mixBlock(uint8_t *x, const uint8_t *m, uint32_t n, bool inverse) {
  uint8_t invFlat[16] = {};
  const uint8_t *mat = m;
  if (inverse) {
    // Gauss-Jordan inverse over GF(2^8) for n <= 4. The result is stored with
    // row stride n (not 4), because mat is indexed as mat[r * n + c].
    uint8_t aug[4][8] = {};
    for (uint32_t r = 0; r < n; ++r) {
      for (uint32_t c = 0; c < n; ++c)
        aug[r][c] = m[r * n + c];
      aug[r][n + r] = 1;
    }
    for (uint32_t col = 0; col < n; ++col) {
      uint32_t piv = col;
      while (piv < n && aug[piv][col] == 0)
        ++piv;
      assert(piv < n && "SPN diffusion matrix is singular");
      if (piv != col)
        for (uint32_t k = 0; k < 2 * n; ++k)
          std::swap(aug[piv][k], aug[col][k]);
      const uint8_t invPiv = gf256Inv(aug[col][col]);
      for (uint32_t k = 0; k < 2 * n; ++k)
        aug[col][k] = gf256Mul(aug[col][k], invPiv);
      for (uint32_t r = 0; r < n; ++r) {
        if (r == col || aug[r][col] == 0)
          continue;
        const uint8_t f = aug[r][col];
        for (uint32_t k = 0; k < 2 * n; ++k)
          aug[r][k] ^= gf256Mul(f, aug[col][k]);
      }
    }
    for (uint32_t r = 0; r < n; ++r)
      for (uint32_t c = 0; c < n; ++c)
        invFlat[r * n + c] = aug[r][n + c];
    mat = invFlat;
  }

  uint8_t out[4] = {};
  for (uint32_t r = 0; r < n; ++r) {
    uint8_t acc = 0;
    for (uint32_t c = 0; c < n; ++c)
      acc ^= mulCoef(x[c], mat[r * n + c]);
    out[r] = acc;
  }
  std::memcpy(x, out, n);
}

} // namespace

uint8_t gf256Mul(uint8_t a, uint8_t b) { return gfMulSlow(a, b); }

uint8_t gf256Inv(uint8_t a) {
  assert(a != 0 && "gf256Inv(0)");
  uint8_t r = 1;
  uint8_t base = a;
  unsigned e = 254;
  while (e) {
    if (e & 1)
      r = gfMulSlow(r, base);
    base = gfMulSlow(base, base);
    e >>= 1;
  }
  return r;
}

//---------------------------------------------------------------------------
// PsiTable
//---------------------------------------------------------------------------
PsiTable::PsiTable(uint32_t w, uint32_t c, uint64_t seed, uint32_t index)
    : w_(w), c_(c) {
  if (w > 16)
    throw std::invalid_argument("PsiTable: w > 16 needs the SPN family");
  const uint32_t n = 1u << w;
  table_.resize(n);
  inverse_.assign(n, 0);

  SplitMix sm(seed ^ (0xC2B2AE3D27D4EB4FULL * (index + 1)));
  std::vector<uint32_t> perm(n);
  for (uint32_t i = 0; i < n; ++i)
    perm[i] = i;
  for (uint32_t i = n; i > 1; --i) {
    const uint32_t j = static_cast<uint32_t>(sm.next() % i);
    std::swap(perm[i - 1], perm[j]);
  }
  const uint32_t mask = (c >= 32) ? 0xFFFFFFFFu : ((1u << c) - 1u);
  for (uint32_t x = 0; x < n; ++x)
    table_[x] = static_cast<uint16_t>(perm[x] & mask);

  if (c_ == w_) {
    for (uint32_t x = 0; x < n; ++x)
      inverse_[table_[x]] = static_cast<uint16_t>(x);
  }
}

BitVector PsiTable::apply(const BitVector &in) const {
  uint64_t idx = 0;
  for (uint32_t i = 0; i < w_; ++i)
    if (in.get(i))
      idx |= (1ULL << i);
  const uint64_t val = applyU64(idx);
  BitVector out(c_);
  for (uint32_t i = 0; i < c_; ++i)
    if ((val >> i) & 1ULL)
      out.set(i, true);
  return out;
}

uint64_t PsiTable::applyU64(uint64_t in) const {
  return table_[in & ((1ULL << w_) - 1ULL)];
}

BitVector PsiTable::invert(const BitVector &out) const {
  assert(c_ == w_ && "PsiTable::invert needs c == w");
  uint32_t idx = 0;
  for (uint32_t i = 0; i < c_; ++i)
    if (out.get(i))
      idx |= (1u << i);
  const uint16_t val = inverse_[idx];
  BitVector in(w_);
  for (uint32_t i = 0; i < w_; ++i)
    if ((val >> i) & 1u)
      in.set(i, true);
  return in;
}

//---------------------------------------------------------------------------
// PsiArx
//---------------------------------------------------------------------------
PsiArx::PsiArx(uint32_t w, uint32_t rounds, uint64_t seed, uint32_t index)
    : w_(w), rounds_(rounds) {
  if (w < 16 || w > 64 || w % 8 != 0)
    throw std::invalid_argument("PsiArx: w must be a multiple of 8 in [16,64]");
  if (rounds == 0)
    throw std::invalid_argument("PsiArx: rounds must be >= 1");
  SplitMix sm(seed ^ (0xD6E8FEB86659FD93ULL * (index + 1)));
  for (auto &k : keys_)
    k = sm.next();
}

namespace {
inline uint64_t rotl64(uint64_t x, uint32_t n) {
  return (x << n) | (x >> (64 - n));
}
} // namespace

uint64_t PsiArx::applyU64(uint64_t in) const {
  uint64_t x = in ^ keys_[0];
  for (uint32_t r = 0; r < rounds_; ++r) {
    x ^= rotl64(x, 13) + keys_[1 + (r % 7)];
    x += keys_[1 + ((r + 3) % 7)];
    x ^= rotl64(x, 29);
  }
  return (w_ == 64) ? x : (x & ((1ULL << w_) - 1ULL));
}

BitVector PsiArx::apply(const BitVector &in) const {
  uint64_t bits = 0;
  for (uint32_t i = 0; i < w_; ++i)
    if (in.get(i))
      bits |= (1ULL << i);
  const uint64_t out = applyU64(bits);
  BitVector res(w_);
  for (uint32_t i = 0; i < w_; ++i)
    if ((out >> i) & 1ULL)
      res.set(i, true);
  return res;
}

//---------------------------------------------------------------------------
// PsiSpn
//---------------------------------------------------------------------------
PsiSpn::PsiSpn(uint32_t w, uint32_t rounds, uint64_t seed, uint32_t index)
    : w_(w), lanes_(w / 8), rounds_(rounds) {
  if (w == 0 || w % 8 != 0 || lanes_ > 8)
    throw std::invalid_argument("PsiSpn: w must be a multiple of 8, at most 64");
  if (rounds == 0)
    throw std::invalid_argument("PsiSpn: rounds must be >= 1");

  SplitMix sm(seed ^ (0x165667B19E3779F9ULL * (index + 1)));

  // S-box = affine(inverse(x)); A is a random invertible 8x8 bit matrix.
  Rng rng(seed ^ (index + 1) ^ 0xA5A5A5A5A5A5A5A5ULL);
  BitMatrix m = BitMatrix::randomInvertible(8, rng);
  uint64_t rows[8] = {};
  for (int r = 0; r < 8; ++r) {
    uint8_t row = 0;
    for (int b = 0; b < 8; ++b)
      if (m.get(static_cast<uint32_t>(r), static_cast<uint32_t>(b)))
        row |= static_cast<uint8_t>(1u << b);
    rows[r] = row;
  }
  const uint8_t c = static_cast<uint8_t>(sm.next() & 0xFF);

  for (uint32_t x = 0; x < 256; ++x) {
    const uint8_t inv = (x == 0) ? 0 : gf256Inv(static_cast<uint8_t>(x));
    sbox_[x] = applyAffine(inv, rows, c);
  }
  for (uint32_t x = 0; x < 256; ++x)
    invSbox_[sbox_[x]] = static_cast<uint8_t>(x);

  roundKeys_.resize(static_cast<size_t>(rounds_ + 1) * lanes_);
  for (auto &k : roundKeys_)
    k = static_cast<uint8_t>(sm.next() & 0xFF);
}

uint64_t PsiSpn::runRounds(uint64_t in, bool inverse) const {
  uint8_t lane[8] = {};
  for (uint32_t i = 0; i < lanes_; ++i)
    lane[i] = static_cast<uint8_t>((in >> (8 * i)) & 0xFF);

  auto addKey = [&](uint32_t r) {
    for (uint32_t i = 0; i < lanes_; ++i)
      lane[i] ^= roundKeys_[static_cast<size_t>(r) * lanes_ + i];
  };
  auto mix = [&](bool inv) {
    uint32_t i = 0;
    while (i < lanes_) {
      const uint32_t left = lanes_ - i;
      if (left >= 4) {
        mixBlock(&lane[i], &kM4[0][0], 4, inv);
        i += 4;
      } else if (left == 3) {
        mixBlock(&lane[i], &kM3[0][0], 3, inv);
        i += 3;
      } else if (left == 2) {
        mixBlock(&lane[i], &kM2[0][0], 2, inv);
        i += 2;
      } else {
        i += 1; // single lane: no diffusion
      }
    }
  };
  auto rotateLeft = [&]() {
    const uint8_t first = lane[0];
    for (uint32_t i = 0; i + 1 < lanes_; ++i)
      lane[i] = lane[i + 1];
    lane[lanes_ - 1] = first;
  };
  auto rotateRight = [&]() {
    const uint8_t last = lane[lanes_ - 1];
    for (uint32_t i = lanes_ - 1; i > 0; --i)
      lane[i] = lane[i - 1];
    lane[0] = last;
  };

  if (!inverse) {
    addKey(0);
    for (uint32_t r = 0; r < rounds_; ++r) {
      for (uint32_t i = 0; i < lanes_; ++i)
        lane[i] = sbox_[lane[i]];
      mix(false);
      // Lane rotation makes diffusion cross block boundaries; without it each
      // 4-lane block stays independent and the avalanche test shows only
      // ~1/blocks of the output bits changing.
      if (lanes_ > 1)
        rotateLeft();
      addKey(r + 1);
    }
  } else {
    for (int r = static_cast<int>(rounds_) - 1; r >= 0; --r) {
      addKey(static_cast<uint32_t>(r) + 1);
      if (lanes_ > 1)
        rotateRight();
      mix(true);
      for (uint32_t i = 0; i < lanes_; ++i)
        lane[i] = invSbox_[lane[i]];
    }
    addKey(0);
  }

  uint64_t out = 0;
  for (uint32_t i = 0; i < lanes_; ++i)
    out |= static_cast<uint64_t>(lane[i]) << (8 * i);
  return out;
}

uint64_t PsiSpn::applyU64(uint64_t in) const {
  const uint64_t mask = (w_ == 64) ? ~0ULL : ((1ULL << w_) - 1ULL);
  return runRounds(in & mask, false);
}

BitVector PsiSpn::apply(const BitVector &in) const {
  uint64_t bits = 0;
  for (uint32_t i = 0; i < w_; ++i)
    if (in.get(i))
      bits |= (1ULL << i);
  const uint64_t out = applyU64(bits);
  BitVector res(w_);
  for (uint32_t i = 0; i < w_; ++i)
    if ((out >> i) & 1ULL)
      res.set(i, true);
  return res;
}

BitVector PsiSpn::invert(const BitVector &out) const {
  uint64_t bits = 0;
  for (uint32_t i = 0; i < w_; ++i)
    if (out.get(i))
      bits |= (1ULL << i);
  const uint64_t in = runRounds(bits, true);
  BitVector res(w_);
  for (uint32_t i = 0; i < w_; ++i)
    if ((in >> i) & 1ULL)
      res.set(i, true);
  return res;
}

std::unique_ptr<Psi> makePsi(const HsvmParams &p, uint32_t index) {
  if (p.psi == PsiMode::Table)
    return std::make_unique<PsiTable>(p.w, p.c, p.seed, index);
  if (p.psi == PsiMode::Arx)
    return std::make_unique<PsiArx>(p.w, p.rounds, p.seed, index);
  return std::make_unique<PsiSpn>(p.w, p.rounds, p.seed, index);
}

} // namespace hsvm
