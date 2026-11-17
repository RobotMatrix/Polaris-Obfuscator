//===- gf2.cpp - GF(2) bit-matrix primitives ------------------------------===//
//
// All matrices are small by cryptographic standards (N <= a few thousand bits),
// so elimination is a straightforward O(rows^2 * words) Gauss-Jordan pass.
// Correctness and clarity matter more than micro-optimisation here: this code
// is the oracle the compiler pass is measured against.
//
//===----------------------------------------------------------------------===//
#include "hsvm/gf2.h"

#include <cassert>
#include <stdexcept>

namespace hsvm {

namespace {

inline unsigned parity64(uint64_t v) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_popcountll(v) & 1u;
#else
  v ^= v >> 32;
  v ^= v >> 16;
  v ^= v >> 8;
  v ^= v >> 4;
  v &= 0x0f0f0f0f0f0f0f0fULL;
  return static_cast<unsigned>((v * 0x0101010101010101ULL) >> 56) & 1u;
#endif
}

inline void xorWords(uint64_t *__restrict dst, const uint64_t *__restrict src,
                     uint32_t n) {
  for (uint32_t i = 0; i < n; ++i)
    dst[i] ^= src[i];
}

} // namespace

//---------------------------------------------------------------------------
// BitVector
//---------------------------------------------------------------------------
BitVector::BitVector(uint32_t n, uint64_t init)
    : n_(n), w_(wordsFor(n), 0) {
  if (n_ > 0)
    w_[0] = init;
  maskTail();
}

void BitVector::maskTail() {
  if (n_ == 0 || w_.empty())
    return;
  const uint32_t tail = n_ % 64u;
  if (tail != 0)
    w_.back() &= (1ULL << tail) - 1ULL;
}

bool BitVector::get(uint32_t i) const {
  assert(i < n_ && "BitVector::get out of range");
  return (w_[i >> 6] >> (i & 63u)) & 1ULL;
}

void BitVector::set(uint32_t i, bool v) {
  assert(i < n_ && "BitVector::set out of range");
  const uint64_t mask = 1ULL << (i & 63u);
  if (v)
    w_[i >> 6] |= mask;
  else
    w_[i >> 6] &= ~mask;
}

void BitVector::flip(uint32_t i) {
  assert(i < n_ && "BitVector::flip out of range");
  w_[i >> 6] ^= 1ULL << (i & 63u);
}

uint32_t BitVector::popcount() const {
  uint32_t c = 0;
  for (uint64_t v : w_)
    c += static_cast<uint32_t>(__builtin_popcountll(v));
  return c;
}

void BitVector::xorWith(const BitVector &other) {
  assert(other.n_ == n_ && "BitVector size mismatch");
  for (uint32_t i = 0; i < w_.size(); ++i)
    w_[i] ^= other.w_[i];
}

bool BitVector::operator==(const BitVector &o) const {
  return n_ == o.n_ && w_ == o.w_;
}

BitVector BitVector::random(uint32_t n, Rng &rng) {
  BitVector v(n);
  for (auto &w : v.w_)
    w = rng();
  v.maskTail();
  return v;
}

//---------------------------------------------------------------------------
// BitMatrix
//---------------------------------------------------------------------------
BitMatrix::BitMatrix(uint32_t rows, uint32_t cols)
    : rows_(rows), cols_(cols), wpr_(wordsFor(cols)),
      d_(static_cast<size_t>(rows) * wpr_, 0) {}

bool BitMatrix::get(uint32_t r, uint32_t c) const {
  assert(r < rows_ && c < cols_ && "BitMatrix::get out of range");
  return (d_[static_cast<size_t>(r) * wpr_ + (c >> 6)] >> (c & 63u)) & 1ULL;
}

void BitMatrix::set(uint32_t r, uint32_t c, bool v) {
  assert(r < rows_ && c < cols_ && "BitMatrix::set out of range");
  uint64_t &w = d_[static_cast<size_t>(r) * wpr_ + (c >> 6)];
  const uint64_t mask = 1ULL << (c & 63u);
  if (v)
    w |= mask;
  else
    w &= ~mask;
}

void BitMatrix::flip(uint32_t r, uint32_t c) {
  assert(r < rows_ && c < cols_ && "BitMatrix::flip out of range");
  d_[static_cast<size_t>(r) * wpr_ + (c >> 6)] ^= 1ULL << (c & 63u);
}

void BitMatrix::xorRow(uint32_t dst, uint32_t src) {
  assert(dst < rows_ && src < rows_ && "BitMatrix::xorRow out of range");
  uint64_t *d = d_.data() + static_cast<size_t>(dst) * wpr_;
  const uint64_t *s = d_.data() + static_cast<size_t>(src) * wpr_;
  xorWords(d, s, wpr_);
}

void BitMatrix::swapRows(uint32_t a, uint32_t b) {
  assert(a < rows_ && b < rows_ && "BitMatrix::swapRows out of range");
  if (a == b)
    return;
  uint64_t *pa = d_.data() + static_cast<size_t>(a) * wpr_;
  uint64_t *pb = d_.data() + static_cast<size_t>(b) * wpr_;
  for (uint32_t i = 0; i < wpr_; ++i)
    std::swap(pa[i], pb[i]);
}

uint32_t BitMatrix::rowPopcount(uint32_t r) const {
  assert(r < rows_ && "BitMatrix::rowPopcount out of range");
  const uint64_t *p = d_.data() + static_cast<size_t>(r) * wpr_;
  uint32_t c = 0;
  for (uint32_t i = 0; i < wpr_; ++i)
    c += static_cast<uint32_t>(__builtin_popcountll(p[i]));
  return c;
}

void BitMatrix::maskRow(uint32_t r) {
  const uint32_t tail = cols_ % 64u;
  if (tail == 0)
    return;
  d_[static_cast<size_t>(r) * wpr_ + (wpr_ - 1)] &= (1ULL << tail) - 1ULL;
}

BitMatrix BitMatrix::zeros(uint32_t rows, uint32_t cols) {
  return BitMatrix(rows, cols);
}

BitMatrix BitMatrix::identity(uint32_t n) {
  BitMatrix m(n, n);
  for (uint32_t i = 0; i < n; ++i)
    m.set(i, i, true);
  return m;
}

BitMatrix BitMatrix::randomFullRowRank(uint32_t rows, uint32_t cols,
                                       Rng &rng) {
  if (rows > cols)
    throw std::invalid_argument("randomFullRowRank: rows > cols");
  for (unsigned attempt = 0; attempt < 10000; ++attempt) {
    BitMatrix m(rows, cols);
    for (uint32_t r = 0; r < rows; ++r) {
      uint64_t *p = m.rowData(r);
      for (uint32_t i = 0; i < m.wordsPerRow(); ++i)
        p[i] = rng();
      m.maskRow(r);
    }
    if (rank(m) == rows)
      return m;
  }
  throw std::runtime_error("randomFullRowRank: could not reach full rank");
}

BitMatrix BitMatrix::randomInvertible(uint32_t n, Rng &rng) {
  for (unsigned attempt = 0; attempt < 10000; ++attempt) {
    BitMatrix m(n, n);
    for (uint32_t r = 0; r < n; ++r) {
      uint64_t *p = m.rowData(r);
      for (uint32_t i = 0; i < m.wordsPerRow(); ++i)
        p[i] = rng();
      m.maskRow(r);
    }
    if (rank(m) == n)
      return m;
  }
  throw std::runtime_error("randomInvertible: could not reach full rank");
}

bool BitMatrix::operator==(const BitMatrix &o) const {
  return rows_ == o.rows_ && cols_ == o.cols_ && d_ == o.d_;
}

//---------------------------------------------------------------------------
// Elimination
//---------------------------------------------------------------------------
RrefResult rref(const BitMatrix &a) {
  RrefResult res;
  res.rref = a;
  const uint32_t rows = a.rows();
  const uint32_t cols = a.cols();
  uint32_t pivotRow = 0;

  for (uint32_t c = 0; c < cols && pivotRow < rows; ++c) {
    uint32_t p = rows;
    for (uint32_t r = pivotRow; r < rows; ++r) {
      if (res.rref.get(r, c)) {
        p = r;
        break;
      }
    }
    if (p == rows)
      continue;
    res.rref.swapRows(pivotRow, p);
    for (uint32_t r = 0; r < rows; ++r) {
      if (r != pivotRow && res.rref.get(r, c))
        res.rref.xorRow(r, pivotRow);
    }
    res.pivots.push_back(c);
    ++pivotRow;
  }
  res.rank = pivotRow;
  return res;
}

uint32_t rank(const BitMatrix &a) { return rref(a).rank; }

BitMatrix kernelBasis(const BitMatrix &a) {
  const uint32_t n = a.cols();
  const RrefResult rr = rref(a);
  const uint32_t nullity = n - rr.rank;

  std::vector<bool> isPivot(n, false);
  for (uint32_t p : rr.pivots)
    isPivot[p] = true;

  BitMatrix basis(n, nullity);
  uint32_t col = 0;
  for (uint32_t freeCol = 0; freeCol < n; ++freeCol) {
    if (isPivot[freeCol])
      continue;
    // x_free = 1, all other free variables 0; pivot variables follow from
    // the row-reduced equations x_p + sum_f rref[i][f] * x_f = 0.
    basis.set(freeCol, col, true);
    for (uint32_t i = 0; i < rr.rank; ++i)
      basis.set(rr.pivots[i], col, rr.rref.get(i, freeCol));
    ++col;
  }
  assert(col == nullity && "kernelBasis: column count mismatch");
  return basis;
}

std::optional<BitVector> solve(const BitMatrix &a, const BitVector &b) {
  assert(b.size() == a.rows() && "solve: b has wrong length");

  BitMatrix m = a;
  BitVector rhs = b;
  const uint32_t rows = a.rows();
  const uint32_t cols = a.cols();
  uint32_t pivotRow = 0;
  std::vector<uint32_t> pivots;

  for (uint32_t c = 0; c < cols && pivotRow < rows; ++c) {
    uint32_t p = rows;
    for (uint32_t r = pivotRow; r < rows; ++r) {
      if (m.get(r, c)) {
        p = r;
        break;
      }
    }
    if (p == rows)
      continue;
    m.swapRows(pivotRow, p);
    if (pivotRow != p && rhs.get(pivotRow) != rhs.get(p)) {
      rhs.flip(pivotRow);
      rhs.flip(p);
    }

    for (uint32_t r = 0; r < rows; ++r) {
      if (r == pivotRow || !m.get(r, c))
        continue;
      m.xorRow(r, pivotRow);
      if (rhs.get(pivotRow))
        rhs.flip(r);
    }
    pivots.push_back(c);
    ++pivotRow;
  }

  // Inconsistent rows: all-zero left side but a set right-hand bit.
  for (uint32_t r = pivotRow; r < rows; ++r) {
    if (m.rowPopcount(r) == 0 && rhs.get(r))
      return std::nullopt;
  }

  BitVector s(cols); // free variables stay zero
  for (uint32_t i = 0; i < pivots.size(); ++i)
    if (rhs.get(i))
      s.set(pivots[i], true);
  return s;
}

//---------------------------------------------------------------------------
// Products
//---------------------------------------------------------------------------
BitVector matVec(const BitMatrix &a, const BitVector &x) {
  assert(x.size() == a.cols() && "matVec: dimension mismatch");
  BitVector out(a.rows());
  const uint32_t wpr = a.wordsPerRow();
  for (uint32_t r = 0; r < a.rows(); ++r) {
    const uint64_t *row = a.rowData(r);
    uint64_t acc = 0;
    for (uint32_t i = 0; i < wpr; ++i)
      acc ^= row[i] & x.word(i);
    if (parity64(acc))
      out.set(r, true);
  }
  return out;
}

BitMatrix multiply(const BitMatrix &a, const BitMatrix &b) {
  assert(a.cols() == b.rows() && "multiply: dimension mismatch");
  BitMatrix out(a.rows(), b.cols());
  for (uint32_t r = 0; r < a.rows(); ++r) {
    const uint64_t *arow = a.rowData(r);
    for (uint32_t c = 0; c < a.cols(); ++c) {
      if (!((arow[c >> 6] >> (c & 63u)) & 1ULL))
        continue;
      const uint64_t *brow = b.rowData(c);
      uint64_t *orow = out.rowData(r);
      xorWords(orow, brow, out.wordsPerRow());
    }
  }
  return out;
}

BitMatrix transpose(const BitMatrix &a) {
  BitMatrix out(a.cols(), a.rows());
  for (uint32_t r = 0; r < a.rows(); ++r)
    for (uint32_t c = 0; c < a.cols(); ++c)
      if (a.get(r, c))
        out.set(c, r, true);
  return out;
}

} // namespace hsvm
