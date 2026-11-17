//===- gf2.h - GF(2) bit-matrix primitives ---------------------*- C++ -*-===//
//
// Part of the HSV (hidden-state VM) research harness.
//
// Everything here is row-major over little-endian 64-bit words:
//   bit (r, c) lives in row r, word c / 64, bit c % 64.
// Rows are kept masked in the last word so unused bits never contribute.
//
// The research plan needs exactly these primitives (M0-2):
//   rank, kernel basis (B_K with H * B_K = 0), particular solve (H*s = x),
//   random full-row-rank H, random invertible M, mat-vec and mat-mat products.
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_GF2_H
#define HSV_M_GF2_H

#include <cstdint>
#include <optional>
#include <random>
#include <vector>

namespace hsvm {

using Rng = std::mt19937_64;

constexpr uint32_t wordsFor(uint32_t bits) { return (bits + 63u) / 64u; }

//---------------------------------------------------------------------------
// BitVector: fixed-length vector over GF(2)
//---------------------------------------------------------------------------
class BitVector {
public:
  BitVector() = default;
  explicit BitVector(uint32_t n, uint64_t init = 0);

  uint32_t size() const { return n_; }
  bool empty() const { return n_ == 0; }

  bool get(uint32_t i) const;
  void set(uint32_t i, bool v);
  void flip(uint32_t i);
  void clear() { w_.assign(w_.size(), 0); }

  uint32_t popcount() const;
  uint64_t word(uint32_t i) const { return w_[i]; }
  const uint64_t *words() const { return w_.data(); }
  uint64_t *words() { return w_.data(); }

  void xorWith(const BitVector &other);

  bool operator==(const BitVector &o) const;
  bool operator!=(const BitVector &o) const { return !(*this == o); }

  static BitVector random(uint32_t n, Rng &rng);

private:
  void maskTail();

  uint32_t n_ = 0;
  std::vector<uint64_t> w_;
};

//---------------------------------------------------------------------------
// BitMatrix: rows x cols matrix over GF(2)
//---------------------------------------------------------------------------
class BitMatrix {
public:
  BitMatrix() = default;
  BitMatrix(uint32_t rows, uint32_t cols);

  uint32_t rows() const { return rows_; }
  uint32_t cols() const { return cols_; }
  uint32_t wordsPerRow() const { return wpr_; }

  bool get(uint32_t r, uint32_t c) const;
  void set(uint32_t r, uint32_t c, bool v);
  void flip(uint32_t r, uint32_t c);

  // Whole-row operations, used by elimination and by the encoders later.
  void xorRow(uint32_t dst, uint32_t src);
  void swapRows(uint32_t a, uint32_t b);
  uint32_t rowPopcount(uint32_t r) const;

  // Low-level access for elimination-heavy code (documented, checked).
  uint64_t *rowData(uint32_t r) { return d_.data() + r * wpr_; }
  const uint64_t *rowData(uint32_t r) const { return d_.data() + r * wpr_; }

  static BitMatrix zeros(uint32_t rows, uint32_t cols);
  static BitMatrix identity(uint32_t n);
  static BitMatrix randomFullRowRank(uint32_t rows, uint32_t cols, Rng &rng);
  static BitMatrix randomInvertible(uint32_t n, Rng &rng);

  bool operator==(const BitMatrix &o) const;
  bool operator!=(const BitMatrix &o) const { return !(*this == o); }

private:
  void maskRow(uint32_t r);

  uint32_t rows_ = 0;
  uint32_t cols_ = 0;
  uint32_t wpr_ = 0;
  std::vector<uint64_t> d_;
};

//---------------------------------------------------------------------------
// Elimination results
//---------------------------------------------------------------------------
struct RrefResult {
  uint32_t rank = 0;
  std::vector<uint32_t> pivots; // pivot column of each pivot row, ascending
  BitMatrix rref;               // row-reduced echelon form
};

RrefResult rref(const BitMatrix &a);
uint32_t rank(const BitMatrix &a);

// Basis of ker(a): returns a (cols x nullity) matrix whose COLUMNS form a
// basis, so matVec(basis, r) is a uniform sample of ker(a) for uniform r.
BitMatrix kernelBasis(const BitMatrix &a);

// Any solution s of a*s = b, or nullopt when the system is inconsistent.
// Free variables are set to zero; callers must not assume uniqueness.
std::optional<BitVector> solve(const BitMatrix &a, const BitVector &b);

// Linear algebra products.
BitVector matVec(const BitMatrix &a, const BitVector &x);
BitMatrix multiply(const BitMatrix &a, const BitMatrix &b);
BitMatrix transpose(const BitMatrix &a);

} // namespace hsvm

#endif // HSV_M_GF2_H
