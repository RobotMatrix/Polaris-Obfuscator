//===- test_gf2.cpp - GF(2) library tests ---------------------------------===//
//
// Every test that can be a negative control is written as one: a matrix that
// MUST be rejected (inconsistent system) or a rank that MUST come out lower.
// A library that only passes positive cases is not evidence.
//
//===----------------------------------------------------------------------===//
#include "hsvm/gf2.h"
#include "test_harness.h"

#include <cstdio>
#include <stdexcept>
#include <vector>

using namespace hsvm;

namespace {

BitMatrix fromRows(const std::vector<std::vector<int>> &rows) {
  BitMatrix m(static_cast<uint32_t>(rows.size()),
              rows.empty() ? 0u : static_cast<uint32_t>(rows[0].size()));
  for (uint32_t r = 0; r < m.rows(); ++r)
    for (uint32_t c = 0; c < m.cols(); ++c)
      m.set(r, c, rows[r][c] != 0);
  return m;
}

BitVector vec(std::initializer_list<int> bits) {
  BitVector v(static_cast<uint32_t>(bits.size()));
  uint32_t i = 0;
  for (int b : bits)
    v.set(i++, b != 0);
  return v;
}

void testRankKnown() {
  // r2 == r0 ^ r1, so rank must be 2, not 3.
  BitMatrix a = fromRows({{1, 1, 0, 0, 1},
                          {0, 1, 1, 0, 0},
                          {1, 0, 1, 0, 1}});
  CHECK(rank(a) == 2, "known 3x5 rank == 2");

  BitMatrix e = fromRows({{1, 0, 0}, {0, 1, 0}, {0, 0, 1}});
  CHECK(rank(e) == 3, "3x3 identity rank == 3");

  BitMatrix z(4, 7);
  CHECK(rank(z) == 0, "zero matrix rank == 0");

  BitMatrix dup = fromRows({{1, 1, 0}, {1, 1, 0}});
  CHECK(rank(dup) == 1, "duplicate rows rank == 1");
}

void testKernelKnown() {
  BitMatrix a = fromRows({{1, 1, 0, 0, 1},
                          {0, 1, 1, 0, 0},
                          {1, 0, 1, 0, 1}});
  BitMatrix k = kernelBasis(a);
  CHECK(k.rows() == 5, "kernel has one row per state bit");
  CHECK(k.cols() == 3, "kernel nullity == 3 for rank-2 3x5");

  CHECK(matVec(a, matVec(k, BitVector(3))).popcount() == 0,
        "A * B_K * 0 == 0");
  for (uint32_t c = 0; c < k.cols(); ++c) {
    BitVector e(k.cols());
    e.set(c, true);
    BitVector v = matVec(k, e);
    CHECK(matVec(a, v).popcount() == 0, "A * B_K column == 0");
    CHECK(v.popcount() >= 1, "kernel column is nonzero");
  }
  CHECK(rank(k) == 3, "rank(B_K) == N - rank(A)");
}

void testKernelZeroMatrix() {
  BitMatrix z(3, 9);
  BitMatrix k = kernelBasis(z);
  CHECK(k.rows() == 9 && k.cols() == 9, "ker(0) is 9-dimensional");
  CHECK(k == BitMatrix::identity(9), "ker(0) basis is the identity");
}

void testSolve() {
  // Simple full-rank triangular system.
  BitMatrix a = fromRows({{1, 1, 0}, {0, 1, 1}});
  auto s = solve(a, vec({1, 0}));
  CHECK(s.has_value(), "consistent system solved");
  if (s)
    CHECK(matVec(a, *s) == vec({1, 0}), "A*s == b");

  // Pivot requires a row swap: rhs must move with it.
  BitMatrix sw = fromRows({{0, 1}, {1, 0}});
  auto s2 = solve(sw, vec({1, 0}));
  CHECK(s2.has_value() && s2->get(0) == 0 && s2->get(1) == 1,
        "row swap carries rhs (s == (0,1))");

  // Inconsistent: identical left rows, different right-hand bits.
  BitMatrix inc = fromRows({{1, 0, 0}, {1, 0, 0}});
  CHECK(!solve(inc, vec({1, 0})).has_value(), "inconsistent system rejected");
  auto s3 = solve(inc, vec({1, 1}));
  CHECK(s3.has_value(), "consistent duplicate rows still solved");
  if (s3)
    CHECK(matVec(inc, *s3) == vec({1, 1}), "duplicate rows: A*s == b");

  // Zero matrix: every rhs must be zero, otherwise no solution.
  BitMatrix z(2, 4);
  CHECK(solve(z, vec({0, 0})).has_value(), "zero matrix, zero rhs solvable");
  CHECK(!solve(z, vec({0, 1})).has_value(), "zero matrix, nonzero rhs rejected");
}

BitMatrix randomDense(uint32_t rows, uint32_t cols, Rng &rng) {
  BitMatrix m(rows, cols);
  for (uint32_t r = 0; r < rows; ++r)
    for (uint32_t c = 0; c < cols; ++c)
      m.set(r, c, (rng() & 1ULL) != 0);
  return m;
}

void testProducts() {
  Rng rng(12345);
  BitMatrix a = BitMatrix::randomFullRowRank(2, 5, rng);
  BitMatrix b = randomDense(5, 3, rng);
  BitVector x = BitVector::random(3, rng);

  CHECK(matVec(multiply(a, b), x) == matVec(a, matVec(b, x)),
        "(A*B)*x == A*(B*x)");
  CHECK(multiply(BitMatrix::identity(2), a) == a, "I*A == A");
  CHECK(multiply(a, BitMatrix::identity(5)) == a, "A*I == A");

  BitMatrix t = transpose(a);
  CHECK(t.rows() == a.cols() && t.cols() == a.rows(), "transpose shape");
  CHECK(transpose(t) == a, "transpose is an involution");
}

void testRandomHelpers() {
  Rng rng(6789);
  const uint32_t m = 8, n = 20;
  BitMatrix h = BitMatrix::randomFullRowRank(m, n, rng);
  CHECK(rank(h) == m, "randomFullRowRank reaches requested rank");

  BitMatrix k = kernelBasis(h);
  CHECK(k.cols() == n - m, "kernel nullity == N - m");
  for (uint32_t c = 0; c < k.cols(); ++c) {
    BitVector e(k.cols());
    e.set(c, true);
    CHECK(matVec(h, matVec(k, e)).popcount() == 0, "H * B_K == 0");
  }

  const uint32_t d = 24;
  BitMatrix inv = BitMatrix::randomInvertible(d, rng);
  CHECK(rank(inv) == d, "randomInvertible has full rank");
  bool allOk = true;
  for (int i = 0; i < 200; ++i) {
    BitVector x2 = BitVector::random(d, rng);
    auto s = solve(inv, x2);
    if (!s || matVec(inv, *s) != x2)
      allOk = false;
  }
  CHECK(allOk, "solve(M, x) reproduces x for invertible M");
}

void testKernelUniformSampling() {
  Rng rng(4242);
  const uint32_t m = 6, n = 14;
  BitMatrix h = BitMatrix::randomFullRowRank(m, n, rng);
  BitMatrix k = kernelBasis(h);
  CHECK(k.cols() == n - m, "uniform-sampling setup nullity");

  // 10k samples must stay in the kernel and span it (rank == nullity).
  std::vector<BitVector> keep;
  for (int i = 0; i < 10000; ++i) {
    BitVector r = BitVector::random(k.cols(), rng);
    BitVector delta = matVec(k, r);
    if (matVec(h, delta).popcount() != 0) {
      CHECK(false, "sampled delta left the kernel");
      return;
    }
    if (i < 2000)
      keep.push_back(delta);
  }
  BitMatrix span(n, static_cast<uint32_t>(keep.size()));
  for (uint32_t c = 0; c < span.cols(); ++c)
    for (uint32_t r = 0; r < n; ++r)
      span.set(r, c, keep[c].get(r));
  CHECK(rank(span) == n - m, "2000 samples span the whole kernel");
}

void testOddDimensions() {
  // 65 columns exercises the masked tail word.
  Rng rng(777);
  BitMatrix h = BitMatrix::randomFullRowRank(5, 65, rng);
  CHECK(rank(h) == 5, "rank with 65 columns");
  BitMatrix k = kernelBasis(h);
  CHECK(k.rows() == 65 && k.cols() == 60, "kernel shape with tail word");
  for (uint32_t c = 0; c < k.cols(); ++c) {
    BitVector e(k.cols());
    e.set(c, true);
    CHECK(matVec(h, matVec(k, e)).popcount() == 0, "H*B_K == 0 (tail word)");
  }

  // 0 rows: everything is in the kernel.
  BitMatrix empty(0, 65);
  CHECK(rank(empty) == 0, "0-row matrix rank == 0");
  CHECK(kernelBasis(empty).cols() == 65, "0-row matrix kernel == full space");
}

void testTargetSize() {
  // N = 512, m = 256 is the plan's first real parameter point.
  Rng rng(2026);
  BitMatrix h = BitMatrix::randomFullRowRank(256, 512, rng);
  CHECK(rank(h) == 256, "512-bit H is full row rank");

  BitMatrix k = kernelBasis(h);
  CHECK(k.cols() == 256, "512-bit kernel nullity == 256");

  BitVector x = BitVector::random(256, rng);
  auto s = solve(h, x);
  CHECK(s.has_value(), "512-bit system solvable");
  if (s)
    CHECK(matVec(h, *s) == x, "512-bit solve roundtrip");

  // A sampled kernel direction must project to zero.
  BitVector r = BitVector::random(256, rng);
  CHECK(matVec(h, matVec(k, r)).popcount() == 0, "512-bit H * B_K * r == 0");
}

} // namespace

int main() {
  testRankKnown();
  testKernelKnown();
  testKernelZeroMatrix();
  testSolve();
  testProducts();
  testRandomHelpers();
  testKernelUniformSampling();
  testOddDimensions();
  testTargetSize();
  return hsvm_test::summary("gf2");
}
