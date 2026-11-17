//===- test_psi.cpp - nonlinear window function tests ---------------------===//
#include "hsvm/psi.h"
#include "test_harness.h"

#include <cmath>
#include <cstdio>
#include <set>
#include <vector>

using namespace hsvm;

namespace {

void testGf256() {
  CHECK(gf256Mul(0x57, 0x83) == 0xC1, "GF(2^8) reference product 57*83 == c1");
  bool inverseOk = true;
  for (int a = 1; a < 256; ++a) {
    const uint8_t x = static_cast<uint8_t>(a);
    if (gf256Mul(x, gf256Inv(x)) != 1)
      inverseOk = false;
  }
  CHECK(inverseOk, "every nonzero element has a GF(2^8) inverse");
}

void testTableBijection() {
  PsiTable psi(8, 8, 1234, 3);
  bool roundtrip = true;
  for (int x = 0; x < 256; ++x) {
    BitVector in(8);
    for (int b = 0; b < 8; ++b)
      if ((x >> b) & 1)
        in.set(b, true);
    const BitVector out = psi.apply(in);
    const BitVector back = psi.invert(out);
    if (back != in)
      roundtrip = false;
  }
  CHECK(roundtrip, "table psi is a bijection (apply/invert roundtrip)");
  CHECK(psi.table().size() == 256, "8-bit table has 256 entries");

  PsiTable same(8, 8, 1234, 3);
  PsiTable other(8, 8, 1234, 4);
  bool identical = true;
  bool differs = false;
  for (int x = 0; x < 256; ++x) {
    if (same.table()[x] != psi.table()[x])
      identical = false;
    if (other.table()[x] != psi.table()[x])
      differs = true;
  }
  CHECK(identical, "same seed/index reproduces the same table");
  CHECK(differs, "different instruction index gives a different table");
}

void testTruncatedTable() {
  PsiTable psi(8, 4, 99, 0);
  CHECK(!psi.invertible(), "truncated table (c<w) is not invertible");
  bool inRange = true;
  for (int x = 0; x < 256; ++x) {
    BitVector in(8);
    for (int b = 0; b < 8; ++b)
      if ((x >> b) & 1)
        in.set(b, true);
    if (psi.apply(in).popcount() > 4)
      inRange = false;
  }
  CHECK(inRange, "truncated table output stays within c bits");
}

void testSpnBijection() {
  for (uint32_t w : {8u, 16u, 32u, 48u, 64u}) {
    PsiSpn psi(w, 3, 777, 5);
    Rng rng(w);
    bool ok = true;
    for (int t = 0; t < 2000; ++t) {
      const BitVector in = BitVector::random(w, rng);
      const BitVector out = psi.apply(in);
      if (psi.invert(out) != in)
        ok = false;
    }
    char name[64];
    std::snprintf(name, sizeof(name), "spn w=%u: 2000 roundtrips", w);
    CHECK(ok, name);
  }
}

void testSpnAvalanche() {
  PsiSpn psi(64, 3, 4242, 1);
  Rng rng(4242);
  double total = 0;
  int trials = 200;
  for (int t = 0; t < trials; ++t) {
    BitVector in = BitVector::random(64, rng);
    BitVector flipped = in;
    flipped.flip(static_cast<uint32_t>(rng() % 64));
    BitVector diff = psi.apply(in);
    diff.xorWith(psi.apply(flipped));
    total += diff.popcount();
  }
  const double avg = total / (trials * 64.0);
  CHECK(avg > 0.30 && avg < 0.70, "spn avalanche: ~50% of output bits change");
}

void testSboxNonlinearity() {
  PsiSpn psi(32, 2, 31337, 2);
  const uint8_t *sbox = psi.sbox();
  int maxWalsh = 0;
  for (int a = 1; a < 256; ++a) {
    for (int b = 1; b < 256; ++b) {
      int sum = 0;
      for (int x = 0; x < 256; ++x) {
        const unsigned ax = static_cast<unsigned>(a & x);
        const unsigned bx = static_cast<unsigned>(b & sbox[x]);
        const int bit = (__builtin_popcount(ax) ^ __builtin_popcount(bx)) & 1;
        sum += bit ? -1 : 1;
      }
      const int mag = sum < 0 ? -sum : sum;
      if (mag > maxWalsh)
        maxWalsh = mag;
    }
  }
  CHECK(maxWalsh <= 32, "spn sbox max Walsh <= 32 (linear bias <= 2^-3)");
}

void testArx() {
  for (uint32_t w : {16u, 32u, 64u}) {
    PsiArx a(w, 6, 555, 2), b(w, 6, 555, 2);
    Rng rng(w);
    bool same = true, inRange = true;
    for (int t = 0; t < 200; ++t) {
      const BitVector x = BitVector::random(w, rng);
      if (a.apply(x) != b.apply(x))
        same = false;
      if (a.apply(x).popcount() > w)
        inRange = false;
    }
    char name[80];
    std::snprintf(name, sizeof(name), "arx w=%u: deterministic, within w bits", w);
    CHECK(same && inRange, name);

    double total = 0;
    const int trials = 100;
    for (int t = 0; t < trials; ++t) {
      const BitVector x = BitVector::random(w, rng);
      BitVector f = x;
      f.flip(static_cast<uint32_t>(rng() % w));
      BitVector d = a.apply(x);
      d.xorWith(a.apply(f));
      total += d.popcount();
    }
    const double avg = total / (trials * w);
    std::snprintf(name, sizeof(name), "arx w=%u: avalanche near 50%% (%.2f)", w,
                  avg);
    CHECK(avg > 0.30 && avg < 0.70, name);
  }
  PsiArx x(32, 6, 1, 0), y(32, 6, 1, 1);
  Rng rng(9);
  bool differs = false;
  for (int t = 0; t < 50; ++t) {
    const BitVector v = BitVector::random(32, rng);
    if (x.apply(v) != y.apply(v))
      differs = true;
  }
  CHECK(differs, "arx: different instruction index gives a different function");
}

} // namespace

int main() {
  testGf256();
  testTableBijection();
  testTruncatedTable();
  testSpnBijection();
  testSpnAvalanche();
  testSboxNonlinearity();
  testArx();
  return hsvm_test::summary("psi");
}
