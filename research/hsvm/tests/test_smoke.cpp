//===- test_smoke.cpp - harness wiring smoke test -------------------------===//
#include "hsvm/gf2.h"
#include "test_harness.h"

int main() {
  using namespace hsvm;

  std::printf("smoke: gf2 primitives reachable\n");
  CHECK(wordsFor(0) == 0, "wordsFor(0)");
  CHECK(wordsFor(1) == 1, "wordsFor(1)");
  CHECK(wordsFor(64) == 1, "wordsFor(64)");
  CHECK(wordsFor(65) == 2, "wordsFor(65)");

  BitMatrix id = BitMatrix::identity(3);
  CHECK(rank(id) == 3, "identity rank");

  return hsvm_test::summary("smoke");
}
