//===- test_model.cpp - C1 model consistency and Gamma sanity -------------===//
#include "hsvm/machine.h"
#include "hsvm/model.h"
#include "test_harness.h"

#include <algorithm>
#include <cmath>
#include <vector>

using namespace hsvm;

namespace {

HsvmParams mkParams(uint32_t n, uint32_t m, uint32_t w, uint32_t c,
                    PsiMode psi, uint32_t rounds, uint64_t seed) {
  HsvmParams p;
  p.n = n;
  p.m = m;
  p.w = w;
  p.c = c;
  p.rBar = 2;
  p.rounds = rounds;
  p.psi = psi;
  p.seed = seed;
  p.workload = Workload::Crc32;
  return p;
}

std::vector<BitVector> walk(const NonlinearModel &model, uint32_t count,
                            Rng &rng) {
  std::vector<BitVector> states;
  BitVector s = BitVector::random(model.params().n, rng);
  states.reserve(count);
  for (uint32_t t = 0; t < count; ++t) {
    states.push_back(s);
    s = model.step(s, static_cast<uint32_t>(rng() % model.instructionCount()));
  }
  return states;
}

void testDifferentialMatchesStep() {
  // Two independent paths to D = H*(F(s^d) ^ F(s)): the full step, and the
  // precomputed HE shortcut. They must agree, otherwise Gamma is measuring
  // something other than the transition it claims to.
  const auto p = mkParams(128, 64, 8, 8, PsiMode::Table, 0, 4321);
  NonlinearModel model(p);
  Rng rng(4321);
  bool ok = true;
  for (int t = 0; t < 200; ++t) {
    const BitVector s = BitVector::random(p.n, rng);
    const BitVector delta = model.kernelSample(BitVector::random(p.n - p.m, rng));
    const uint32_t i = static_cast<uint32_t>(rng() % model.instructionCount());

    BitVector sa = s;
    sa.xorWith(delta);
    BitVector lhs = model.step(sa, i);
    lhs.xorWith(model.step(s, i));
    const BitVector viaStep = matVec(model.projection(), lhs);
    const BitVector viaModel = model.differential(i, s, delta);
    if (viaStep != viaModel)
      ok = false;
  }
  CHECK(ok, "differential() agrees with H*(F(s^d)^F(s)) on 200 cases");
}

void testKernelSamples() {
  const auto p = mkParams(128, 64, 8, 8, PsiMode::Table, 0, 11);
  NonlinearModel model(p);
  Rng rng(11);
  bool inKernel = true;
  for (int t = 0; t < 500; ++t) {
    const BitVector r = BitVector::random(p.n - p.m, rng);
    const BitVector delta = model.kernelSample(r);
    if (matVec(model.projection(), delta).popcount() != 0)
      inKernel = false;
  }
  CHECK(inKernel, "500 sampled directions lie in ker(H)");
}

void testGammaHigh() {
  const auto p = mkParams(128, 64, 8, 8, PsiMode::Table, 0, 9001);
  NonlinearModel model(p);
  Rng rng(9001);
  const auto states = walk(model, 256, rng);
  GammaResult worst;
  worst.gamma = 2.0;
  bool trialsOk = true;
  for (uint32_t i = 0; i < model.instructionCount(); ++i) {
    const GammaResult g = model.gamma(i, states, 4, rng);
    if (g.trials != states.size() * 4)
      trialsOk = false;
    if (g.gamma < worst.gamma)
      worst = g;
  }
  CHECK(trialsOk, "gamma trial count matches states x directions");
  CHECK(worst.gamma >= 0.9, "gamma stays >= 0.9 for every instruction");
  CHECK(worst.ciLo <= worst.gamma && worst.gamma <= worst.ciHi,
        "gamma CI brackets the estimate");
}

void testAffineDetected() {
  const auto p = mkParams(128, 64, 8, 8, PsiMode::Table, 0, 3131);
  NonlinearModel model(p);
  Rng rng(3131);
  const BitVector s = BitVector::random(p.n, rng);
  bool anyNonAffine = false;
  bool exhaustiveSeen = false;
  for (uint32_t i = 0; i < model.instructionCount(); ++i) {
    const AffineResult r = model.affineTest(i, s, rng, true);
    if (!r.affine)
      anyNonAffine = true;
    if (r.exhaustive)
      exhaustiveSeen = true;
    if (r.dim == 0 || r.checked == 0)
      anyNonAffine = false;
  }
  CHECK(anyNonAffine, "random table psi yields a non-affine D on pi_A(K)");
  CHECK(exhaustiveSeen, "small pi_A(K) dimension is tested exhaustively");
}

void testStepWordsMatchesStep() {
  const auto p = mkParams(128, 64, 8, 8, PsiMode::Table, 0, 6060);
  NonlinearModel model(p);
  Rng rng(6060);
  bool ok = true;
  for (int t = 0; t < 100; ++t) {
    const BitVector s = BitVector::random(p.n, rng);
    std::vector<uint64_t> words((p.n + 63) / 64);
    for (uint32_t w = 0; w < words.size(); ++w)
      words[w] = s.word(w);
    for (uint32_t i = 0; i < model.instructionCount(); ++i) {
      model.stepWords(words.data(), i);
      const BitVector expected = model.step(s, i);
      BitVector actual(p.n);
      for (uint32_t w = 0; w < words.size(); ++w)
        for (uint32_t b = 0; b < 64 && w * 64 + b < p.n; ++b)
          if ((words[w] >> b) & 1ULL)
            actual.set(w * 64 + b, true);
      if (actual != expected)
        ok = false;
      // restore for the next instruction
      for (uint32_t w = 0; w < words.size(); ++w)
        words[w] = s.word(w);
    }
  }
  CHECK(ok, "stepWords matches step() for every instruction");
}

void testSpnSampled() {
  const auto p = mkParams(128, 64, 32, 16, PsiMode::Spn, 2, 5150);
  NonlinearModel model(p);
  Rng rng(5150);
  const BitVector s = BitVector::random(p.n, rng);
  const AffineResult r = model.affineTest(0, s, rng, true);
  CHECK(r.dim > 16, "w=32 window projects to more than 16 dimensions");
  CHECK(!r.exhaustive, "large pi_A(K) falls back to sampled testing");
  CHECK(r.checked > 0 && r.checked <= 10000,
        "sampled test records how many checks it performed");
  CHECK(!r.affine, "spn psi is non-affine on the window subspace");
}

void testDeterminism() {
  const auto p = mkParams(128, 64, 8, 8, PsiMode::Table, 0, 2020);
  NonlinearModel a(p), b(p);
  Rng rng(1);
  const BitVector s = BitVector::random(p.n, rng);
  bool same = true;
  for (uint32_t i = 0; i < a.instructionCount(); ++i)
    if (a.step(s, i) != b.step(s, i))
      same = false;
  CHECK(same, "same seed reproduces the same transition");

  NonlinearModel c(mkParams(128, 64, 8, 8, PsiMode::Table, 0, 2021));
  bool differs = false;
  for (uint32_t i = 0; i < a.instructionCount(); ++i)
    if (a.step(s, i) != c.step(s, i))
      differs = true;
  CHECK(differs, "different seed changes the transition");
}

} // namespace

int main() {
  testDifferentialMatchesStep();
  testKernelSamples();
  testGammaHigh();
  testAffineDetected();
  testStepWordsMatchesStep();
  testSpnSampled();
  testDeterminism();
  return hsvm_test::summary("model");
}
