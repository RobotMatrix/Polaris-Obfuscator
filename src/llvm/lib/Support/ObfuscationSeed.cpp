//===- ObfuscationSeed.cpp - Shared obfuscation RNG seed ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
//
//===----------------------------------------------------------------------===//

#include "llvm/Support/ObfuscationSeed.h"
#include "llvm/Support/CommandLine.h"
#include <ctime>
#include <random>

using namespace llvm;

static cl::opt<unsigned long long> ObfSeed(
    "obf-seed", cl::Hidden, cl::init(0),
    cl::desc("Seed for obfuscation RNG (0 derives one from the clock)"));

uint64_t llvm::getObfSeed() { return ObfSeed; }

uint64_t llvm::nextObfRandom() {
  // First call is during a pass, after command-line parsing.
  static std::mt19937_64 Rng = [] {
    uint64_t Seed = ObfSeed;
    if (Seed == 0)
      Seed = (uint64_t)std::time(nullptr) ^
             ((uint64_t)std::clock() << 17) ^ 0xA5A5A5A5ULL;
    return std::mt19937_64(Seed);
  }();
  return Rng();
}
