//===- ObfuscationSeed.h - Shared obfuscation RNG seed ----------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_SUPPORT_OBFUSCATIONSEED_H
#define LLVM_SUPPORT_OBFUSCATIONSEED_H

#include <cstdint>

namespace llvm {

/// Value of -mllvm -obf-seed. Zero means a seed is chosen on first use.
uint64_t getObfSeed();

/// Next value from the process-wide obfuscation generator.
/// The generator is seeded from -obf-seed, or from the clock when that is 0.
uint64_t nextObfRandom();

} // namespace llvm

#endif
