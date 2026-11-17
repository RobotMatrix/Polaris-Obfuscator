// V-07: native code emission (C), compiled by the system toolchain.
//
// The chain under test is bytecode -> lift -> lower -> native code -> run, with
// the interpreter as the reference. Emitting C rather than hand-written LLVM IR
// is deliberate at this stage: the goal is to prove the *semantics* survive a
// real compiler, and hand-written IR syntax would add a second, unrelated source
// of failure. The Polaris pass (V-08) is where LLVM IR becomes the medium.
//
// The emitted program reproduces the interpreter exactly, including the fault
// path: an out-of-range or unaligned address prints "fault" and exits 3, running
// past the instruction budget exits 5, and a stop instruction prints
// "r0=<dec> mem=<fnv8>" and exits 0.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hsvm {

// initRegs fills every register before the first instruction, matching
// Machine::fillRegs().
std::string emitC(const std::vector<uint8_t> &code, uint32_t regCount,
                  uint32_t maxSteps, uint32_t initRegs);

// The same report string the emitted program prints, computed from the state the
// oracle reaches. Used as the expected value.
std::string reportOf(const uint32_t *regs, const uint8_t *mem, uint32_t memBytes);

} // namespace hsvm
