// Stage 5, slice 1: the lifter.
//
// The native VM needs the bytecode in a typed form before any lowering can
// happen. MirOp is that form: the 16-opcode encoding, decoded once, with a
// total (never throwing) mapping and an exact inverse. lift()/emit() round-trip
// byte-for-byte, which is what makes this slice testable without committing to
// operand semantics yet.
#pragma once

#include "hsvm/isa.h"

#include <cstdint>
#include <vector>

namespace hsvm {

struct MirOp {
  Opcode op = Opcode::Nop;
  uint8_t dst = 0;
  uint8_t a = 0;
  uint8_t b = 0;
  uint32_t imm = 0;
};

// Decodes whole instructions; returns false if the byte count is not a multiple
// of the instruction size or any opcode byte is outside the 16 defined values.
bool lift(const std::vector<uint8_t> &code, std::vector<MirOp> *out);

// Exact inverse of lift for well-formed input.
std::vector<uint8_t> emit(const std::vector<MirOp> &ops);

} // namespace hsvm
