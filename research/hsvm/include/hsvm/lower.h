// V-04: register-class lowering.
//
// The bytecode becomes a small typed IR whose only job is to be (a) executed by
// tests today and (b) emitted as LLVM IR later (V-07). Keeping the IR this
// small is deliberate: one IrOp per arithmetic effect, no addressing modes, no
// control flow yet, so the differential test can tell a lowering bug from a
// memory-model bug.
//
// Register-class opcodes lower to zero or one IrOp. Memory and control-flow
// opcodes are refused (lowerOp returns false) rather than approximated: a wrong
// approximation would look like a pass until the day it matters.
#pragma once

#include "hsvm/mir.h"
#include "hsvm/semantics.h"

#include <vector>

namespace hsvm {

enum class IrKind : uint8_t {
  Const, // dst = imm
  Copy,  // dst = a
  Add,   // dst = a + b
  Sub,
  Xor,
  And,
  Or,
  Mul,
  Shl, // dst = a << (b & 31)
  Shr, // dst = a >> (b & 31)
};

struct IrOp {
  IrKind kind = IrKind::Copy;
  uint8_t dst = 0;
  uint8_t a = 0;
  uint8_t b = 0;
  uint32_t imm = 0;
};

// Returns false when the opcode is not in the register class (nothing is
// appended in that case, so callers cannot mistake a refusal for "no effect").
bool lowerOp(const MirOp &in, std::vector<IrOp> *out);

// Executes one lowered instruction against the same state the oracle uses, so
// the two can be compared field by field.
bool irExec(SemState &s, const std::vector<IrOp> &ops);

} // namespace hsvm
