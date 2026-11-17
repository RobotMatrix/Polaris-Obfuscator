// V-04/V-05: lowering to a minimal IR.
//
// The bytecode becomes a small typed IR whose only job is to be (a) executed by
// tests today and (b) emitted as LLVM IR later (V-07). The IR stays explicit
// about control flow and faults: a jump carries a signed displacement, and a
// fault stops without advancing pc, exactly like the interpreter.
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
  Shl,   // dst = a << (b & 31)
  Shr,   // dst = a >> (b & 31)
  Load,  // dst = mem32[a + imm]
  Store, // mem32[a + imm] = b
  Jmp,   // pc += simm(imm)
  Brz,   // regs[a] == 0 ? pc += simm(imm) : pc += 1
  Stop,  // mark the machine stopped, pc unchanged
};

struct IrOp {
  IrKind kind = IrKind::Copy;
  uint8_t dst = 0;
  uint8_t a = 0;
  uint8_t b = 0;
  uint32_t imm = 0;
};

// Returns false when the opcode is not lowered at all (nothing is appended in
// that case, so callers cannot mistake a refusal for "no effect").
bool lowerOp(const MirOp &in, std::vector<IrOp> *out);

// Executes the operations of one lowered instruction against the same state the
// oracle uses, including pc movement and the fault path.
bool irExec(SemState &s, const std::vector<IrOp> &ops);

} // namespace hsvm
