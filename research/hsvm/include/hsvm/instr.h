//===- instr.h - HSV instruction encoding --------------------------------===//
//
// Fixed 8-byte encoding, little-endian:
//   [0] opcode  [1] dst  [2] a  [3] b  [4..7] imm (u32)
//
// Keeping the format fixed and explicit is deliberate: the bytecode is the one
// artifact the attack scripts, the model tests and (later) the compiler pass
// all have to agree on.
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_INSTR_H
#define HSV_M_INSTR_H

#include "hsvm/isa.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hsvm {

struct Instr {
  uint8_t op = 0;
  uint8_t dst = 0;
  uint8_t a = 0;
  uint8_t b = 0;
  uint32_t imm = 0;

  int32_t simm() const { return static_cast<int32_t>(imm); }
};

void encodeInstr(const Instr &in, uint8_t out[kInstrBytes]);
Instr decodeInstr(const uint8_t *bytes);

// "add r1, r2, r3" / "movi r1, 0x10" / "jmp +3"
std::string disassemble(const Instr &in);

// Convenience builder for test programs.
class Asm {
public:
  Asm &op(Opcode o, uint8_t dst = 0, uint8_t a = 0, uint8_t b = 0,
          uint32_t imm = 0);
  Asm &label();
  // Patch the immediate of an already emitted instruction (branch targets).
  Asm &patch(uint32_t index, uint32_t imm);
  uint32_t here() const { return static_cast<uint32_t>(code_.size() / kInstrBytes); }
  const std::vector<uint8_t> &code() const { return code_; }

private:
  std::vector<uint8_t> code_;
};

} // namespace hsvm

#endif // HSV_M_INSTR_H
