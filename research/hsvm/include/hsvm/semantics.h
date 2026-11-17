// Stage 5, slice 2a: executable semantics for the 16 opcodes.
//
// This is the spec in reports/S5-nativevm/slice2-semantics.md turned into code
// that can be run. It is deliberately a pure function over an explicit State so
// that the upcoming lowering has an oracle that does not depend on the
// interpreter: lower a program, step both, compare.
//
// Faults are part of the semantics, not an afterthought: an out-of-range
// register, an out-of-range or unaligned address sets faulted and stops the
// instruction, matching Machine::step's fault path.
#pragma once

#include "hsvm/mir.h"

#include <cstdint>

namespace hsvm {

struct SemState {
  uint32_t regs[64] = {};
  uint8_t *mem = nullptr;
  uint32_t memBytes = 0;
  uint32_t pc = 0;
  bool halted = false;
  bool faulted = false;
};

constexpr uint32_t kSemRegs = 64;

inline bool semRegOk(uint8_t r) { return r < kSemRegs; }

inline bool semMemOk(const SemState &s, uint32_t addr) {
  return (addr & 3u) == 0 && addr + 4u <= s.memBytes && s.mem != nullptr;
}

inline uint32_t semLoad32(const SemState &s, uint32_t addr) {
  return static_cast<uint32_t>(s.mem[addr]) |
         (static_cast<uint32_t>(s.mem[addr + 1]) << 8) |
         (static_cast<uint32_t>(s.mem[addr + 2]) << 16) |
         (static_cast<uint32_t>(s.mem[addr + 3]) << 24);
}

inline void semStore32(SemState &s, uint32_t addr, uint32_t v) {
  s.mem[addr] = static_cast<uint8_t>(v & 0xFF);
  s.mem[addr + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
  s.mem[addr + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
  s.mem[addr + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

// Executes one instruction. Returns false if the instruction faulted (state is
// then marked faulted and left otherwise untouched).
inline bool semStep(SemState &s, const MirOp &op) {
  if (s.halted || s.faulted)
    return false;
  switch (op.op) {
  case Opcode::Nop:
    s.pc += 1;
    return true;
  case Opcode::Movi:
    s.regs[op.dst] = op.imm;
    s.pc += 1;
    return true;
  case Opcode::Mov:
    if (!semRegOk(op.a) || !semRegOk(op.dst)) {
      s.faulted = true;
      return false;
    }
    s.regs[op.dst] = s.regs[op.a];
    s.pc += 1;
    return true;
  case Opcode::Add:
  case Opcode::Sub:
  case Opcode::Xor:
  case Opcode::And:
  case Opcode::Or:
  case Opcode::Mul:
  case Opcode::Shl:
  case Opcode::Shr: {
    if (!semRegOk(op.a) || !semRegOk(op.b) || !semRegOk(op.dst)) {
      s.faulted = true;
      return false;
    }
    const uint32_t x = s.regs[op.a];
    const uint32_t y = s.regs[op.b];
    uint32_t r = 0;
    switch (op.op) {
    case Opcode::Add: r = x + y; break;
    case Opcode::Sub: r = x - y; break;
    case Opcode::Xor: r = x ^ y; break;
    case Opcode::And: r = x & y; break;
    case Opcode::Or: r = x | y; break;
    case Opcode::Mul: r = x * y; break;
    case Opcode::Shl: r = x << (y & 31u); break;
    case Opcode::Shr: r = x >> (y & 31u); break;
    default: break;
    }
    s.regs[op.dst] = r;
    s.pc += 1;
    return true;
  }
  case Opcode::Ld: {
    if (!semRegOk(op.a) || !semRegOk(op.dst)) {
      s.faulted = true;
      return false;
    }
    const uint32_t addr = s.regs[op.a] + op.imm;
    if (!semMemOk(s, addr)) {
      s.faulted = true;
      return false;
    }
    s.regs[op.dst] = semLoad32(s, addr);
    s.pc += 1;
    return true;
  }
  case Opcode::St: {
    if (!semRegOk(op.a) || !semRegOk(op.b)) {
      s.faulted = true;
      return false;
    }
    const uint32_t addr = s.regs[op.a] + op.imm;
    if (!semMemOk(s, addr)) {
      s.faulted = true;
      return false;
    }
    semStore32(s, addr, s.regs[op.b]);
    s.pc += 1;
    return true;
  }
  case Opcode::Jmp:
    s.pc = static_cast<uint32_t>(static_cast<int64_t>(s.pc) +
                                 static_cast<int32_t>(op.imm));
    return true;
  case Opcode::Brz: {
    if (!semRegOk(op.a)) {
      s.faulted = true;
      return false;
    }
    if (s.regs[op.a] == 0)
      s.pc = static_cast<uint32_t>(static_cast<int64_t>(s.pc) +
                                   static_cast<int32_t>(op.imm));
    else
      s.pc += 1;
    return true;
  }
  case Opcode::Halt:
    s.halted = true;
    return true;
  }
  s.faulted = true; // unreachable for the 16 defined opcodes
  return false;
}

} // namespace hsvm
