//===- instr.cpp - HSV instruction encoding -------------------------------===//
#include "hsvm/instr.h"

#include <cstdio>

namespace hsvm {

void encodeInstr(const Instr &in, uint8_t out[kInstrBytes]) {
  out[0] = in.op;
  out[1] = in.dst;
  out[2] = in.a;
  out[3] = in.b;
  out[4] = static_cast<uint8_t>(in.imm & 0xFF);
  out[5] = static_cast<uint8_t>((in.imm >> 8) & 0xFF);
  out[6] = static_cast<uint8_t>((in.imm >> 16) & 0xFF);
  out[7] = static_cast<uint8_t>((in.imm >> 24) & 0xFF);
}

Instr decodeInstr(const uint8_t *bytes) {
  Instr in;
  in.op = bytes[0];
  in.dst = bytes[1];
  in.a = bytes[2];
  in.b = bytes[3];
  in.imm = static_cast<uint32_t>(bytes[4]) |
           (static_cast<uint32_t>(bytes[5]) << 8) |
           (static_cast<uint32_t>(bytes[6]) << 16) |
           (static_cast<uint32_t>(bytes[7]) << 24);
  return in;
}

std::string disassemble(const Instr &in) {
  char buf[96];
  const auto op = static_cast<Opcode>(in.op);
  switch (op) {
  case Opcode::Nop:
  case Opcode::Halt:
    std::snprintf(buf, sizeof(buf), "%s", opcodeName(op));
    break;
  case Opcode::Movi:
    std::snprintf(buf, sizeof(buf), "%s r%u, 0x%x", opcodeName(op), in.dst,
                  in.imm);
    break;
  case Opcode::Mov:
    std::snprintf(buf, sizeof(buf), "%s r%u, r%u", opcodeName(op), in.dst,
                  in.a);
    break;
  case Opcode::Add:
  case Opcode::Sub:
  case Opcode::Xor:
  case Opcode::And:
  case Opcode::Or:
  case Opcode::Shl:
  case Opcode::Shr:
  case Opcode::Mul:
    std::snprintf(buf, sizeof(buf), "%s r%u, r%u, r%u", opcodeName(op), in.dst,
                  in.a, in.b);
    break;
  case Opcode::Ld: {
    char addr[32];
    if (in.simm() < 0)
      std::snprintf(addr, sizeof(addr), "-0x%x", -in.simm());
    else
      std::snprintf(addr, sizeof(addr), "+0x%x", in.simm());
    std::snprintf(buf, sizeof(buf), "%s r%u, [r%u%s]", opcodeName(op), in.dst,
                  in.a, addr);
    break;
  }
  case Opcode::St: {
    char addr[32];
    if (in.simm() < 0)
      std::snprintf(addr, sizeof(addr), "-0x%x", -in.simm());
    else
      std::snprintf(addr, sizeof(addr), "+0x%x", in.simm());
    std::snprintf(buf, sizeof(buf), "%s [r%u%s], r%u", opcodeName(op), in.a,
                  addr, in.b);
    break;
  }
  case Opcode::Jmp:
    std::snprintf(buf, sizeof(buf), "%s %+d", opcodeName(op), in.simm());
    break;
  case Opcode::Brz:
    std::snprintf(buf, sizeof(buf), "%s r%u, %+d", opcodeName(op), in.a,
                  in.simm());
    break;
  default:
    std::snprintf(buf, sizeof(buf), "db 0x%02x", in.op);
    break;
  }
  return std::string(buf);
}

Asm &Asm::op(Opcode o, uint8_t dst, uint8_t a, uint8_t b, uint32_t imm) {
  Instr in;
  in.op = static_cast<uint8_t>(o);
  in.dst = dst;
  in.a = a;
  in.b = b;
  in.imm = imm;
  uint8_t bytes[kInstrBytes];
  encodeInstr(in, bytes);
  code_.insert(code_.end(), bytes, bytes + kInstrBytes);
  return *this;
}

Asm &Asm::label() { return *this; }

Asm &Asm::patch(uint32_t index, uint32_t imm) {
  const size_t off = static_cast<size_t>(index) * kInstrBytes;
  if (off + kInstrBytes > code_.size())
    return *this;
  code_[off + 4] = static_cast<uint8_t>(imm & 0xFF);
  code_[off + 5] = static_cast<uint8_t>((imm >> 8) & 0xFF);
  code_[off + 6] = static_cast<uint8_t>((imm >> 16) & 0xFF);
  code_[off + 7] = static_cast<uint8_t>((imm >> 24) & 0xFF);
  return *this;
}

} // namespace hsvm
