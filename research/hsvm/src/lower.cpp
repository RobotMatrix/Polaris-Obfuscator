#include "hsvm/lower.h"

namespace hsvm {

bool lowerOp(const MirOp &in, std::vector<IrOp> *out) {
  if (!out)
    return false;
  IrOp o;
  o.dst = in.dst;
  o.a = in.a;
  o.b = in.b;
  o.imm = in.imm;
  switch (in.op) {
  case Opcode::Nop:
    return true; // zero ops, but still a successful lowering
  case Opcode::Movi:
    o.kind = IrKind::Const;
    break;
  case Opcode::Mov:
    o.kind = IrKind::Copy;
    break;
  case Opcode::Add:
    o.kind = IrKind::Add;
    break;
  case Opcode::Sub:
    o.kind = IrKind::Sub;
    break;
  case Opcode::Xor:
    o.kind = IrKind::Xor;
    break;
  case Opcode::And:
    o.kind = IrKind::And;
    break;
  case Opcode::Or:
    o.kind = IrKind::Or;
    break;
  case Opcode::Mul:
    o.kind = IrKind::Mul;
    break;
  case Opcode::Shl:
    o.kind = IrKind::Shl;
    break;
  case Opcode::Shr:
    o.kind = IrKind::Shr;
    break;
  case Opcode::Ld:
    o.kind = IrKind::Load;
    break;
  case Opcode::Tld:
    o.kind = IrKind::TableLoad;
    break;
  case Opcode::St:
    o.kind = IrKind::Store;
    break;
  case Opcode::Jmp:
    o.kind = IrKind::Jmp;
    break;
  case Opcode::Brz:
    o.kind = IrKind::Brz;
    break;
  case Opcode::Halt:
    o.kind = IrKind::Stop;
    break;
  default:
    // An opcode outside the ISA must never be approximated: silence here would
    // turn a corrupt bytecode into a plausible-looking copy.
    return false;
  }
  out->push_back(o);
  return true;
}

bool irExec(SemState &s, const std::vector<IrOp> &ops) {
  if (s.halted || s.faulted)
    return false;
  bool pcHandled = false;
  for (const IrOp &o : ops) {
    switch (o.kind) {
    case IrKind::Jmp:
      s.pc = static_cast<uint32_t>(static_cast<int64_t>(s.pc) +
                                   static_cast<int32_t>(o.imm));
      pcHandled = true;
      break;
    case IrKind::Stop:
      s.halted = true;
      pcHandled = true; // pc stays where it is
      break;
    case IrKind::Brz:
      if (!semRegOk(s, o.a)) {
        s.faulted = true;
        return false;
      }
      if (s.regs[o.a] == 0)
        s.pc = static_cast<uint32_t>(static_cast<int64_t>(s.pc) +
                                     static_cast<int32_t>(o.imm));
      else
        s.pc += 1;
      pcHandled = true;
      break;
    case IrKind::Load: {
      if (!semRegOk(s, o.dst) || !semRegOk(s, o.a)) {
        s.faulted = true;
        return false;
      }
      const uint32_t addr = s.regs[o.a] + o.imm;
      if (!semMemOk(s, addr)) {
        s.faulted = true;
        return false;
      }
      s.regs[o.dst] = semLoad32(s, addr);
      break;
    }
    case IrKind::TableLoad: {
      if (!semRegOk(s, o.dst) || !semRegOk(s, o.a)) { s.faulted = true; return false; }
      const uint32_t addr = s.regs[o.a] + o.imm;
      if (s.table == nullptr || addr > s.tableBytes - 4 || (addr & 3u) != 0) {
        s.faulted = true;
        return false;
      }
      s.regs[o.dst] = (uint32_t)s.table[addr] | ((uint32_t)s.table[addr + 1] << 8) |
                      ((uint32_t)s.table[addr + 2] << 16) |
                      ((uint32_t)s.table[addr + 3] << 24);
      break;
    }
    case IrKind::Store: {
      if (!semRegOk(s, o.a) || !semRegOk(s, o.b)) {
        s.faulted = true;
        return false;
      }
      const uint32_t addr = s.regs[o.a] + o.imm;
      if (!semMemOk(s, addr)) {
        s.faulted = true;
        return false;
      }
      semStore32(s, addr, s.regs[o.b]);
      break;
    }
    case IrKind::Const:
      if (!semRegOk(s, o.dst)) {
        s.faulted = true;
        return false;
      }
      s.regs[o.dst] = o.imm;
      break;
    case IrKind::Copy:
      if (!semRegOk(s, o.dst) || !semRegOk(s, o.a)) {
        s.faulted = true;
        return false;
      }
      s.regs[o.dst] = s.regs[o.a];
      break;
    default: {
      if (!semRegOk(s, o.dst) || !semRegOk(s, o.a) || !semRegOk(s, o.b)) {
        s.faulted = true;
        return false;
      }
      const uint32_t x = s.regs[o.a];
      const uint32_t y = s.regs[o.b];
      uint32_t r = 0;
      switch (o.kind) {
      case IrKind::Add: r = x + y; break;
      case IrKind::Sub: r = x - y; break;
      case IrKind::Xor: r = x ^ y; break;
      case IrKind::And: r = x & y; break;
      case IrKind::Or: r = x | y; break;
      case IrKind::Mul: r = x * y; break;
      case IrKind::Shl: r = x << (y & 31u); break;
      case IrKind::Shr: r = x >> (y & 31u); break;
      default: break;
      }
      s.regs[o.dst] = r;
      break;
    }
    }
  }
  if (!pcHandled)
    s.pc += 1;
  return true;
}

} // namespace hsvm
