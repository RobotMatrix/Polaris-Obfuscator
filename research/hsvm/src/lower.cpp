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
    out->push_back(o);
    return true;
  case Opcode::Mov:
    o.kind = IrKind::Copy;
    out->push_back(o);
    return true;
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
  default:
    return false; // Ld/St/Jmp/Brz: not in this slice
  }
  out->push_back(o);
  return true;
}

bool irExec(SemState &s, const std::vector<IrOp> &ops) {
  if (s.halted || s.faulted)
    return false;
  for (const IrOp &o : ops) {
    switch (o.kind) {
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
      case IrKind::Shl: r = x << (y & 63u); break;
      case IrKind::Shr: r = x >> (y & 63u); break;
      default: break;
      }
      s.regs[o.dst] = r;
      break;
    }
    }
  }
  s.pc += 1;
  return true;
}

} // namespace hsvm
