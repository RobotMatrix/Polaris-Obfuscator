#include "hsvm/emit_c.h"

#include "hsvm/instr.h"
#include "hsvm/lower.h"

#include <cstdio>
#include <string>

namespace hsvm {

namespace {

const char *kindToC(IrKind k) {
  switch (k) {
  case IrKind::Add: return "+";
  case IrKind::Sub: return "-";
  case IrKind::Xor: return "^";
  case IrKind::And: return "&";
  case IrKind::Or: return "|";
  case IrKind::Mul: return "*";
  default: return nullptr;
  }
}

void emitGuard(std::string &out, uint8_t reg) {
  out += "  if (" + std::to_string(reg) + "u >= regCount) { fault(); }\n";
}

} // namespace

std::string reportOf(const uint32_t *regs, const uint8_t *mem, uint32_t memBytes) {
  uint32_t h = 2166136261u;
  for (uint32_t i = 0; i < memBytes; ++i) {
    h ^= mem[i];
    h *= 16777619u;
  }
  char buf[64];
  std::snprintf(buf, sizeof(buf), "r0=%u mem=%08x", regs[0], h);
  return std::string(buf);
}

std::string emitC(const std::vector<uint8_t> &code, uint32_t regCount,
                  uint32_t maxSteps, uint32_t initRegs) {
  std::vector<MirOp> ops;
  if (!lift(code, &ops))
    return std::string();

  const uint32_t slots = static_cast<uint32_t>(ops.size());
  std::string out;
  out += "#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n";
  out += "static uint8_t mem[4096];\n";
  out += "static uint32_t regs[16];\n";
  out += "static uint32_t steps;\n";
  out += "static uint32_t regCount = " + std::to_string(regCount) + "u;\n";
  out += "static void fault(void) { printf(\"fault\\n\"); exit(3); }\n";
  out += "static void budget(void) { printf(\"budget\\n\"); exit(5); }\n";
  out += "static void report(void) {\n";
  out += "  uint32_t h = 2166136261u;\n";
  out += "  for (uint32_t i = 0; i < 4096u; ++i) { h ^= mem[i]; h *= 16777619u; }\n";
  out += "  printf(\"r0=%u mem=%08x\\n\", regs[0], h);\n";
  out += "  exit(0);\n}\n";
  out += "static void load32(uint32_t a, uint32_t *dst) {\n";
  out += "  if ((a & 3u) != 0 || a > 4092u) { fault(); }\n";
  out += "  *dst = (uint32_t)mem[a] | ((uint32_t)mem[a+1] << 8) |\n";
  out += "         ((uint32_t)mem[a+2] << 16) | ((uint32_t)mem[a+3] << 24);\n}\n";
  out += "static void store32(uint32_t a, uint32_t v) {\n";
  out += "  if ((a & 3u) != 0 || a > 4092u) { fault(); }\n";
  out += "  mem[a] = (uint8_t)(v & 0xffu); mem[a+1] = (uint8_t)((v >> 8) & 0xffu);\n";
  out += "  mem[a+2] = (uint8_t)((v >> 16) & 0xffu); mem[a+3] = (uint8_t)((v >> 24) & 0xffu);\n}\n";
  out += "int main(void) {\n";
  out += "  for (uint32_t i = 0; i < 16u; ++i) regs[i] = " +
         std::to_string(initRegs) + "u;\n";
  out += "  steps = 0;\n";
  out += "  goto L0;\n";

  for (uint32_t pc = 0; pc < slots; ++pc) {
    const MirOp &op = ops[pc];
    std::vector<IrOp> ir;
    if (!lowerOp(op, &ir))
      return std::string();
    out += "L" + std::to_string(pc) + ":\n";
    out += "  if (++steps > " + std::to_string(maxSteps) + "u) { budget(); }\n";
    const std::string next = (pc + 1 < slots) ? ("L" + std::to_string(pc + 1)) : "Lout";

    for (const IrOp &o : ir) {
      switch (o.kind) {
      case IrKind::Const:
        emitGuard(out, o.dst);
        out += "  regs[" + std::to_string(o.dst) + "] = " +
               std::to_string(o.imm) + "u;\n";
        break;
      case IrKind::Copy:
        emitGuard(out, o.dst);
        emitGuard(out, o.a);
        out += "  regs[" + std::to_string(o.dst) + "] = regs[" +
               std::to_string(o.a) + "];\n";
        break;
      case IrKind::Load:
        emitGuard(out, o.dst);
        emitGuard(out, o.a);
        out += "  load32(regs[" + std::to_string(o.a) + "] + " +
               std::to_string(o.imm) + "u, &regs[" + std::to_string(o.dst) + "]);\n";
        break;
      case IrKind::Store:
        emitGuard(out, o.a);
        emitGuard(out, o.b);
        out += "  store32(regs[" + std::to_string(o.a) + "] + " +
               std::to_string(o.imm) + "u, regs[" + std::to_string(o.b) + "]);\n";
        break;
      case IrKind::TableLoad: {
        emitGuard(out, o.dst);
        emitGuard(out, o.a);
        const std::string d = std::to_string(o.dst), a = std::to_string(o.a);
        out += "  { static unsigned char *tbl = 0; static unsigned long long len = 0;\n";
        out += "    uint32_t ad = regs[" + a + "] + " + std::to_string(o.imm) + "u;\n";
        out += "    if (!tbl || ad + 4u > len || (ad & 3u)) { fault(); }\n";
        out += "    else { regs[" + d + "] = (uint32_t)tbl[ad] | ((uint32_t)tbl[ad+1] << 8) |";
        out += " ((uint32_t)tbl[ad+2] << 16) | ((uint32_t)tbl[ad+3] << 24); } }\n";
        break;
      }
      case IrKind::Jmp: {
        const int64_t target = static_cast<int64_t>(pc) +
                               static_cast<int32_t>(o.imm);
        if (target < 0 || target >= static_cast<int64_t>(slots)) {
          out += "  goto Lout;\n";
        } else {
          out += "  goto L" + std::to_string(target) + ";\n";
        }
        break;
      }
      case IrKind::Brz: {
        emitGuard(out, o.a);
        const int64_t target = static_cast<int64_t>(pc) +
                               static_cast<int32_t>(o.imm);
        const std::string tgt =
            (target < 0 || target >= static_cast<int64_t>(slots))
                ? std::string("Lout")
                : ("L" + std::to_string(target));
        out += "  if (regs[" + std::to_string(o.a) + "] == 0u) goto " + tgt +
               "; else goto " + next + ";\n";
        break;
      }
      case IrKind::Stop:
        out += "  report();\n";
        break;
      default: {
        emitGuard(out, o.dst);
        emitGuard(out, o.a);
        emitGuard(out, o.b);
        const uint32_t a = o.a, b = o.b, d = o.dst;
        if (o.kind == IrKind::Shl || o.kind == IrKind::Shr) {
          out += std::string("  regs[") + std::to_string(d) + "] = regs[" +
                 std::to_string(a) + "] " +
                 (o.kind == IrKind::Shl ? "<<" : ">>") + " (regs[" +
                 std::to_string(b) + "] & 31u);\n";
        } else if (const char *sym = kindToC(o.kind)) {
          out += std::string("  regs[") + std::to_string(d) + "] = regs[" +
                 std::to_string(a) + "] " + sym + " regs[" + std::to_string(b) +
                 "];\n";
        } else {
          return std::string();
        }
        break;
      }
      }
    }
    // A block that did not jump or stop falls through to the next instruction.
    if (op.op != Opcode::Jmp && op.op != Opcode::Brz && op.op != Opcode::Halt)
      out += "  goto " + next + ";\n";
  }

  out += "Lout:\n  fault();\n  return 0;\n}\n";
  return out;
}

} // namespace hsvm
