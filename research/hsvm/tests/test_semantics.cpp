#include "hsvm/semantics.h"
#include "test_harness.h"

#include <vector>

using namespace hsvm;

namespace {

MirOp mk(Opcode op, uint8_t dst = 0, uint8_t a = 0, uint8_t b = 0,
         uint32_t imm = 0) {
  MirOp m;
  m.op = op;
  m.dst = dst;
  m.a = a;
  m.b = b;
  m.imm = imm;
  return m;
}

SemState fresh(std::vector<uint8_t> &mem) {
  SemState s;
  s.mem = mem.data();
  s.memBytes = static_cast<uint32_t>(mem.size());
  return s;
}

} // namespace

int main() {
  std::vector<uint8_t> mem(256, 0);

  // Movi / Mov / Nop
  {
    SemState s = fresh(mem);
    CHECK(semStep(s, mk(Opcode::Movi, 3, 0, 0, 0xDEADBEEF)), "movi runs");
    CHECK(s.regs[3] == 0xDEADBEEF, "movi writes the immediate");
    CHECK(s.pc == 1, "movi advances pc");
    CHECK(semStep(s, mk(Opcode::Mov, 4, 3)), "mov runs");
    CHECK(s.regs[4] == 0xDEADBEEF, "mov copies the register");
    SemState n = fresh(mem);
    CHECK(semStep(n, mk(Opcode::Nop)) && n.pc == 1, "nop only advances pc");
  }

  // Arithmetic, including the two edges: wraparound and masked shifts.
  {
    SemState s = fresh(mem);
    s.regs[1] = 0;
    s.regs[2] = 1;
    CHECK(semStep(s, mk(Opcode::Sub, 5, 1, 2)), "sub runs");
    CHECK(s.regs[5] == 0xFFFFFFFFu, "sub wraps around at 32 bits");

    SemState m = fresh(mem);
    m.regs[1] = 0x10001u;
    m.regs[2] = 0x10001u;
    CHECK(semStep(m, mk(Opcode::Mul, 5, 1, 2)), "mul runs");
    CHECK(m.regs[5] == 0x00020001u, "mul wraps around at 32 bits");

    SemState sh = fresh(mem);
    sh.regs[1] = 1;
    sh.regs[2] = 33; // 33 & 31 == 1
    CHECK(semStep(sh, mk(Opcode::Shl, 5, 1, 2)), "shl runs");
    CHECK(sh.regs[5] == 2u, "shl masks the shift count to 5 bits");
    sh.regs[2] = 0;
    CHECK(semStep(sh, mk(Opcode::Shr, 6, 5, 2)), "shr runs");
    CHECK(sh.regs[6] == 2u, "shr by zero is identity");

    SemState lg = fresh(mem);
    lg.regs[1] = 0x80000000u;
    lg.regs[2] = 31;
    CHECK(semStep(lg, mk(Opcode::Shr, 5, 1, 2)), "logical shr runs");
    CHECK(lg.regs[5] == 1u, "shr is logical, not arithmetic");
  }

  // Memory: little-endian round trip, then the alignment and range faults.
  {
    SemState s = fresh(mem);
    s.regs[1] = 8;
    s.regs[2] = 0x11223344u;
    CHECK(semStep(s, mk(Opcode::St, 0, 1, 2)), "st runs");
    CHECK(mem[8] == 0x44 && mem[9] == 0x33 && mem[10] == 0x22 && mem[11] == 0x11,
          "st writes little-endian");
    CHECK(semStep(s, mk(Opcode::Ld, 3, 1, 0, 0)), "ld runs");
    CHECK(s.regs[3] == 0x11223344u, "ld reads back what st wrote");

    SemState ua = fresh(mem);
    ua.regs[1] = 9; // unaligned
    CHECK(!semStep(ua, mk(Opcode::Ld, 3, 1)), "unaligned ld faults");
    CHECK(ua.faulted, "fault is recorded");

    SemState oor = fresh(mem);
    oor.regs[1] = 254; // 254 + 4 > 256
    CHECK(!semStep(oor, mk(Opcode::St, 0, 1, 2)), "out-of-range st faults");
    CHECK(oor.faulted, "range fault is recorded");
  }

  // Control flow: signed displacement, taken and not-taken branch, halt.
  {
    SemState s = fresh(mem);
    s.pc = 5;
    CHECK(semStep(s, mk(Opcode::Jmp, 0, 0, 0, 0xFFFFFFFEu)), "jmp runs");
    CHECK(s.pc == 3u, "jmp displacement is signed");

    SemState bz = fresh(mem);
    bz.pc = 4;
    bz.regs[1] = 0;
    CHECK(semStep(bz, mk(Opcode::Brz, 0, 1, 0, 0xFFFFFFFDu)), "brz runs");
    CHECK(bz.pc == 1u, "brz jumps when the register is zero");

    SemState bn = fresh(mem);
    bn.pc = 4;
    bn.regs[1] = 7;
    CHECK(semStep(bn, mk(Opcode::Brz, 0, 1, 0, 0xFFFFFFFDu)), "brz runs");
    CHECK(bn.pc == 5u, "brz falls through when the register is nonzero");

    SemState h = fresh(mem);
    CHECK(semStep(h, mk(Opcode::Halt)), "halt runs");
    CHECK(h.halted, "halt is recorded");
    CHECK(!semStep(h, mk(Opcode::Nop)), "nothing executes after halt");
    CHECK(h.pc == 0, "pc does not move on halt");
  }

  // Register range: Machine::kMaxRegs is 16, so 15 is legal and 16 faults.
  {
    SemState s = fresh(mem);
    CHECK(s.regCount == 16, "default register count matches the machine");
    CHECK(semStep(s, mk(Opcode::Movi, 15, 0, 0, 42)), "top register is legal");
    CHECK(s.regs[15] == 42, "top register keeps its value");
    SemState bad = fresh(mem);
    CHECK(!semStep(bad, mk(Opcode::Mov, 0, 16)), "register 16 faults");
    CHECK(bad.faulted, "register fault is recorded");
    SemState wide = fresh(mem);
    wide.regCount = 64;
    CHECK(semStep(wide, mk(Opcode::Movi, 63, 0, 0, 7)), "count is a parameter, not a constant");
  }

  return hsvm_test::summary("semantics");
}
