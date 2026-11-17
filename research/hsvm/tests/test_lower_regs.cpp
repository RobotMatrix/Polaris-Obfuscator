// V-04: three-way differential for the register class.
//
// engine 1: Machine (VmMode::Plain) - the interpreter
// engine 2: semStep                - the semantics oracle
// engine 3: lowerOp + irExec       - the lowering
//
// All three run the same bytes in lockstep. The program below uses only
// register-class opcodes on purpose: memory and control flow are V-05, and
// mixing them in here would hide which layer broke.
#include "hsvm/instr.h"
#include "hsvm/lower.h"
#include "hsvm/machine.h"
#include "hsvm/params.h"
#include "hsvm/semantics.h"
#include "test_harness.h"

#include <cstdio>
#include <vector>

using namespace hsvm;

namespace {

void enc(std::vector<uint8_t> &code, Opcode op, uint8_t dst, uint8_t a, uint8_t b,
         uint32_t imm = 0) {
  Instr in;
  in.op = static_cast<uint8_t>(op);
  in.dst = dst;
  in.a = a;
  in.b = b;
  in.imm = imm;
  uint8_t buf[kInstrBytes];
  encodeInstr(in, buf);
  code.insert(code.end(), buf, buf + kInstrBytes);
}

// Every register-class opcode, plus the two edges that bite: shift counts
// above 31 (masked) and multiplication wraparound.
std::vector<uint8_t> regProgram() {
  std::vector<uint8_t> c;
  enc(c, Opcode::Movi, 1, 0, 0, 0x12345678u);
  enc(c, Opcode::Movi, 2, 0, 0, 0x9E3779B9u);
  enc(c, Opcode::Add, 3, 1, 2);
  enc(c, Opcode::Sub, 4, 3, 1);
  enc(c, Opcode::Xor, 5, 3, 4);
  enc(c, Opcode::And, 6, 3, 1);
  enc(c, Opcode::Or, 7, 4, 2);
  enc(c, Opcode::Mul, 8, 1, 2);
  enc(c, Opcode::Shl, 9, 1, 2); // count = 0x9E3779B9 & 31 == 25
  enc(c, Opcode::Shr, 10, 2, 1); // count = 0x12345678 & 31 == 24
  enc(c, Opcode::Mov, 11, 8, 0);
  enc(c, Opcode::Nop, 0, 0, 0, 0);
  enc(c, Opcode::Movi, 12, 0, 0, 33);
  enc(c, Opcode::Shl, 13, 1, 12); // 33 & 31 == 1
  enc(c, Opcode::Mov, 14, 13, 0);
  enc(c, Opcode::Xor, 15, 14, 15); // reads and writes the same register
  return c;
}

struct Result {
  bool same = true;
  uint32_t steps = 0;
  const char *field = "";
  uint32_t pc = 0;
  uint64_t sem = 0;
  uint64_t low = 0;
};

Result threeWay(const std::vector<uint8_t> &code, uint32_t initRegs) {
  Result r;
  HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = 8;
  p.c = 8;
  p.rBar = 1;
  p.rounds = 0;
  p.psi = PsiMode::Table;
  p.seed = 12345;
  p.workload = Workload::Crc32;

  Machine m(p, VmMode::Plain);
  std::string err;
  if (!m.loadProgram(code, &err))
    return r;
  m.fillRegs(initRegs);

  std::vector<uint8_t> mem1(Machine::kMemBytes, 0);
  std::vector<uint8_t> mem2(Machine::kMemBytes, 0);
  SemState sem;
  sem.mem = mem1.data();
  sem.memBytes = Machine::kMemBytes;
  sem.regCount = m.regCount();
  SemState low = sem;
  low.mem = mem2.data();
  for (uint32_t i = 0; i < m.regCount(); ++i) {
    sem.regs[i] = initRegs;
    low.regs[i] = initRegs;
  }

  while (!m.halted() && !m.faulted()) {
    const uint32_t pc = m.pcValue();
    std::vector<MirOp> ops;
    if (!lift(code, &ops) || pc >= ops.size()) {
      r.field = "program-end";
      r.pc = pc;
      return r;
    }
    std::vector<IrOp> ir;
    if (!lowerOp(ops[pc], &ir)) {
      r.field = "not-lowered";
      r.pc = pc;
      return r;
    }
    semStep(sem, ops[pc]);
    irExec(low, ir);
    m.stepOnce();
    ++r.steps;
    r.pc = pc;
    for (uint32_t i = 0; i < m.regCount(); ++i) {
      if (sem.regs[i] != low.regs[i] || sem.regs[i] != m.reg(i)) {
        r.same = false;
        r.field = "register";
        r.sem = sem.regs[i];
        r.low = low.regs[i];
        std::printf("  [DIVERGE] step %u pc=%u reg r%u: interp=%u oracle=%u lower=%u\n",
                    r.steps, pc, i, m.reg(i), sem.regs[i], low.regs[i]);
        return r;
      }
    }
    if (sem.pc != low.pc || sem.pc != m.pcValue()) {
      r.same = false;
      r.field = "pc";
      r.sem = sem.pc;
      r.low = low.pc;
      return r;
    }
  }
  return r;
}

} // namespace

int main() {
  const std::vector<uint8_t> prog = regProgram();

  // The lowering covers all sixteen opcodes now; what must still be refused is
  // anything outside the ISA, and a refusal must append nothing.
  {
    std::vector<IrOp> ir;
    MirOp ld;
    ld.op = Opcode::Ld;
    CHECK(lowerOp(ld, &ir) && ir.size() == 1 && ir[0].kind == IrKind::Load,
          "ld lowers to a load");
    ir.clear();
    MirOp jmp;
    jmp.op = Opcode::Jmp;
    CHECK(lowerOp(jmp, &ir) && ir.size() == 1 && ir[0].kind == IrKind::Jmp,
          "jmp lowers to a jump");
    ir.clear();
    MirOp sto;
    sto.op = Opcode::Halt;
    CHECK(lowerOp(sto, &ir) && ir.size() == 1 && ir[0].kind == IrKind::Stop,
          "the stop instruction lowers to a stop");
    ir.clear();
    MirOp nop;
    nop.op = Opcode::Nop;
    CHECK(lowerOp(nop, &ir) && ir.empty(), "nop lowers to zero operations");
    MirOp bogus;
    bogus.op = static_cast<Opcode>(0x11);
    CHECK(!lowerOp(bogus, &ir), "an opcode outside the ISA is refused");
    CHECK(ir.empty(), "a refusal appends nothing");
  }

  for (uint32_t init : {0x12345678u, 0u, 0xFFFFFFFFu}) {
    Result r = threeWay(prog, init);
    std::printf("  [%s] init=0x%08x steps=%u field=%s\n",
                r.same ? "ok" : "DIVERGE", init, r.steps,
                r.field[0] ? r.field : "-");
    CHECK(r.same, "interpreter, oracle and lowering agree");
    CHECK(r.field[0] != 'n', "every opcode in the program was lowered");
    CHECK(r.steps == 16, "all sixteen instructions ran");
  }

  return hsvm_test::summary("lower_regs");
}
