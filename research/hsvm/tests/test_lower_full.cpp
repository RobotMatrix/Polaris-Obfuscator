// V-05/V-06: three-way differential over the real programs.
//
// engine 1: Machine (VmMode::Plain)  - the interpreter
// engine 2: semStep                  - the semantics oracle
// engine 3: lowerOp + irExec         - the lowering, now covering memory,
//                                      branches and the stop instruction
//
// Every step compares all registers, all of memory (word-wise) and pc, so a
// divergence is pinned to a step and a field rather than reported as "states
// differ".
#include "hsvm/instr.h"
#include "hsvm/lower.h"
#include "hsvm/machine.h"
#include "hsvm/params.h"
#include "hsvm/programs.h"
#include "hsvm/semantics.h"
#include "test_harness.h"

#include <cstdio>
#include <vector>

using namespace hsvm;

namespace {

struct Result {
  bool same = true;
  uint32_t steps = 0;
  const char *field = "";
  uint32_t pc = 0;
  uint64_t sem = 0;
  uint64_t low = 0;
  bool stopped = false;
};

Result threeWay(const std::vector<uint8_t> &code, uint32_t initRegs,
                uint32_t maxSteps) {
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

  std::vector<MirOp> ops;
  if (!lift(code, &ops))
    return r;

  std::vector<uint8_t> memA(Machine::kMemBytes, 0);
  std::vector<uint8_t> memB(Machine::kMemBytes, 0);
  SemState sem;
  sem.mem = memA.data();
  sem.memBytes = Machine::kMemBytes;
  sem.regCount = m.regCount();
  SemState low = sem;
  low.mem = memB.data();
  for (uint32_t i = 0; i < m.regCount(); ++i) {
    sem.regs[i] = initRegs;
    low.regs[i] = initRegs;
  }

  while (r.steps < maxSteps && !m.halted() && !m.faulted()) {
    const uint32_t pc = m.pcValue();
    if (pc >= ops.size()) {
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
        std::printf("  [DIVERGE] step %u pc=%u r%u: interp=%u oracle=%u lower=%u\n",
                    r.steps, pc, i, m.reg(i), sem.regs[i], low.regs[i]);
        return r;
      }
    }
    for (uint32_t a = 0; a + 4 <= Machine::kMemBytes; a += 4) {
      const uint32_t mv = m.readMem32(a);
      const uint32_t sv = semLoad32(sem, a);
      const uint32_t lv = semLoad32(low, a);
      if (mv != sv || mv != lv) {
        r.same = false;
        r.field = "memory";
        r.sem = sv;
        r.low = lv;
        std::printf("  [DIVERGE] step %u pc=%u mem[%u]: interp=%u oracle=%u lower=%u\n",
                    r.steps, pc, a, mv, sv, lv);
        return r;
      }
    }
    if (sem.pc != low.pc || sem.pc != m.pcValue()) {
      r.same = false;
      r.field = "pc";
      r.sem = sem.pc;
      r.low = low.pc;
      std::printf("  [DIVERGE] step %u pc=%u: interp=%u oracle=%u lower=%u\n", r.steps,
                  pc, m.pcValue(), sem.pc, low.pc);
      return r;
    }
    if (sem.halted != m.halted() || sem.faulted != m.faulted() ||
        low.halted != sem.halted || low.faulted != sem.faulted) {
      r.same = false;
      r.field = "status";
      return r;
    }
  }
  r.stopped = m.halted();
  return r;
}

struct Case {
  const char *name;
  const std::vector<uint8_t> *code;
};

} // namespace

int main() {
  const Case cases[] = {{"sum", &programSum()},
                        {"crc", &programCrc()},
                        {"copy_xor", &programCopyXor()},
                        {"allops", &programAllOps()}};

  for (const Case &c : cases) {
    for (uint32_t init : {0x12345678u, 0u}) {
      Result r = threeWay(*c.code, init, 8192);
      std::printf("  [%s] %-9s init=0x%08x steps=%u stopped=%d field=%s\n",
                  r.same ? "ok" : "DIVERGE", c.name, init, r.steps, r.stopped ? 1 : 0,
                  r.field[0] ? r.field : "-");
      CHECK(r.same, "three engines agree on the real program");
      CHECK(r.steps > 0, "the program executed instructions");
    }
  }

  // Termination is only meaningful from an initial state that terminates:
  // filling every register with a large value sets the loop counters too, so
  // sum/crc/copy_xor then run far past any sane budget. Assert the two cases
  // that are actually observable instead of pretending the others stop.
  Result clean = threeWay(*cases[0].code, 0u, 8192); // sum from zero
  std::printf("  [%s] sum from zero: steps=%u stopped=%d\n", clean.same ? "ok" : "DIVERGE",
              clean.steps, clean.stopped ? 1 : 0);
  CHECK(clean.stopped, "sum from a zeroed register file reaches its stop instruction");

  Result faults = threeWay(*cases[3].code, 0x12345678u, 8192); // allops
  CHECK(!faults.stopped, "allops does not reach a stop: it faults on an address");
  CHECK(faults.same, "the fault itself agrees across the three engines");

  return hsvm_test::summary("lower_full");
}
