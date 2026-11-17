// V-03: differential harness, interpreter vs executable semantics.
//
// The point of this test is to be able to FAIL precisely: when the two
// disagree it reports the first step and the first differing field, because a
// vague "states differ" is useless once a lowering is added on top.
#include "hsvm/machine.h"
#include "hsvm/params.h"
#include "hsvm/programs.h"
#include "hsvm/instr.h"
#include "hsvm/semantics.h"
#include "test_harness.h"

#include <cstdio>
#include <vector>

using namespace hsvm;

namespace {

struct DiffReport {
  bool same = true;
  uint32_t step = 0;
  const char *field = "";
  uint32_t pc = 0;
  uint64_t a = 0;
  uint64_t b = 0;
};

MirOp decodeAt(const std::vector<uint8_t> &code, uint32_t pc) {
  MirOp op;
  const size_t off = static_cast<size_t>(pc) * kInstrBytes;
  if (off + kInstrBytes > code.size())
    return op;
  op.op = static_cast<Opcode>(code[off]);
  op.dst = code[off + 1];
  op.a = code[off + 2];
  op.b = code[off + 3];
  op.imm = static_cast<uint32_t>(code[off + 4]) |
           (static_cast<uint32_t>(code[off + 5]) << 8) |
           (static_cast<uint32_t>(code[off + 6]) << 16) |
           (static_cast<uint32_t>(code[off + 7]) << 24);
  return op;
}

// Runs both engines in lockstep and returns the first divergence.
DiffReport diffRun(const HsvmParams &p, const std::vector<uint8_t> &code,
                   uint32_t initRegs, uint32_t maxSteps) {
  DiffReport r;
  Machine m(p, VmMode::Plain);
  std::string err;
  if (!m.loadProgram(code, &err))
    return r;
  m.fillRegs(initRegs);

  std::vector<uint8_t> mem(Machine::kMemBytes, 0);
  SemState s;
  s.mem = mem.data();
  s.memBytes = Machine::kMemBytes;
  s.regCount = m.regCount();
  for (uint32_t i = 0; i < m.regCount(); ++i)
    s.regs[i] = initRegs;

  for (uint32_t step = 0; step < maxSteps; ++step) {
    if (m.halted() || m.faulted())
      break;
    const uint32_t pc = m.pcValue();
    const MirOp op = decodeAt(code, pc);
    const bool liked = semStep(s, op);
    const bool mok = m.stepOnce();
    ++r.step;
    (void)liked;
    (void)mok;
    for (uint32_t i = 0; i < m.regCount(); ++i) {
      if (s.regs[i] != m.reg(i)) {
        std::printf("  instr: %s | reg index %u\n",
                    disassemble(decodeInstr(&code[static_cast<size_t>(pc) * kInstrBytes])).c_str(),
                    i);
        r.same = false;
        r.field = "register";
        r.pc = pc;
        r.a = s.regs[i];
        r.b = m.reg(i);
        return r;
      }
    }
    for (uint32_t a = 0; a + 4 <= Machine::kMemBytes; a += 4) {
      const uint32_t mv = m.readMem32(a);
      const uint32_t sv = semLoad32(s, a);
      if (mv != sv) {
        r.same = false;
        r.field = "memory";
        r.pc = pc;
        r.a = sv;
        r.b = mv;
        return r;
      }
    }
    if (s.pc != m.pcValue()) {
      r.same = false;
      r.field = "pc";
      r.pc = pc;
      r.a = s.pc;
      r.b = m.pcValue();
      return r;
    }
    if (s.halted != m.halted() || s.faulted != m.faulted()) {
      r.same = false;
      r.field = "status";
      r.pc = pc;
      r.a = (s.halted ? 1u : 0u) | (s.faulted ? 2u : 0u);
      r.b = (m.halted() ? 1u : 0u) | (m.faulted() ? 2u : 0u);
      return r;
    }
  }
  return r;
}

void report(const DiffReport &r, const char *what) {
  if (r.same) {
    std::printf("  [ok] %s: %u steps agree\n", what, r.step);
    return;
  }
  std::printf("  [DIVERGE] %s at step %u (pc=%u) field=%s sem=%llu vm=%llu\n", what,
              r.step, r.pc, r.field, (unsigned long long)r.a,
              (unsigned long long)r.b);
}

} // namespace

int main() {
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

  DiffReport a = diffRun(p, programAllOps(), 0x12345678u, 4096);
  report(a, "allops");
  CHECK(a.same, "interpreter and oracle agree on allops");

  DiffReport b = diffRun(p, programAllOps(), 0x0u, 4096);
  report(b, "allops/zero-regs");
  CHECK(b.same, "interpreter and oracle agree with zeroed registers");

  DiffReport c = diffRun(p, programAllOps(), 0xFFFFFFFFu, 4096);
  report(c, "allops/max-regs");
  CHECK(c.same, "interpreter and oracle agree with saturated registers");

  CHECK(a.step > 0, "the differential actually executed instructions");

  struct Case { const char *name; const std::vector<uint8_t> *code; };
  const Case cases[] = {{"sum", &programSum()},
                        {"crc", &programCrc()},
                        {"copy_xor", &programCopyXor()}};
  for (const Case &c : cases) {
    DiffReport r1 = diffRun(p, *c.code, 0x12345678u, 4096);
    report(r1, c.name);
    CHECK(r1.same, "interpreter and oracle agree on real program");
    CHECK(r1.step > 0, "real program executed instructions");
    DiffReport r2 = diffRun(p, *c.code, 0x0u, 4096);
    report(r2, c.name);
    CHECK(r2.same, "interpreter and oracle agree on real program (zero regs)");
  }

  return hsvm_test::summary("diff");
}
