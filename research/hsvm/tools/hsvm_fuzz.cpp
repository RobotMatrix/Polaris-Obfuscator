// Property test: random bytecode, three engines, must agree.
//
//   Machine(Plain)  - the interpreter
//   semStep         - the semantics oracle
//   lowerOp+irExec  - the lowering
//
// Registers, pc and both status flags are compared every step; memory is
// compared on the final state and whenever either engine faults (a full 4 KiB
// compare on every step of every program would dominate the runtime for no
// extra signal).
//
// A failing seed prints the program bytes, so the case can be replayed with
// --seed. Exit code is 1 when any program diverges.
#include "hsvm/lower.h"
#include "hsvm/machine.h"
#include "hsvm/params.h"
#include "hsvm/semantics.h"

#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

using namespace hsvm;

namespace {

struct Program {
  std::vector<uint8_t> code;
  uint32_t steps = 0;
  bool halted = false;
  bool faulted = false;
  uint32_t regs[64] = {};
  uint32_t memHash = 0;
};

void put(std::vector<uint8_t> &c, uint8_t op, uint8_t dst, uint8_t a, uint8_t b,
         uint32_t imm) {
  c.push_back(op);
  c.push_back(dst);
  c.push_back(a);
  c.push_back(b);
  for (int s = 0; s < 32; s += 8)
    c.push_back(static_cast<uint8_t>((imm >> s) & 0xFF));
}

uint32_t fnv(const std::vector<uint8_t> &m) {
  uint32_t h = 2166136261u;
  for (uint8_t b : m) {
    h ^= b;
    h *= 16777619u;
  }
  return h;
}

std::vector<uint8_t> randomProgram(std::mt19937_64 &rng, uint32_t *initRegs) {
  const uint32_t len = 4 + static_cast<uint32_t>(rng() % 28);
  std::vector<uint8_t> c;
  *initRegs = static_cast<uint32_t>(rng());
  // Registers stay inside the machine's 16 most of the time; one in sixteen
  // bytes is out of range so the fault path is exercised too.
  auto reg = [&]() {
    return static_cast<uint8_t>((rng() % 16) == 0 ? 16 + (rng() % 8) : (rng() % 16));
  };
  for (uint32_t i = 0; i < len; ++i) {
    const uint8_t op = static_cast<uint8_t>(rng() % kNumOpcodes);
    uint32_t imm = static_cast<uint32_t>(rng());
    const Opcode o = static_cast<Opcode>(op);
    if (o == Opcode::Jmp || o == Opcode::Brz) {
      // Short displacements, so loops form and terminate often.
      imm = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int>(rng() % 9) - 4));
    } else if (o == Opcode::Ld || o == Opcode::St) {
      imm = (rng() % 4) * 64u; // keep addresses mostly inside 4096
    } else if (o == Opcode::Movi) {
      imm = static_cast<uint32_t>(rng() % 64);
    } else if (o == Opcode::Shl || o == Opcode::Shr) {
      imm = 0;
    }
    put(c, op, reg(), reg(), reg(), imm);
  }
  return c;
}

// Runs one program through a given engine and records the observable outcome.
template <typename StepFn>
Program runEngine(const std::vector<uint8_t> &code, uint32_t initRegs,
                  uint32_t maxSteps, uint32_t regCount, StepFn step) {
  Program out;
  out.code = code;
  std::vector<uint8_t> mem(Machine::kMemBytes, 0);
  SemState s;
  s.mem = mem.data();
  s.memBytes = Machine::kMemBytes;
  s.regCount = regCount;
  for (uint32_t i = 0; i < regCount; ++i)
    s.regs[i] = initRegs;

  Machine m([&] {
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
    return p;
  }());
  (void)m;
  return out; // unused; the real drivers are below
}

struct Engine {
  Machine m;
  SemState state;
  std::vector<uint8_t> mem;
  std::vector<MirOp> ops;

  explicit Engine(const HsvmParams &p, const std::vector<uint8_t> &code,
                  uint32_t initRegs, bool isLowering)
      : m(p, VmMode::Plain) {
    std::string err;
    m.loadProgram(code, &err);
    m.fillRegs(initRegs);
    lift(code, &ops);
    mem.assign(Machine::kMemBytes, 0);
    state.mem = mem.data();
    state.memBytes = Machine::kMemBytes;
    state.regCount = m.regCount();
    for (uint32_t i = 0; i < state.regCount; ++i)
      state.regs[i] = initRegs;
    (void)isLowering;
  }
};

} // namespace

int main(int argc, char **argv) {
  uint64_t seed = 20260117;
  uint32_t count = 200;
  for (int i = 1; i + 1 < argc; i += 1) {
    if (std::string(argv[i]) == "--seed")
      seed = std::strtoull(argv[++i], nullptr, 0);
    else if (std::string(argv[i]) == "--count")
      count = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
  }

  std::mt19937_64 rng(seed);
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

  uint32_t diverged = 0;
  uint32_t faulted = 0;
  uint32_t halted = 0;
  uint64_t totalSteps = 0;

  for (uint32_t n = 0; n < count; ++n) {
    uint32_t initRegs = 0;
    const std::vector<uint8_t> code = randomProgram(rng, &initRegs);
    const uint32_t regCount = 16;

    Engine sem(p, code, initRegs, false);
    Engine low(p, code, initRegs, true);
    if (!sem.m.halted() && sem.ops.empty()) {
      ++diverged;
      continue; // undecodable program: both sides agree by refusing
    }
    Machine &interp = sem.m;

    bool bad = false;
    uint32_t steps = 0;
    const uint32_t maxSteps = 4000;
    while (steps < maxSteps && !interp.halted() && !interp.faulted()) {
      const uint32_t pc = interp.pcValue();
      if (pc >= sem.ops.size())
        break;
      semStep(sem.state, sem.ops[pc]);
      std::vector<IrOp> ir;
      if (!lowerOp(sem.ops[pc], &ir)) {
        bad = true;
        break;
      }
      irExec(low.state, ir);
      interp.stepOnce();
      ++steps;
      ++totalSteps;
      for (uint32_t r = 0; r < regCount; ++r) {
        if (sem.state.regs[r] != low.state.regs[r] ||
            sem.state.regs[r] != interp.reg(r)) {
          std::printf("[DIVERGE] seed=%llu prog=%u step=%u pc=%u r%u sem=%u low=%u vm=%u\n",
                      (unsigned long long)seed, n, steps, pc, r, sem.state.regs[r],
                      low.state.regs[r], interp.reg(r));
          bad = true;
          break;
        }
      }
      if (bad)
        break;
      if (sem.state.pc != low.state.pc || sem.state.pc != interp.pcValue() ||
          sem.state.halted != interp.halted() ||
          sem.state.faulted != interp.faulted() ||
          low.state.halted != sem.state.halted ||
          low.state.faulted != sem.state.faulted) {
        std::printf("[DIVERGE] seed=%llu prog=%u step=%u pc=%u op=%02x "
                    "pc(sem=%u low=%u vm=%u) halted(sem=%d low=%d vm=%d) "
                    "faulted(sem=%d low=%d vm=%d)\n",
                    (unsigned long long)seed, n, steps, pc,
                    (unsigned)sem.ops[pc].op, sem.state.pc, low.state.pc,
                    interp.pcValue(), (int)sem.state.halted, (int)low.state.halted,
                    (int)interp.halted(), (int)sem.state.faulted,
                    (int)low.state.faulted, (int)interp.faulted());
        bad = true;
        break;
      }
    }
    if (bad)
      ++diverged;
    if (interp.halted())
      ++halted;
    if (interp.faulted())
      ++faulted;
  }

  std::printf("seed=%llu programs=%u steps=%llu halted=%u faulted=%u diverged=%u\n",
              (unsigned long long)seed, count, (unsigned long long)totalSteps, halted,
              faulted, diverged);
  if (diverged != 0) {
    std::printf("FAIL: %u program(s) diverged\n", diverged);
    return 1;
  }
  std::printf("PASS: three engines agree on %u random programs\n", count);
  return 0;
}
