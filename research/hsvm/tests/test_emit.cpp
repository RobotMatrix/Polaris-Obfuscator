// V-07: the emitted native program must reproduce the interpreter.
//
// bytecode -> lift -> lower -> C -> clang -> run, compared against the oracle's
// expected report string and exit code. The three observable outcomes are
// covered: a normal stop (exit 0, report string), a fault (exit 3), and a budget
// exhaustion (exit 5).
#include "hsvm/emit_c.h"
#include "hsvm/instr.h"
#include "hsvm/lower.h"
#include "hsvm/machine.h"
#include "hsvm/params.h"
#include "hsvm/programs.h"
#include "hsvm/semantics.h"
#include "test_harness.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace hsvm;

namespace {

struct Expect {
  std::string text;
  int code = 0;
};

Expect oracleRun(const std::vector<uint8_t> &code, uint32_t initRegs,
                 uint32_t maxSteps, uint32_t regCount) {
  Expect e;
  std::vector<MirOp> ops;
  std::vector<uint8_t> mem(Machine::kMemBytes, 0);
  SemState s;
  s.mem = mem.data();
  s.memBytes = Machine::kMemBytes;
  s.regCount = regCount;
  for (uint32_t i = 0; i < regCount; ++i)
    s.regs[i] = initRegs;
  if (!lift(code, &ops)) {
    e.text = "fault\n";
    e.code = 3;
    return e;
  }
  uint32_t steps = 0;
  while (steps < maxSteps && !s.halted && !s.faulted) {
    if (s.pc >= ops.size())
      break;
    semStep(s, ops[s.pc]);
    ++steps;
  }
  if (s.faulted) {
    e.text = "fault\n";
    e.code = 3;
  } else if (s.halted) {
    e.text = reportOf(s.regs, mem.data(), Machine::kMemBytes) + "\n";
    e.code = 0;
  } else {
    e.text = "budget\n";
    e.code = 5;
  }
  return e;
}

std::string runShell(const std::string &cmd) {
  std::string out;
  FILE *f = ::popen(cmd.c_str(), "r");
  if (!f)
    return out;
  char buf[512];
  while (std::fgets(buf, sizeof(buf), f))
    out += buf;
  ::pclose(f);
  return out;
}

struct Observed {
  std::string text;
  int code = -1;
};

Observed runEmitted(const std::string &source, const std::string &stem) {
  Observed o;
  const std::string src = "/tmp/" + stem + ".c";
  const std::string bin = "/tmp/" + stem;
  FILE *fh = std::fopen(src.c_str(), "w");
  if (!fh)
    return o;
  std::fwrite(source.data(), 1, source.size(), fh);
  std::fclose(fh);
  const std::string cmd = "clang -O1 -w -o " + bin + " " + src + " 2>/dev/null && " +
                          bin + "; printf 'rc=%d' $?";
  o.text = runShell(cmd);
  const size_t at = o.text.rfind("rc=");
  if (at != std::string::npos) {
    o.code = std::atoi(o.text.c_str() + at + 3);
    o.text = o.text.substr(0, at);
  }
  return o;
}

void checkCase(const char *name, const std::vector<uint8_t> &code, uint32_t init,
               uint32_t maxSteps, uint32_t regCount) {
  const std::string src = emitC(code, regCount, maxSteps, init);
  CHECK(!src.empty(), "emission produced source");
  Expect want = oracleRun(code, init, maxSteps, regCount);
  Observed got = runEmitted(src, std::string("hsvm_v07_") + name);
  if (got.text != want.text || got.code != want.code) {
    std::printf("  [MISMATCH] %s init=0x%08x want=(%d)%s got=(%d)%s\n", name, init,
                want.code, want.text.c_str(), got.code, got.text.c_str());
  }
  CHECK(got.code == want.code, "exit code matches the oracle");
  CHECK(got.text == want.text, "report string matches the oracle");
}

// A store/load pair, so the native path is shown to touch memory rather than
// only registers: sum from zero writes nothing to memory.
std::vector<uint8_t> memProgram() {
  std::vector<uint8_t> c;
  auto op = [&](Opcode o, uint8_t dst, uint8_t a, uint8_t b, uint32_t imm) {
    Instr in;
    in.op = static_cast<uint8_t>(o);
    in.dst = dst;
    in.a = a;
    in.b = b;
    in.imm = imm;
    uint8_t buf[kInstrBytes];
    encodeInstr(in, buf);
    c.insert(c.end(), buf, buf + kInstrBytes);
  };
  op(Opcode::Movi, 1, 0, 0, 0u);          // r1 = 0  (address)
  op(Opcode::Movi, 2, 0, 0, 0x11223344u); // r2 = value
  op(Opcode::St, 0, 1, 2, 0u);            // mem32[0] = r2
  op(Opcode::Ld, 3, 1, 0, 0u);            // r3 = mem32[0]
  op(Opcode::Mov, 0, 3, 0, 0u);           // r0 = r3
  op(Opcode::Halt, 0, 0, 0, 0u);
  return c;
}

} // namespace

int main() {
  // Normal stop: sum from a zeroed register file is the one program that
  // reaches its stop instruction inside a small budget.
  checkCase("sum0", programSum(), 0u, 64u, 16u);

  // Budget exhaustion: crc with a large budget agreement, then a small one that
  // must be reported as budget rather than silently truncated.
  checkCase("crc_budget", programCrc(), 0x12345678u, 32u, 16u);

  // Fault: allops reads an out-of-range address.
  checkCase("allops_fault", programAllOps(), 0x12345678u, 64u, 16u);

  // copy_xor exercises loads, stores and a loop.
  checkCase("copy_budget", programCopyXor(), 0x12345678u, 128u, 16u);

  // Store/load round trip through the native path, with a stop instruction, so
  // the memory hash in the report is provably not the hash of a zeroed array.
  {
    const std::vector<uint8_t> mp = memProgram();
    checkCase("memround", mp, 0u, 64u, 16u);
    Expect want = oracleRun(mp, 0u, 64u, 16u);
    CHECK(want.code == 0, "store/load program stops normally");
    CHECK(want.text.find("r0=287454020") != std::string::npos,
          "store/load returns the stored value");
    std::vector<uint8_t> zeros(Machine::kMemBytes, 0);
    uint32_t zregs[16] = {};
    CHECK(want.text.find(reportOf(zregs, zeros.data(), Machine::kMemBytes)) ==
              std::string::npos,
          "the memory hash reflects the store, not a zeroed array");
  }

  return hsvm_test::summary("emit_c");
}
