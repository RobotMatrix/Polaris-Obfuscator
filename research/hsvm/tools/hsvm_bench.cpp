// Bench: interpreted bytecode vs the same bytecode lowered by the Polaris pass.
//
// This measures "compiled vs interpreted" for one loop-heavy program. It is NOT
// R_plain: R_plain compares a protected VM against a plain baseline under the
// fixed 4.2-4.34 ns cost model of doc 5.5, and swapping that ruler is forbidden.
//
// The trip count arrives in a register and the emitted C reads it from argv, so
// nothing can be constant-folded away.
//
//   loop: acc += count ; count -= 1 ; if count == 0 -> halt ; goto loop
//
// Deliberately arithmetic only: a memory-touching loop runs off the 4096-byte
// space after 1024 iterations, which would measure the fault path instead.
#include "hsvm/machine.h"
#include "hsvm/params.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace hsvm;

namespace {

void enc(std::vector<uint8_t> &c, Opcode op, uint8_t dst, uint8_t a, uint8_t b,
         uint32_t imm) {
  c.push_back(static_cast<uint8_t>(op));
  c.push_back(dst);
  c.push_back(a);
  c.push_back(b);
  for (int s = 0; s < 32; s += 8)
    c.push_back(static_cast<uint8_t>((imm >> s) & 0xFF));
}

// 11 instructions; r1 = trip count, r2 = cursor, r0 = checksum.
std::vector<uint8_t> loopProgram() {
  std::vector<uint8_t> c;
  enc(c, Opcode::Movi, 0, 0, 0, 0);          // 0 acc = 0
  enc(c, Opcode::Movi, 4, 0, 0, 1);          // 1 one = 1
  enc(c, Opcode::Add, 0, 0, 1, 0);           // 2 acc += count
  enc(c, Opcode::Sub, 1, 1, 4, 0);           // 3 count -= 1
  enc(c, Opcode::Brz, 0, 1, 0, 2);           // 4 count == 0 -> 6
  enc(c, Opcode::Jmp, 0, 0, 0, 0xFFFFFFFCu); // 5 -> 2
  enc(c, Opcode::Halt, 0, 0, 0, 0);          // 6
  return c;
}

std::string emitC(const std::vector<uint8_t> &code) {
  std::string s;
  s += "#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n";
  s += "extern int hsvm_entry(int);\n";
  s += "extern const unsigned char hsvm_bytecode[" + std::to_string(code.size()) +
       "];\n";
  s += "int main(int argc, char **argv) {\n";
  s += "  int n = argc > 1 ? atoi(argv[1]) : 0;\n";
  s += "  printf(\"%d\\n\", hsvm_entry(n));\n  return 0;\n}\n";
  s += "const unsigned char hsvm_bytecode[" + std::to_string(code.size()) +
       "] __attribute__((used)) = {";
  for (size_t i = 0; i < code.size(); ++i)
    s += (i ? "," : "") + std::to_string(code[i]);
  s += "};\n";
  return s;
}

double timeInterpreter(const std::vector<uint8_t> &code, uint32_t count,
                       uint64_t *steps, uint32_t *reg0Out) {
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
    return -1;
  m.fillRegs(0);
  m.setReg(1, count);
  const auto t0 = std::chrono::steady_clock::now();
  // Machine::run() defaults to a 1e6 step cap: without this the interpreter
  // silently stops early and the two runs compare different work.
  m.run(50000000u);
  const auto t1 = std::chrono::steady_clock::now();
  *reg0Out = m.reg(0);
  *steps = m.programSlots();
  return std::chrono::duration<double>(t1 - t0).count();
}

} // namespace

int main(int argc, char **argv) {
  const uint32_t count = argc > 1 ? static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 0))
                                  : 1000000u;
  const std::string work = argc > 2 ? argv[2] : "/tmp/hsvm_bench";
  const std::vector<uint8_t> code = loopProgram();

  uint64_t slots = 0;
  uint32_t reg0 = 0;
  const double tInterp = timeInterpreter(code, count, &slots, &reg0);

  FILE *fh = std::fopen((work + ".c").c_str(), "w");
  if (!fh) {
    std::fprintf(stderr, "cannot write %s.c\n", work.c_str());
    return 2;
  }
  const std::string src = emitC(code);
  std::fwrite(src.data(), 1, src.size(), fh);
  std::fclose(fh);

  // Must be the Polaris clang: the system one has no -passes=hsvm.
  const char *envClang = std::getenv("HSV_CLANG");
  if (!envClang) {
    std::fprintf(stderr, "set HSV_CLANG to the rebuilt Polaris clang\n");
    return 2;
  }
  const std::string build = std::string(envClang) + " -O1 -w -mllvm -passes=hsvm -o " +
                            work + " " + work + ".c 2>" + work + ".err";
  if (std::system(build.c_str()) != 0) {
    std::fprintf(stderr, "emitted program failed to build (see %s.err)\n", work.c_str());
    return 2;
  }

  const auto t0 = std::chrono::steady_clock::now();
  const std::string runCmd = work + " " + std::to_string(count) + " > " + work + ".out";
  if (std::system(runCmd.c_str()) != 0) {
    std::fprintf(stderr, "emitted program failed to run\n");
    return 2;
  }
  const auto t1 = std::chrono::steady_clock::now();
  const double tNative = std::chrono::duration<double>(t1 - t0).count();

  // The two runs must agree on the result, otherwise this compares different work.
  const uint32_t interpR0 = reg0;
  uint32_t nativeR0 = 0;
  {
    FILE *rf = std::fopen((work + ".out").c_str(), "r");
    if (rf) {
      long long v = 0;
      if (std::fscanf(rf, "%lld", &v) == 1)
        nativeR0 = static_cast<uint32_t>(static_cast<int32_t>(v));
      std::fclose(rf);
    }
  }
  std::printf("result       : interp=%u native=%u %s\n", interpR0, nativeR0,
              interpR0 == nativeR0 ? "MATCH" : "MISMATCH");
  std::printf("trips        : %u\n", count);
  std::printf("interpreter  : %.6f s\n", tInterp);
  std::printf("native (pass): %.6f s\n", tNative);
  std::printf("speedup      : %.2fx  (compiled vs interpreted; NOT R_plain)\n",
              tNative > 0 ? tInterp / tNative : 0.0);
  // The timing is informational; only the result equality is a pass condition.
  return interpR0 == nativeR0 ? 0 : 1;
}
