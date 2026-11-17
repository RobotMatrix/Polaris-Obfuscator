// Dump a test program as C source carrying @hsvm_bytecode, plus the outcome the
// oracle expects. Used by scripts/verify_vmp_pass.sh to compare the Polaris pass
// against the interpreter without duplicating either side by hand.
//
// usage: hsvm_dump_program <name> <initRegs> <maxSteps> <out.c>
//   maxSteps = 0 means "no budget" (bounded internally to keep the run finite).
// Prints one line: r0=<dec> | fault | oob | budget
#include "hsvm/machine.h"
#include "hsvm/programs.h"
#include "hsvm/semantics.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace hsvm;

int main(int argc, char **argv) {
  if (argc < 5) {
    std::fprintf(stderr,
                 "usage: %s <name> <initRegs> <maxSteps> <out.c>\n", argv[0]);
    return 2;
  }
  const std::vector<uint8_t> *prog = findProgram(argv[1]);
  if (!prog) {
    std::fprintf(stderr, "unknown program '%s'\n", argv[1]);
    return 2;
  }
  const uint32_t initRegs = static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 0));
  uint32_t maxSteps = static_cast<uint32_t>(std::strtoul(argv[3], nullptr, 0));
  if (maxSteps == 0)
    maxSteps = 50000000u;

  std::vector<MirOp> ops;
  if (!lift(*prog, &ops)) {
    std::fprintf(stderr, "program does not lift\n");
    return 2;
  }

  std::vector<uint8_t> mem(Machine::kMemBytes, 0);
  SemState s;
  s.mem = mem.data();
  s.memBytes = Machine::kMemBytes;
  s.regCount = 16;
  for (uint32_t i = 0; i < s.regCount; ++i)
    s.regs[i] = initRegs;

  uint32_t steps = 0;
  while (steps < maxSteps && !s.halted && !s.faulted) {
    if (s.pc >= ops.size())
      break;
    semStep(s, ops[s.pc]);
    ++steps;
  }

  const char *verdict = "oob";
  std::string line;
  char buf[64];
  if (s.faulted) {
    verdict = "fault";
    line = "fault";
  } else if (s.halted) {
    verdict = "r0";
    std::snprintf(buf, sizeof(buf), "r0=%u", s.regs[0]);
    line = buf;
  } else if (steps >= maxSteps) {
    verdict = "budget";
    line = "budget";
  } else {
    line = "oob";
  }

  FILE *out = std::fopen(argv[4], "w");
  if (!out) {
    std::fprintf(stderr, "cannot write %s\n", argv[4]);
    return 2;
  }
  std::fprintf(out,
               "#include <stdio.h>\n"
               "extern int hsvm_entry(void);\n"
               "extern const unsigned char hsvm_bytecode[%zu];\n"
               "extern const unsigned hsvm_init;\n"
               "int main(void) {\n"
               "  unsigned v = (unsigned)hsvm_entry();\n"
               "  if (v == 0xFFFFFFFEu) { printf(\"fault\\n\"); return 0; }\n"
               "  if (v == 0xFFFFFFFFu) { printf(\"oob\\n\"); return 0; }\n"
               "  printf(\"r0=%%u\\n\", v);\n"
               "  return 0;\n"
               "}\n"
               "const unsigned char hsvm_bytecode[%zu] __attribute__((used)) = {",
               prog->size(), prog->size());
  for (size_t i = 0; i < prog->size(); ++i)
    std::fprintf(out, "%s%u", i ? "," : "", (*prog)[i]);
  std::fprintf(out, "};\nconst unsigned hsvm_init = %uu;\n", initRegs);
  std::fclose(out);

  std::printf("%s\n", line.c_str());
  (void)verdict;
  return 0;
}
