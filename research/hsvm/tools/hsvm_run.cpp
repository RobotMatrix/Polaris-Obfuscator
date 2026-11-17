//===- hsvm_run.cpp - run a test program and dump evidence ----------------===//
//
//   hsvm_run --program allops --mode linear --seed 12345 \
//            --trace trace.jsonl --truth truth.json --dump-state states.bin
//
// Emits on stdout one JSON summary line. Optional artifacts:
//   --trace      JSONL, one record per step: t, pc, op, x_before, x_after
//   --truth      JSON: params_hash, n, m, slots, v[], hv[]  (attack ground truth)
//   --dump-state raw little-endian state words, one record per boundary
//
//===----------------------------------------------------------------------===//
#include "hsvm/machine.h"
#include "hsvm/params.h"
#include "hsvm/programs.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Args {
  std::string program = "sum";
  std::string mode = "plain";
  std::string tracePath;
  std::string truthPath;
  std::string dumpPath;
  uint32_t n = 512;
  uint32_t m = 256;
  uint32_t w = 8;
  uint32_t c = 8;
  uint32_t input = 0;
  uint32_t init = 0x12345678u;
  uint64_t seed = 12345;
  uint64_t steps = 1000000;
};

void usage() {
  std::fprintf(stderr,
               "usage: hsvm_run --program sum|crc|copy_xor|allops "
               "[--mode plain|linear] [--n 512] [--m 256] [--w 8] [--c 8] "
               "[--input N] [--init 0x12345678] [--seed S] [--steps N] "
               "[--trace PATH] [--truth PATH] [--dump-state PATH]\n");
}

bool parseU64(const char *s, uint64_t &out) {
  if (!s || !*s)
    return false;
  char *end = nullptr;
  const unsigned long long v = std::strtoull(s, &end, 0);
  if (!end || *end != '\0')
    return false;
  out = v;
  return true;
}

bool parseArgs(int argc, char **argv, Args &a) {
  for (int i = 1; i < argc; ++i) {
    const std::string k = argv[i];
    const char *v = (i + 1 < argc) ? argv[i + 1] : nullptr;
    if (k == "--program" && v) {
      a.program = v, ++i;
    } else if (k == "--mode" && v) {
      a.mode = v, ++i;
    } else if (k == "--trace" && v) {
      a.tracePath = v, ++i;
    } else if (k == "--truth" && v) {
      a.truthPath = v, ++i;
    } else if (k == "--dump-state" && v) {
      a.dumpPath = v, ++i;
    } else if (k == "--n" && v) {
      uint64_t t = 0;
      if (!parseU64(v, t)) return false;
      a.n = static_cast<uint32_t>(t), ++i;
    } else if (k == "--m" && v) {
      uint64_t t = 0;
      if (!parseU64(v, t)) return false;
      a.m = static_cast<uint32_t>(t), ++i;
    } else if (k == "--w" && v) {
      uint64_t t = 0;
      if (!parseU64(v, t)) return false;
      a.w = static_cast<uint32_t>(t), ++i;
    } else if (k == "--c" && v) {
      uint64_t t = 0;
      if (!parseU64(v, t)) return false;
      a.c = static_cast<uint32_t>(t), ++i;
    } else if (k == "--input" && v) {
      uint64_t t = 0;
      if (!parseU64(v, t)) return false;
      a.input = static_cast<uint32_t>(t), ++i;
    } else if (k == "--init" && v) {
      uint64_t t = 0;
      if (!parseU64(v, t)) return false;
      a.init = static_cast<uint32_t>(t), ++i;
    } else if (k == "--seed" && v) {
      if (!parseU64(v, a.seed)) return false;
      ++i;
    } else if (k == "--steps" && v) {
      if (!parseU64(v, a.steps)) return false;
      ++i;
    } else {
      return false;
    }
  }
  return true;
}

void writeState(FILE *fp, const hsvm::BitVector &s) {
  const uint32_t bytes = s.size() / 8;
  for (uint32_t i = 0; i < bytes; ++i) {
    uint8_t b = 0;
    for (uint32_t j = 0; j < 8; ++j)
      if (s.get(i * 8 + j))
        b |= static_cast<uint8_t>(1u << j);
    std::fputc(b, fp);
  }
}

} // namespace

int main(int argc, char **argv) {
  Args a;
  if (!parseArgs(argc, argv, a)) {
    usage();
    return 3;
  }

  const std::vector<uint8_t> *code = hsvm::findProgram(a.program);
  if (!code) {
    std::fprintf(stderr, "hsvm_run: unknown program '%s'\n", a.program.c_str());
    return 3;
  }

  hsvm::HsvmParams p;
  p.n = a.n;
  p.m = a.m;
  p.w = a.w;
  p.c = a.c;
  p.rBar = 2;
  p.rounds = 0;
  p.psi = hsvm::PsiMode::Table;
  p.seed = a.seed;
  p.workload = hsvm::Workload::Crc32;
  if (!hsvm::validate(p).empty()) {
    std::fprintf(stderr, "hsvm_run: %s\n", hsvm::validate(p).c_str());
    return 2;
  }

  const bool linear = a.mode == "linear";
  if (!linear && a.mode != "plain") {
    std::fprintf(stderr, "hsvm_run: --mode must be plain or linear\n");
    return 3;
  }

  hsvm::Machine vm(p, linear ? hsvm::VmMode::Linear : hsvm::VmMode::Plain);
  std::string err;
  if (!vm.loadProgram(*code, &err)) {
    std::fprintf(stderr, "hsvm_run: %s\n", err.c_str());
    return 3;
  }

  if (a.program == "sum") {
    vm.setReg(0, a.input);
  } else if (a.program == "allops") {
    vm.fillRegs(a.init);
  } else {
    if (a.input == 0 || a.input % 4 != 0) {
      std::fprintf(stderr,
                   "hsvm_run: --input must be a positive multiple of 4 for %s\n",
                   a.program.c_str());
      return 3;
    }
    std::vector<uint8_t> buf(a.input);
    hsvm::fillDeterministic(buf.data(), a.input, a.seed);
    vm.writeMem(0, buf.data(), a.input);
    vm.setReg(0, a.input);
  }

  if (!a.dumpPath.empty())
    vm.setStateDumpEnabled(true);

  const uint64_t steps = vm.run(a.steps);

  std::printf("{\"program\":\"%s\",\"mode\":\"%s\",\"steps\":%llu,"
              "\"halted\":%s,\"faulted\":%s,\"result\":%u,"
              "\"params_hash\":\"%s\"}\n",
              a.program.c_str(), linear ? "linear" : "plain",
              static_cast<unsigned long long>(steps),
              vm.halted() ? "true" : "false",
              vm.faulted() ? "true" : "false", vm.reg(0),
              hsvm::paramsHash(p).c_str());

  if (!a.tracePath.empty()) {
    FILE *fp = std::fopen(a.tracePath.c_str(), "w");
    if (!fp) {
      std::fprintf(stderr, "hsvm_run: cannot write trace\n");
      return 3;
    }
    for (const auto &rec : vm.trace())
      std::fprintf(fp,
                   "{\"t\":%llu,\"pc\":%u,\"op\":%u,\"x_before\":\"%s\","
                   "\"x_after\":\"%s\"}\n",
                   static_cast<unsigned long long>(rec.t), rec.pc, rec.op,
                   hsvm::toHex(rec.xBefore).c_str(),
                   hsvm::toHex(rec.xAfter).c_str());
    std::fclose(fp);
  }

  if (!a.truthPath.empty()) {
    FILE *fp = std::fopen(a.truthPath.c_str(), "w");
    if (!fp) {
      std::fprintf(stderr, "hsvm_run: cannot write truth\n");
      return 3;
    }
    std::fprintf(fp, "{\"params_hash\":\"%s\",\"n\":%u,\"m\":%u,\"slots\":%u,\n",
                 hsvm::paramsHash(p).c_str(), p.n, p.m,
                 vm.programSlots());
    std::fprintf(fp, " \"v\":[");
    for (size_t i = 0; i < vm.vTable().size(); ++i)
      std::fprintf(fp, "%s\"%s\"", i ? "," : "",
                   hsvm::toHex(vm.vTable()[i]).c_str());
    std::fprintf(fp, "],\n \"hv\":[");
    for (size_t i = 0; i < vm.vTable().size(); ++i)
      std::fprintf(fp, "%s\"%s\"", i ? "," : "",
                   hsvm::toHex(hsvm::matVec(vm.projection(), vm.vTable()[i]))
                       .c_str());
    std::fprintf(fp, "]}\n");
    std::fclose(fp);
  }

  if (!a.dumpPath.empty()) {
    FILE *fp = std::fopen(a.dumpPath.c_str(), "wb");
    if (!fp) {
      std::fprintf(stderr, "hsvm_run: cannot write state dump\n");
      return 3;
    }
    for (const auto &s : vm.stateDump())
      writeState(fp, s);
    std::fclose(fp);
  }

  return vm.faulted() ? 1 : 0;
}
