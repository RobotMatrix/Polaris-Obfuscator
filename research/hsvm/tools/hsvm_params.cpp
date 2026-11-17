//===- hsvm_params.cpp - print/validate one parameter point ---------------===//
//
//   hsvm_params --n 512 --m 256 --w 8 --c 8 --rbar 2 --rounds 0 \
//               --psi table --workload crc32 --seed 12345
//
// Prints one JSON object: {"params":...,"params_hash":...,"provenance":...}
// Exit codes: 0 ok, 2 invalid parameters, 3 bad usage.
//
//===----------------------------------------------------------------------===//
#include "hsvm/params.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

void usage() {
  std::fprintf(stderr,
               "usage: hsvm_params --n N --m M --w W --c C --rbar R "
               "--rounds R --psi table|spn --workload crc32|base64|bignum|"
               "hashtable|aes_round --seed S\n");
}

bool parseU64(const char *s, uint64_t &out) {
  if (!s || !*s)
    return false;
  char *end = nullptr;
  errno = 0;
  unsigned long long v = std::strtoull(s, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return false;
  out = v;
  return true;
}

} // namespace

int main(int argc, char **argv) {
  hsvm::HsvmParams p;
  bool haveN = false, haveM = false, haveW = false, haveC = false;
  bool haveRBar = false, haveSeed = false;

  for (int i = 1; i < argc; ++i) {
    const char *a = argv[i];
    const char *v = (i + 1 < argc) ? argv[i + 1] : nullptr;
    uint64_t num = 0;

    if (!std::strcmp(a, "--n") && parseU64(v, num)) {
      p.n = static_cast<uint32_t>(num), haveN = true, ++i;
    } else if (!std::strcmp(a, "--m") && parseU64(v, num)) {
      p.m = static_cast<uint32_t>(num), haveM = true, ++i;
    } else if (!std::strcmp(a, "--w") && parseU64(v, num)) {
      p.w = static_cast<uint32_t>(num), haveW = true, ++i;
    } else if (!std::strcmp(a, "--c") && parseU64(v, num)) {
      p.c = static_cast<uint32_t>(num), haveC = true, ++i;
    } else if (!std::strcmp(a, "--rbar") && parseU64(v, num)) {
      p.rBar = static_cast<uint32_t>(num), haveRBar = true, ++i;
    } else if (!std::strcmp(a, "--rounds") && parseU64(v, num)) {
      p.rounds = static_cast<uint32_t>(num), ++i;
    } else if (!std::strcmp(a, "--seed") && parseU64(v, num)) {
      p.seed = num, haveSeed = true, ++i;
    } else if (!std::strcmp(a, "--psi") && v) {
      if (!std::strcmp(v, "table"))
        p.psi = hsvm::PsiMode::Table;
      else if (!std::strcmp(v, "spn"))
        p.psi = hsvm::PsiMode::Spn;
      else {
        std::fprintf(stderr, "hsvm_params: unknown --psi '%s'\n", v);
        return 3;
      }
      ++i;
    } else if (!std::strcmp(a, "--workload") && v) {
      if (!std::strcmp(v, "crc32"))
        p.workload = hsvm::Workload::Crc32;
      else if (!std::strcmp(v, "base64"))
        p.workload = hsvm::Workload::Base64;
      else if (!std::strcmp(v, "bignum"))
        p.workload = hsvm::Workload::Bignum;
      else if (!std::strcmp(v, "hashtable"))
        p.workload = hsvm::Workload::Hashtable;
      else if (!std::strcmp(v, "aes_round"))
        p.workload = hsvm::Workload::AesRound;
      else {
        std::fprintf(stderr, "hsvm_params: unknown --workload '%s'\n", v);
        return 3;
      }
      ++i;
    } else {
      usage();
      return 3;
    }
  }

  if (!haveN || !haveM || !haveW || !haveC || !haveRBar || !haveSeed) {
    usage();
    return 3;
  }

  const std::string reason = hsvm::validate(p);
  if (!reason.empty()) {
    std::fprintf(stderr, "hsvm_params: invalid parameter point: %s\n",
                 reason.c_str());
    return 2;
  }

  std::printf("{\"params\":%s,\"params_hash\":\"%s\",\"provenance\":%s}\n",
              hsvm::toCanonicalJson(p).c_str(), hsvm::paramsHash(p).c_str(),
              hsvm::provenanceJson().c_str());
  return 0;
}
