//===- params.cpp - HSV parameter validation and provenance ---------------===//
#include "hsvm/params.h"

#include <cstdio>
#include <sstream>
#include <stdexcept>

#ifndef HSV_GIT_COMMIT
#define HSV_GIT_COMMIT "unknown"
#endif
#ifndef HSV_BUILD_TIME
#define HSV_BUILD_TIME "unknown"
#endif
#ifndef HSV_KERNEL_VERSION
#define HSV_KERNEL_VERSION "hsvm-core-dev"
#endif

namespace hsvm {

namespace {

// Hard ceilings keep every downstream buffer size representable and every
// model experiment tractable on one machine.
constexpr uint32_t kMaxBits = 1u << 20;   // 1 Mibit state
constexpr uint32_t kMaxTableW = 16;       // 2^16 * c bits is the table ceiling
constexpr uint32_t kMaxRounds = 16;

std::string fmt(const char *what, uint64_t value) {
  std::ostringstream os;
  os << what << " (" << value << ")";
  return os.str();
}

} // namespace

uint64_t HsvmParams::tableBytes() const {
  if (psi != PsiMode::Table || w > kMaxTableW)
    return 0;
  return (1ull << w) * static_cast<uint64_t>(c) / 8ull;
}

const char *toString(PsiMode mode) {
  switch (mode) {
  case PsiMode::Table:
    return "table";
  case PsiMode::Spn:
    return "spn";
  case PsiMode::Arx:
    return "arx";
  }
  return "?";
}

const char *toString(Workload workload) {
  switch (workload) {
  case Workload::Crc32:
    return "crc32";
  case Workload::Base64:
    return "base64";
  case Workload::Bignum:
    return "bignum";
  case Workload::Hashtable:
    return "hashtable";
  case Workload::AesRound:
    return "aes_round";
  }
  return "?";
}

std::string validate(const HsvmParams &p) {
  if (p.n < 8)
    return "n must be at least 8 bits";
  if (p.n > kMaxBits)
    return fmt("n exceeds the supported maximum", kMaxBits);
  if (p.m == 0)
    return "m must be at least 1 (projection must have a nonzero rank)";
  if (p.m >= p.n)
    return "m must be < n (otherwise there is no hidden state to protect)";
  if (p.w == 0)
    return "w must be at least 1";
  if (p.w > p.n)
    return "w must be <= n (a window cannot exceed the state)";
  if (p.c == 0)
    return "c must be at least 1";
  if (p.c > p.n)
    return "c must be <= n (scatter output cannot exceed the state)";
  if (p.rBar == 0)
    return "r_bar must be at least 1";
  if (static_cast<uint64_t>(p.c) * p.rBar > p.n)
    return "c * r_bar must be <= n (scatter positions must fit the state)";

  if (p.psi == PsiMode::Table) {
    if (p.w > kMaxTableW)
      return "table mode requires w <= 16; use spn/arx for wider windows";
    if (p.c > kMaxTableW)
      return "table mode requires c <= 16 (table entries are c bits)";
    if (p.rounds != 0)
      return "table mode requires rounds == 0 (rounds belong to spn/arx)";
  } else if (p.psi == PsiMode::Arx) {
    if (p.w % 8 != 0 || p.w < 16)
      return "arx mode requires w to be a multiple of 8 and at least 16";
    if (p.rounds == 0)
      return "arx mode requires rounds >= 1";
    if (p.rounds > kMaxRounds)
      return fmt("rounds exceeds the supported maximum", kMaxRounds);
  } else {
    if (p.w % 8 != 0)
      return "spn mode requires w to be a multiple of 8 (8-bit S-box lanes)";
    if (p.rounds == 0)
      return "spn mode requires rounds >= 1";
    if (p.rounds > kMaxRounds)
      return fmt("rounds exceeds the supported maximum", kMaxRounds);
  }

  if (p.seed == 0)
    return "seed must be nonzero: a clock-derived seed makes results "
           "irreproducible (plan §7.3 rule 2)";

  switch (p.workload) {
  case Workload::Crc32:
  case Workload::Base64:
  case Workload::Bignum:
  case Workload::Hashtable:
  case Workload::AesRound:
    break;
  default:
    return "unknown workload enum value";
  }
  return "";
}

void requireValid(const HsvmParams &p) {
  const std::string reason = validate(p);
  if (!reason.empty())
    throw std::invalid_argument("HsvmParams: " + reason);
}

std::string toCanonicalJson(const HsvmParams &p) {
  // Sorted keys, no spaces: stable across builds and locales.
  std::ostringstream os;
  os << "{\"c\":" << p.c
     << ",\"m\":" << p.m
     << ",\"n\":" << p.n
     << ",\"psi\":\"" << toString(p.psi) << "\""
     << ",\"r_bar\":" << p.rBar
     << ",\"rounds\":" << p.rounds
     << ",\"seed\":" << p.seed
     << ",\"w\":" << p.w
     << ",\"workload\":\"" << toString(p.workload) << "\"}";
  return os.str();
}

std::string provenanceJson() {
  std::ostringstream os;
  os << "{\"build_time\":\"" << HSV_BUILD_TIME << "\""
     << ",\"git_commit\":\"" << HSV_GIT_COMMIT << "\""
     << ",\"kernel_version\":\"" << HSV_KERNEL_VERSION << "\"}";
  return os.str();
}

std::string paramsHash(const HsvmParams &p) {
  const std::string s = toCanonicalJson(p);
  uint64_t h = 1469598103934665603ULL; // FNV-1a 64 offset basis
  for (unsigned char ch : s) {
    h ^= static_cast<uint64_t>(ch);
    h *= 1099511628211ULL;
  }
  char buf[17];
  std::snprintf(buf, sizeof(buf), "%016llx",
                static_cast<unsigned long long>(h));
  return std::string(buf);
}

} // namespace hsvm
