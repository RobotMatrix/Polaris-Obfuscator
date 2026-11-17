//===- params.h - HSV parameter set and validation -----------------------===//
//
// One place defines what a legal parameter point is. The compiler pass, the
// model tools and the Python protocol checker must all agree; the C++ side is
// authoritative and the Python checker cross-checks through hsvm_params.
//
// Field meaning (research plan §4, D-04/D-06):
//   n      state bits                         (F2^n)
//   m      projection rank, m < n             (x = H s, H is m x n)
//   w      psi window bits                    (|A_i| = w)
//   c      psi output bits                    (E_i is n x c)
//   r_bar  average nonzeros per scatter column
//   rounds psi rounds, SPN mode only
//   seed   RNG seed, must be explicit (0 is rejected: clock-derived seeds
//          make every report irreproducible)
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_PARAMS_H
#define HSV_M_PARAMS_H

#include <cstdint>
#include <string>

namespace hsvm {

enum class PsiMode { Table, Spn, Arx };
enum class Workload { Crc32, Base64, Bignum, Hashtable, AesRound };

struct HsvmParams {
  uint32_t n = 0;
  uint32_t m = 0;
  uint32_t w = 0;
  uint32_t c = 0;
  uint32_t rBar = 0;
  uint32_t rounds = 0;
  PsiMode psi = PsiMode::Table;
  uint64_t seed = 0;
  Workload workload = Workload::Crc32;

  uint32_t kernelDim() const { return n - m; }
  uint32_t stateWords() const { return (n + 63u) / 64u; }
  uint32_t scatterNonzeros() const { return c * rBar; }

  // Size of the psi lookup table in bytes; 0 for SPN mode.
  uint64_t tableBytes() const;
};

// Empty string when the point is legal, otherwise a human-readable reason.
std::string validate(const HsvmParams &p);

// Throws std::invalid_argument carrying validate()'s message.
void requireValid(const HsvmParams &p);

const char *toString(PsiMode mode);
const char *toString(Workload workload);

// Canonical JSON of the parameter fields only: sorted keys, no whitespace.
// This is what paramsHash() covers, so it must never include provenance.
std::string toCanonicalJson(const HsvmParams &p);

// {"build_time":...,"git_commit":...,"kernel_version":...}
std::string provenanceJson();

// FNV-1a 64 over toCanonicalJson(). An identity tag for reports, NOT a
// cryptographic hash: it only needs to catch accidental parameter drift.
std::string paramsHash(const HsvmParams &p);

} // namespace hsvm

#endif // HSV_M_PARAMS_H
