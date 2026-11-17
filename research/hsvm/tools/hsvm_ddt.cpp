// §6.2 global normalization, first half: what an affine module encoding leaves
// visible.
//
// Claim under test: if the per-lane module encoding is affine (M x + c), the
// differential profile of the composite is a relabelling of the underlying
// function's profile — affine maps act linearly on differences, so the
// difference-distribution table of F = A2 o psi o A1 has exactly the same
// multiset of rows as psi's. An attacker therefore identifies the family (and
// the differential structure) with no queries beyond the table, which is the
// precondition for normalizing the encodings away.
//
// A random per-lane bijection does not have this property, which is what makes
// the test meaningful rather than vacuous.
#include <hsvm/gf2.h>
#include <hsvm/modenc.h>
#include <hsvm/params.h>
#include <hsvm/psi.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <random>
#include <vector>

namespace {

// 8x8 GF(2) matrix applied to a byte, plus a constant.
struct Affine8 {
  uint8_t m[8];
  uint8_t c;
};

Affine8 randomAffine(std::mt19937_64 &rng, bool *ok) {
  Affine8 a{};
  // Random matrix; retry until its 8 rows are independent over GF(2).
  for (int attempt = 0; attempt < 64; ++attempt) {
    for (int i = 0; i < 8; ++i)
      a.m[i] = static_cast<uint8_t>(rng() & 0xFF);
    std::vector<uint8_t> rows(a.m, a.m + 8);
    int rank = 0;
    for (int bit = 7; bit >= 0; --bit) {
      int pivot = -1;
      for (int r = rank; r < 8; ++r)
        if ((rows[r] >> bit) & 1)
          pivot = r;
      if (pivot < 0)
        continue;
      std::swap(rows[rank], rows[pivot]);
      for (int r = 0; r < 8; ++r)
        if (r != rank && ((rows[r] >> bit) & 1))
          rows[r] ^= rows[rank];
      ++rank;
    }
    if (rank == 8) {
      a.c = static_cast<uint8_t>(rng() & 0xFF);
      *ok = true;
      return a;
    }
  }
  *ok = false;
  return a;
}

uint8_t applyAffine(const Affine8 &a, uint8_t x) {
  uint8_t r = 0;
  for (int i = 0; i < 8; ++i) {
    uint8_t bit = 0;
    for (int j = 0; j < 8; ++j)
      if ((a.m[i] >> j) & 1)
        bit ^= (x >> j) & 1;
    r = static_cast<uint8_t>(r | (bit << i));
  }
  return static_cast<uint8_t>(r ^ a.c);
}

// Difference distribution table profile: for each input difference, the sorted
// multiset of output-difference counts. Affine equivalence permutes the rows and
// the columns, so the multiset of *sorted rows* is invariant.
std::vector<std::vector<int>> ddtProfile(const std::vector<uint8_t> &perm) {
  const int n = 256;
  std::vector<std::vector<int>> prof(n - 1);
  for (int a = 1; a < n; ++a) {
    std::vector<int> row(n, 0);
    for (int x = 0; x < n; ++x)
      ++row[perm[x] ^ perm[x ^ a]];
    std::sort(row.begin(), row.end());
    prof[a - 1] = row;
  }
  std::sort(prof.begin(), prof.end());
  return prof;
}

std::vector<uint8_t> tableOf(hsvm::Psi &psi) {
  std::vector<uint8_t> t(256);
  for (int x = 0; x < 256; ++x)
    t[x] = static_cast<uint8_t>(psi.applyU64(static_cast<uint64_t>(x)) & 0xFF);
  return t;
}

} // namespace

int main(int argc, char **argv) {
  const char *out = nullptr;
  for (int i = 1; i < argc; ++i)
    if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc)
      out = argv[++i];

  hsvm::HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = 8;
  p.c = 8;
  p.rBar = 1;
  p.rounds = 0;
  p.psi = hsvm::PsiMode::Table;
  p.seed = 9001;
  p.workload = hsvm::Workload::Crc32;
  auto psi = hsvm::makePsi(p, 0);

  std::mt19937_64 rng(4242);
  bool ok = false;
  const Affine8 a1 = randomAffine(rng, &ok);
  const Affine8 a2 = randomAffine(rng, &ok);
  if (!ok) {
    std::fprintf(stderr, "could not build an invertible affine map\n");
    return 2;
  }

  const std::vector<uint8_t> base = tableOf(*psi);
  std::vector<uint8_t> affineWrapped(256), randomWrapped(256);
  for (int x = 0; x < 256; ++x) {
    const uint8_t mid = static_cast<uint8_t>(psi->applyU64(
        static_cast<uint64_t>(applyAffine(a1, static_cast<uint8_t>(x)))) & 0xFF);
    affineWrapped[x] = applyAffine(a2, mid);
  }
  hsvm::ModuleEncoder enc(1, 77);
  for (int x = 0; x < 256; ++x)
    randomWrapped[x] = static_cast<uint8_t>(
        enc.encode(psi->applyU64(enc.decode(static_cast<uint64_t>(x)))) & 0xFF);

  const auto profBase = ddtProfile(base);
  const auto profAff = ddtProfile(affineWrapped);
  const auto profRnd = ddtProfile(randomWrapped);

  const bool affineSame = (profBase == profAff);
  const bool randomSame = (profBase == profRnd);

  std::printf("differential profile invariant under affine wrap : %s\n",
              affineSame ? "yes" : "no");
  std::printf("differential profile invariant under random wrap : %s\n",
              randomSame ? "yes" : "no");
  std::printf("=> affine module encodings are identifiable from the table alone: %s\n",
              (affineSame && !randomSame) ? "yes" : "no");

  if (out) {
    FILE *fh = std::fopen(out, "w");
    if (fh) {
      std::fprintf(fh,
                   "{\n  \"experiment\": \"affine-ddt-invariance\",\n"
                   "  \"w\": 8,\n  \"ddt_profile_invariant_affine\": %s,\n"
                   "  \"ddt_profile_invariant_random\": %s,\n"
                   "  \"affine_identifiable_from_table\": %s,\n"
                   "  \"note\": \"affine maps act linearly on differences, so the "
                   "difference profile survives; a random per-lane bijection does "
                   "not preserve it\"\n}\n",
                   affineSame ? "true" : "false", randomSame ? "true" : "false",
                   (affineSame && !randomSame) ? "true" : "false");
      std::fclose(fh);
    }
  }
  return (affineSame && !randomSame) ? 0 : 1;
}
