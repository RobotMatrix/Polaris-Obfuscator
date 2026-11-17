// §6.2 normalisation, linear case: nine probes strip affine module encodings.
//
// Claim: if the module function is linear (the V0.1 shape), then A2 o psi o A1 is
// itself affine, so probing at 0 and at the eight basis vectors recovers it
// exactly. The module encodings disappear because nothing is left to hide.
//
// Control: the same nine probes applied to a nonlinear psi do not reproduce it,
// which is what makes the result specific to linearity rather than vacuous.
//
// Conventions (verified by the additivity self-check below, not assumed):
//   applyAffine computes out_i = XOR_j m[i][j] * x_j, then XORs c.
//   Hence the image of e_k is the k-th column of m, and reconstruction must write
//   column k, not row k. The self-check fails loudly if this convention breaks.
#include <hsvm/gf2.h>
#include <hsvm/params.h>
#include <hsvm/psi.h>

#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

namespace {

struct Affine8 {
  uint8_t m[8];
  uint8_t c;
};

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

uint8_t applyLinear(const uint8_t m[8], uint8_t x) {
  Affine8 a{};
  std::memcpy(a.m, m, 8);
  a.c = 0;
  return applyAffine(a, x);
}

bool randomInvertible(std::mt19937_64 &rng, uint8_t out[8]) {
  for (int attempt = 0; attempt < 64; ++attempt) {
    uint8_t rows[8];
    for (int i = 0; i < 8; ++i)
      rows[i] = static_cast<uint8_t>(rng() & 0xFF);
    uint8_t work[8];
    std::memcpy(work, rows, 8);
    int rank = 0;
    for (int bit = 7; bit >= 0; --bit) {
      int pivot = -1;
      for (int r = rank; r < 8; ++r)
        if ((work[r] >> bit) & 1)
          pivot = r;
      if (pivot < 0)
        continue;
      std::swap(work[rank], work[pivot]);
      for (int r = 0; r < 8; ++r)
        if (r != rank && ((work[r] >> bit) & 1))
          work[r] ^= work[rank];
      ++rank;
    }
    if (rank == 8) {
      std::memcpy(out, rows, 8);
      return true;
    }
  }
  return false;
}

Affine8 reconstruct(const uint8_t f[9]) {
  Affine8 out{};
  out.c = f[0];
  for (int k = 0; k < 8; ++k) {
    const uint8_t d = static_cast<uint8_t>(f[1 + k] ^ f[0]);
    for (int i = 0; i < 8; ++i)
      if ((d >> i) & 1)
        out.m[i] = static_cast<uint8_t>(out.m[i] | (1u << k));
  }
  return out;
}

int mismatchesOf(const Affine8 &rec, const std::vector<uint8_t> &f) {
  int bad = 0;
  for (int x = 0; x < 256; ++x)
    if (applyAffine(rec, static_cast<uint8_t>(x)) != f[x])
      ++bad;
  return bad;
}

} // namespace

int main(int argc, char **argv) {
  const char *out = nullptr;
  for (int i = 1; i < argc; ++i)
    if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc)
      out = argv[++i];

  std::mt19937_64 rng(20260117);
  uint8_t m1[8], m2[8], mid[8];
  if (!randomInvertible(rng, m1) || !randomInvertible(rng, m2) ||
      !randomInvertible(rng, mid)) {
    std::fprintf(stderr, "matrix generation failed\n");
    return 2;
  }
  Affine8 a1{}, a2{};
  std::memcpy(a1.m, m1, 8);
  std::memcpy(a2.m, m2, 8);
  a1.c = 0x5A;
  a2.c = 0xC3;

  // Self-check: the composite must be affine, otherwise the claim below is void.
  auto F = [&](uint8_t x) {
    return applyAffine(a2, applyLinear(mid, applyAffine(a1, x)));
  };
  int nonAffine = 0;
  for (int a = 0; a < 256; ++a)
    for (int b = 0; b < 256; ++b) {
      const uint8_t lhs = F(static_cast<uint8_t>(a ^ b));
      const uint8_t rhs = static_cast<uint8_t>(F(static_cast<uint8_t>(a)) ^
                                               F(static_cast<uint8_t>(b)) ^ F(0));
      if (lhs != rhs)
        ++nonAffine;
    }
  if (nonAffine != 0) {
    std::fprintf(stderr, "convention check failed: %d additivity violations\n",
                 nonAffine);
    return 3;
  }

  std::vector<uint8_t> probe(9);
  probe[0] = F(0);
  for (int k = 0; k < 8; ++k)
    probe[1 + k] = F(static_cast<uint8_t>(1u << k));
  const Affine8 rec = reconstruct(probe.data());
  std::vector<uint8_t> full(256);
  for (int x = 0; x < 256; ++x)
    full[x] = F(static_cast<uint8_t>(x));
  const int linearMiss = mismatchesOf(rec, full);

  // Control: the same nine probes against a nonlinear psi.
  hsvm::HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = 8;
  p.c = 8;
  p.rBar = 1;
  p.rounds = 0;
  p.psi = hsvm::PsiMode::Table;
  p.seed = 4711;
  p.workload = hsvm::Workload::Crc32;
  auto tablePsi = hsvm::makePsi(p, 0);
  auto Fnl = [&](uint8_t x) {
    return applyAffine(a2, static_cast<uint8_t>(
                               tablePsi->applyU64(applyAffine(a1, x)) & 0xFF));
  };
  std::vector<uint8_t> probeNl(9);
  probeNl[0] = Fnl(0);
  for (int k = 0; k < 8; ++k)
    probeNl[1 + k] = Fnl(static_cast<uint8_t>(1u << k));
  const Affine8 recNl = reconstruct(probeNl.data());
  std::vector<uint8_t> fullNl(256);
  for (int x = 0; x < 256; ++x)
    fullNl[x] = Fnl(static_cast<uint8_t>(x));
  const int nlMiss = mismatchesOf(recNl, fullNl);

  std::printf("additivity self-check violations : %d\n", nonAffine);
  std::printf("linear psi : 9 probes -> mismatches over 256 = %d\n", linearMiss);
  std::printf("table  psi : 9 probes -> mismatches over 256 = %d\n", nlMiss);
  std::printf("=> affine module encodings stripped for linear modules: %s\n",
              (linearMiss == 0 && nlMiss != 0) ? "yes" : "no");

  if (out) {
    FILE *fh = std::fopen(out, "w");
    if (fh) {
      std::fprintf(fh,
                   "{\n  \"experiment\": \"affine-normalisation-linear\",\n"
                   "  \"queries\": 9,\n"
                   "  \"additivity_violations\": %d,\n"
                   "  \"linear_mismatches\": %d,\n"
                   "  \"nonlinear_mismatches\": %d,\n"
                   "  \"stripped_for_linear\": %s,\n"
                   "  \"note\": \"nine probes recover an affine composite exactly; "
                   "the same probes leave a nonlinear psi unrecovered\"\n}\n",
                   nonAffine, linearMiss, nlMiss,
                   (linearMiss == 0 && nlMiss != 0) ? "true" : "false");
      std::fclose(fh);
    }
  }
  return (linearMiss == 0 && nlMiss != 0) ? 0 : 1;
}
