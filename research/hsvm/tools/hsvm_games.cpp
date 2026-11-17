// G3/G4 games (doc §7.3), model layer.
//
// G3 — functional equivalence recovery: the attacker may query the window map
//      psi: F2^w -> F2^c a bounded number of times and must return an emulator
//      that agrees with it on >= 99% of held-out inputs.
// G4 — compact model extraction: the recovered object must fit in 4 KiB
//      (protocol: model_size_bound_bytes) and still answer held-out inputs.
//
// Both games run against the window map only, because that is the part of the
// step an attacker cannot recompute from public code (v(i), H and E are public).
// Queries are counted, and a game that ends without exhausting its budget is
// reported censored=true (ADR-004): then the only admissible statement is
// "no success within the used budget".
#include <hsvm/modenc.h>
#include <hsvm/params.h>
#include <hsvm/psi.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace {

struct GameResult {
  uint32_t w = 0, c = 0;
  uint64_t budget = 0;
  uint64_t queries = 0;
  bool censored = false;
  bool recovered = false;
  double agreement = 0.0;
  double compact_bytes = 0.0;
  bool fits_4k = false;
};

GameResult play(uint32_t w, uint64_t budget, double min_agreement,
                double model_bound) {
  GameResult r;
  r.w = w;
  r.c = w;
  r.budget = budget;

  hsvm::HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = w;
  p.c = w;
  p.rBar = 1;
  p.rounds = (w == 8) ? 0 : 4;
  p.psi = (w == 8) ? hsvm::PsiMode::Table : hsvm::PsiMode::Arx;
  p.seed = 777;
  p.workload = hsvm::Workload::Crc32;
  const std::string err = hsvm::validate(p);
  if (!err.empty()) {
    std::fprintf(stderr, "invalid point w=%u: %s\n", w, err.c_str());
    std::exit(2);
  }
  auto psi = hsvm::makePsi(p, 0);

  const uint64_t domain = 1ULL << w;
  const uint64_t cap = budget < domain ? budget : domain;

  // Attacker: fill an emulator from oracle queries.
  std::vector<uint64_t> emu;
  emu.reserve(static_cast<size_t>(cap));
  for (uint64_t x = 0; x < cap; ++x) {
    emu.push_back(psi->applyU64(x));
    ++r.queries;
  }
  r.censored = cap < domain;

  if (!r.censored) {
    // Complete table: measure agreement on held-out inputs drawn at random.
    std::mt19937_64 rng(12345);
    const int trials = 2000;
    int hit = 0;
    for (int i = 0; i < trials; ++i) {
      const uint64_t x = rng() & (domain - 1);
      if (emu[x] == psi->applyU64(x))
        ++hit;
    }
    r.agreement = static_cast<double>(hit) / trials;
    r.recovered = r.agreement >= min_agreement;
    // Table form: one uint64 per window value.
    r.compact_bytes = static_cast<double>(domain) * 8.0;
  } else {
    // Censored: no claim about agreement; the model is not complete either.
    r.agreement = 0.0;
    r.recovered = false;
    r.compact_bytes = static_cast<double>(domain) * 8.0;
  }
  r.fits_4k = r.compact_bytes <= model_bound;
  return r;
}

} // namespace

int main(int argc, char **argv) {
  const char *out = nullptr;
  double bound = 4096.0;
  double min_agreement = 0.99;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc)
      out = argv[++i];
    else if (std::strcmp(argv[i], "--model-bound") == 0 && i + 1 < argc)
      bound = std::strtod(argv[++i], nullptr);
    else if (std::strcmp(argv[i], "--min-agreement") == 0 && i + 1 < argc)
      min_agreement = std::strtod(argv[++i], nullptr);
  }

  std::printf("%3s %10s %10s %9s %9s %8s %10s %6s\n", "w", "budget",
              "queries", "censored", "recover", "agree", "bytes", "≤4K");

  FILE *fh = out ? std::fopen(out, "w") : nullptr;
  if (fh)
    std::fprintf(fh, "{\n  \"games\": [\n");

  bool first = true;
  for (uint32_t w : {8u, 16u, 24u}) {
    // budget 2^20: enough for w=8/16, not for w=24 (that is the point)
    const GameResult r = play(w, 1ULL << 20, min_agreement, bound);
    std::printf("%3u %10llu %10llu %9s %9s %8.3f %10.0f %6s\n", r.w,
                static_cast<unsigned long long>(r.budget),
                static_cast<unsigned long long>(r.queries),
                r.censored ? "yes" : "no", r.recovered ? "yes" : "no",
                r.agreement, r.compact_bytes, r.fits_4k ? "yes" : "no");
    if (fh) {
      std::fprintf(fh,
                   "%s    {\"w\": %u, \"c\": %u, \"budget\": %llu, "
                   "\"queries\": %llu, \"censored\": %s, \"recovered\": %s, "
                   "\"agreement\": %.3f, \"compact_bytes\": %.0f, "
                   "\"fits_model_bound\": %s, \"g3_pass\": %s, \"g4_pass\": %s}",
                   first ? "" : ",\n", r.w, r.c,
                   static_cast<unsigned long long>(r.budget),
                   static_cast<unsigned long long>(r.queries),
                   r.censored ? "true" : "false",
                   r.recovered ? "true" : "false", r.agreement, r.compact_bytes,
                   r.fits_4k ? "true" : "false",
                   (!r.censored && r.recovered) ? "true" : "false",
                   (!r.censored && r.recovered && r.fits_4k) ? "true" : "false");
      first = false;
    }
  }
  if (fh) {
    std::fprintf(fh, "\n  ],\n  \"model_bound_bytes\": %.0f,\n"
                     "  \"min_agreement\": %.3f,\n"
                     "  \"note\": \"censored games carry no success claim (ADR-004)\"\n}\n",
                 bound, min_agreement);
    std::fclose(fh);
  }
  return 0;
}
