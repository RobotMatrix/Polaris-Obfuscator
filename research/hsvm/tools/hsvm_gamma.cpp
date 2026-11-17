//===- hsvm_gamma.cpp - measure Gamma, affine structure and step cost -----===//
//
// One parameter point per invocation. Prints one JSON object and optionally
// writes it to --out. The numbers are the stage-1 model-layer evidence:
//
//   gamma_p5 / gamma_median / gamma_min   coverage per instruction type
//   affine_nonaffine / affine_exhaustive  whether D is affine on pi_A(K)
//   step_cost_ratio                       model step vs plain VM instruction
//
// Reachable states are a proxy: a random walk over the model, not real program
// traces (which arrive with the compiler pass at M3). The proxy is recorded in
// the report so the two cannot be confused.
//
//===----------------------------------------------------------------------===//
#include "hsvm/machine.h"
#include "hsvm/model.h"
#include "hsvm/params.h"
#include "hsvm/programs.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Args {
  uint32_t n = 512, m = 256, w = 8, c = 8, rbar = 2, rounds = 0;
  std::string psi = "table";
  uint64_t seed = 12345;
  uint32_t states = 256, dirs = 4;
  std::string affine = "exhaustive"; // exhaustive | sampled | none
  bool bench = false;
  std::string out;
};

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

bool parse(int argc, char **argv, Args &a) {
  for (int i = 1; i < argc; ++i) {
    const std::string k = argv[i];
    const char *v = (i + 1 < argc) ? argv[i + 1] : nullptr;
    uint64_t t = 0;
    if (k == "--n" && v) {
      if (!parseU64(v, t)) return false;
      a.n = static_cast<uint32_t>(t), ++i;
    } else if (k == "--m" && v) {
      if (!parseU64(v, t)) return false;
      a.m = static_cast<uint32_t>(t), ++i;
    } else if (k == "--w" && v) {
      if (!parseU64(v, t)) return false;
      a.w = static_cast<uint32_t>(t), ++i;
    } else if (k == "--c" && v) {
      if (!parseU64(v, t)) return false;
      a.c = static_cast<uint32_t>(t), ++i;
    } else if (k == "--rbar" && v) {
      if (!parseU64(v, t)) return false;
      a.rbar = static_cast<uint32_t>(t), ++i;
    } else if (k == "--rounds" && v) {
      if (!parseU64(v, t)) return false;
      a.rounds = static_cast<uint32_t>(t), ++i;
    } else if (k == "--seed" && v) {
      if (!parseU64(v, a.seed)) return false;
      ++i;
    } else if (k == "--states" && v) {
      if (!parseU64(v, t)) return false;
      a.states = static_cast<uint32_t>(t), ++i;
    } else if (k == "--dirs" && v) {
      if (!parseU64(v, t)) return false;
      a.dirs = static_cast<uint32_t>(t), ++i;
    } else if (k == "--psi" && v) {
      a.psi = v, ++i;
    } else if (k == "--affine" && v) {
      a.affine = v, ++i;
    } else if (k == "--bench") {
      a.bench = true;
    } else if (k == "--out" && v) {
      a.out = v, ++i;
    } else {
      return false;
    }
  }
  return true;
}

double percentile(std::vector<double> v, double pct) {
  if (v.empty())
    return 0.0;
  std::sort(v.begin(), v.end());
  if (v.size() == 1)
    return v[0];
  const double pos = (v.size() - 1) * pct / 100.0;
  const size_t lo = static_cast<size_t>(std::floor(pos));
  const size_t hi = static_cast<size_t>(std::ceil(pos));
  if (lo == hi)
    return v[lo];
  const double frac = pos - static_cast<double>(lo);
  return v[lo] * (1 - frac) + v[hi] * frac;
}

} // namespace

int main(int argc, char **argv) {
  Args a;
  if (!parse(argc, argv, a)) {
    std::fprintf(stderr,
                 "usage: hsvm_gamma --n 512 --m 256 --w 8 --c 8 --rbar 2 "
                 "--rounds 0 --psi table|spn --seed S [--states 256] "
                 "[--dirs 4] [--affine exhaustive|sampled|none] [--bench] "
                 "[--out PATH]\n");
    return 3;
  }

  hsvm::HsvmParams p;
  p.n = a.n;
  p.m = a.m;
  p.w = a.w;
  p.c = a.c;
  p.rBar = a.rbar;
  p.rounds = a.rounds;
  p.psi = a.psi == "spn" ? hsvm::PsiMode::Spn
          : a.psi == "arx" ? hsvm::PsiMode::Arx
                           : hsvm::PsiMode::Table;
  p.seed = a.seed;
  p.workload = hsvm::Workload::Crc32;
  if (!hsvm::validate(p).empty()) {
    std::fprintf(stderr, "hsvm_gamma: %s\n", hsvm::validate(p).c_str());
    return 2;
  }

  hsvm::NonlinearModel model(p);
  hsvm::Rng rng(p.seed ^ 0x5DEECE66DULL);

  // Reachable-state proxy: random walk over the model.
  std::vector<hsvm::BitVector> states;
  states.reserve(a.states);
  hsvm::BitVector s = hsvm::BitVector::random(p.n, rng);
  for (uint32_t t = 0; t < a.states * 4; ++t) {
    if (t % 4 == 0 && states.size() < a.states)
      states.push_back(s);
    s = model.step(s, static_cast<uint32_t>(rng() % model.instructionCount()));
  }

  std::vector<double> gammas;
  std::vector<hsvm::GammaResult> results;
  results.reserve(model.instructionCount());
  for (uint32_t i = 0; i < model.instructionCount(); ++i) {
    const hsvm::GammaResult g = model.gamma(i, states, a.dirs, rng);
    results.push_back(g);
    gammas.push_back(g.gamma);
  }

  uint32_t nonAffine = 0, exhaustive = 0;
  uint64_t checks = 0;
  struct AffineRow {
    uint32_t instr;
    bool affine;
    bool exhaustive;
    uint32_t dim;
    uint64_t checked;
  };
  std::vector<AffineRow> affineRows;
  if (a.affine != "none") {
    const bool allowExhaustive = a.affine == "exhaustive";
    for (uint32_t i = 0; i < model.instructionCount(); ++i) {
      const hsvm::BitVector st = states[i % states.size()];
      const hsvm::AffineResult r =
          model.affineTest(i, st, rng, allowExhaustive);
      if (!r.affine)
        ++nonAffine;
      if (r.exhaustive)
        ++exhaustive;
      checks += r.checked;
      affineRows.push_back({i, r.affine, r.exhaustive, r.dim, r.checked});
    }
  }

  double benchModelNs = 0, benchPlainNs = 0, ratio = 0;
  if (a.bench) {
    using clock = std::chrono::steady_clock;
    const uint32_t steps = 100000;
    hsvm::BitVector st = hsvm::BitVector::random(p.n, rng);
    std::vector<uint64_t> words((p.n + 63) / 64);
    for (uint32_t w = 0; w < words.size(); ++w)
      words[w] = st.word(w);

    auto t0 = clock::now();
    uint32_t idx = 0;
    const uint32_t ninstr = model.instructionCount();
    for (uint32_t t = 0; t < steps; ++t) {
      model.stepWords(words.data(), idx);
      if (++idx == ninstr)
        idx = 0; // avoid a per-iteration integer division
    }
    auto t1 = clock::now();
    benchModelNs =
        std::chrono::duration<double, std::nano>(t1 - t0).count() / steps;

    hsvm::Machine vm(p, hsvm::VmMode::Plain);
    vm.loadProgram(hsvm::programSum());
    vm.setTraceEnabled(false);
    vm.setReg(0, 100000);
    auto t2 = clock::now();
    const uint64_t executed = vm.run(10000000);
    auto t3 = clock::now();
    const double totalNs =
        std::chrono::duration<double, std::nano>(t3 - t2).count();
    benchPlainNs = executed ? totalNs / static_cast<double>(executed) : 0.0;
    ratio = benchPlainNs > 0 ? benchModelNs / benchPlainNs : 0.0;
  }

  FILE *fp = a.out.empty() ? stdout : std::fopen(a.out.c_str(), "w");
  if (!fp) {
    std::fprintf(stderr, "hsvm_gamma: cannot write %s\n", a.out.c_str());
    return 3;
  }

  std::fprintf(fp, "{\n  \"params_hash\": \"%s\",\n",
               hsvm::paramsHash(p).c_str());
  std::fprintf(fp, "  \"n\": %u, \"m\": %u, \"w\": %u, \"c\": %u, "
                   "\"r_bar\": %u, \"rounds\": %u, \"psi\": \"%s\",\n",
               p.n, p.m, p.w, p.c, p.rBar, p.rounds,
               p.psi == hsvm::PsiMode::Spn ? "spn" : "table");
  std::fprintf(fp, "  \"instructions\": %u, \"states\": %zu, \"dirs\": %u,\n",
               model.instructionCount(), states.size(), a.dirs);
  std::fprintf(fp,
               "  \"gamma_p5\": %.6f, \"gamma_median\": %.6f, "
               "\"gamma_min\": %.6f, \"gamma_max\": %.6f,\n",
               percentile(gammas, 5), percentile(gammas, 50),
               percentile(gammas, 0), percentile(gammas, 100));
  std::fprintf(fp, "  \"affine_nonaffine\": %u, \"affine_exhaustive\": %u, "
                   "\"affine_checks\": %llu,\n",
               nonAffine, exhaustive,
               static_cast<unsigned long long>(checks));
  std::fprintf(fp, "  \"bench_model_ns\": %.3f, \"bench_plain_ns\": %.3f, "
                   "\"step_cost_ratio\": %.4f,\n",
               benchModelNs, benchPlainNs, ratio);
  std::fprintf(fp, "  \"per_instruction\": [");
  for (size_t i = 0; i < results.size(); ++i) {
    std::fprintf(fp,
                 "%s{\"instr\":%u,\"gamma\":%.6f,\"ci_lo\":%.6f,"
                 "\"ci_hi\":%.6f,\"trials\":%llu}",
                 i ? "," : "", results[i].instr, results[i].gamma,
                 results[i].ciLo, results[i].ciHi,
                 static_cast<unsigned long long>(results[i].trials));
  }
  std::fprintf(fp, "],\n  \"affine\": [");
  for (size_t i = 0; i < affineRows.size(); ++i) {
    const auto &r = affineRows[i];
    std::fprintf(fp,
                 "%s{\"instr\":%u,\"affine\":%s,\"exhaustive\":%s,"
                 "\"dim\":%u,\"checked\":%llu}",
                 i ? "," : "", r.instr, r.affine ? "true" : "false",
                 r.exhaustive ? "true" : "false", r.dim,
                 static_cast<unsigned long long>(r.checked));
  }
  std::fprintf(fp, "]\n}\n");
  if (fp != stdout)
    std::fclose(fp);
  else
    std::fprintf(stderr, "\n");
  return 0;
}
