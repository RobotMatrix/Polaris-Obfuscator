// G0v2 cost floor (protocol v2.0): how cheap can one hidden-state step possibly
// be, before any C2 encoding is written?
//
// Two independent estimates are produced for every thin grid point:
//   * analytic: count the word/bit operations the construction forces, multiply
//     by the measured cost of one dependent operation on this host;
//   * measured: time each component in isolation (window read, scatter, state
//     mask xor, psi, dispatch) and sum them -- i.e. a perfectly fused kernel.
// The larger of the two is the floor. Summing isolated components is optimistic
// (a real kernel cannot fuse them for free), so a passing floor here is a
// necessary but not sufficient condition.
#include <hsvm/params.h>
#include <hsvm/psi.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace {

using clock_type = std::chrono::steady_clock;

volatile uint64_t g_sink = 0;

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline)) void dispatchStub(uint64_t v) { g_sink ^= v; }
#else
__attribute__((noinline)) void dispatchStub(uint64_t v) { g_sink ^= v; }
#endif

double peakOpsPerNs() {
  // Eight independent chains: this measures throughput, not dependency latency.
  const uint64_t n = 4000000;
  uint64_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  const auto t0 = clock_type::now();
  for (uint64_t i = 0; i < n; ++i) {
    for (int k = 0; k < 8; ++k)
      a[k] = (a[k] << 5) ^ (a[k] >> 2) ^ i;
  }
  const auto t1 = clock_type::now();
  for (int k = 0; k < 8; ++k)
    g_sink ^= a[k];
  const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
  return (8.0 * n * 3.0) / ns; // three ALU ops per iteration per chain
}

struct Point {
  uint32_t w = 8, c = 8, rbar = 1, rounds = 0;
  hsvm::PsiMode mode = hsvm::PsiMode::Table;
};

struct Floor {
  double windowNs = 0, scatterNs = 0, maskNs = 0, psiNs = 0, dispatchNs = 0;
  double sumNs = 0, analyticOps = 0, analyticNs = 0, floorNs = 0, ratio = 0;
  uint32_t psiOps = 0;
};

Floor measure(const Point &p, double peakOps, uint32_t n, uint32_t seed) {
  std::mt19937_64 rng(seed);
  const uint32_t nw = (n + 63) / 64;
  std::vector<uint64_t> words(nw, 0x0123456789ABCDEFULL);
  std::vector<uint64_t> mask(nw, 0xFEDCBA9876543210ULL);

  // Window positions: distinct bit indices of the state.
  std::vector<uint32_t> winPos(p.w);
  {
    std::vector<uint32_t> all(n);
    for (uint32_t i = 0; i < n; ++i)
      all[i] = i;
    for (uint32_t k = 0; k < p.w; ++k) {
      std::uniform_int_distribution<uint32_t> d(k, n - 1);
      std::swap(all[k], all[d(rng)]);
      winPos[k] = all[k];
    }
  }
  // Scatter positions: c * r_bar random bit positions, grouped by column.
  const uint32_t nFlips = p.c * p.rbar;
  std::vector<uint32_t> scat(nFlips);
  for (uint32_t k = 0; k < nFlips; ++k)
    scat[k] = static_cast<uint32_t>(rng() % n);

  hsvm::HsvmParams pr;
  pr.n = n;
  pr.m = 256;
  pr.w = p.w;
  pr.c = p.c;
  pr.rBar = p.rbar;
  pr.rounds = p.rounds;
  pr.psi = p.mode;
  pr.seed = seed;
  pr.workload = hsvm::Workload::Crc32;
  const std::string err = hsvm::validate(pr);
  if (!err.empty()) {
    std::fprintf(stderr, "invalid point: %s\n", err.c_str());
    std::exit(2);
  }
  auto psi = hsvm::makePsi(pr, 0);

  Floor f;
  auto timeIt = [&](auto &&body, uint64_t iters) {
    const auto t0 = clock_type::now();
    for (uint64_t i = 0; i < iters; ++i)
      body(i);
    const auto t1 = clock_type::now();
    return std::chrono::duration<double, std::nano>(t1 - t0).count() / iters;
  };

  // 1. window read
  f.windowNs = timeIt(
      [&](uint64_t) {
        uint64_t win = 0;
        for (uint32_t k = 0; k < p.w; ++k) {
          const uint32_t pos = winPos[k];
          win |= ((words[pos >> 6] >> (pos & 63)) & 1ULL) << k;
        }
        g_sink ^= win;
      },
      2000000);

  // 2. scatter (c * r_bar bit flips into the state words)
  f.scatterNs = timeIt(
      [&](uint64_t i) {
        for (uint32_t k = 0; k < nFlips; ++k) {
          const uint32_t pos = scat[(k + i) % nFlips];
          words[pos >> 6] ^= (1ULL << (pos & 63));
        }
      },
      500000);

  // 3. state mask xor (v(i) over all n bits)
  f.maskNs = timeIt(
      [&](uint64_t i) {
        const uint32_t off = static_cast<uint32_t>(i & 7);
        for (uint32_t k = 0; k < nw; ++k)
          words[k] ^= mask[(k + off) % nw];
      },
      1000000);

  // 4. psi
  f.psiNs = timeIt(
      [&](uint64_t i) {
        const uint64_t x = (i * 0x9E3779B97F4A7C15ULL) & ((p.w == 64) ? ~0ULL : ((1ULL << p.w) - 1));
        g_sink ^= psi->applyU64(x);
      },
      200000);

  // 5. dispatch (call overhead a kernel pays per step)
  f.dispatchNs = timeIt([&](uint64_t i) { dispatchStub(i); }, 5000000);

  // Analytic model: 3 ops per extracted window bit, 3 per flipped bit,
  // 1 per state word, psi cost from its round count, 4 ops of dispatch.
  f.psiOps = (p.mode == hsvm::PsiMode::Table)
                 ? 4
                 : (p.mode == hsvm::PsiMode::Arx ? 4 * p.rounds + 2
                                                : 4 * p.rounds + 8);
  f.analyticOps = 3.0 * p.w + 3.0 * nFlips + nw + f.psiOps + 4.0;
  f.analyticNs = f.analyticOps / peakOps;
  f.sumNs = f.windowNs + f.scatterNs + f.maskNs + f.psiNs + f.dispatchNs;
  f.floorNs = f.sumNs > f.analyticNs ? f.sumNs : f.analyticNs;
  return f;
}

} // namespace

int main(int argc, char **argv) {
  const char *out = nullptr;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc)
      out = argv[++i];
  }

  const double peakOps = peakOpsPerNs();
  std::printf("peak throughput: %.2f ALU ops/ns\n", peakOps);
  std::printf("%-22s %8s %8s %8s %8s %8s %9s %9s %6s\n", "point", "win", "scat",
              "mask", "psi", "disp", "sum_ns", "floor_ns", "ratio");

  std::vector<Point> pts;
  for (uint32_t w : {8u, 16u, 32u}) {
    for (uint32_t c : {8u, 16u}) {
      for (uint32_t rb : {1u, 2u}) {
        if (w <= 16)
          pts.push_back({w, c, rb, 0, hsvm::PsiMode::Table});
        if (w >= 16)
          pts.push_back({w, c, rb, 4, hsvm::PsiMode::Arx});
      }
    }
  }

  FILE *fh = out ? std::fopen(out, "w") : nullptr;
  if (fh)
    std::fprintf(fh, "{\n  \"peak_ops_per_ns\": %.4f,\n  \"baseline_ns\": 4.2,\n  \"cap_ratio\": 3.0,\n  \"points\": [\n",
                 peakOps);

  double best = 1e9;
  std::string bestName;
  bool first = true;
  for (const Point &p : pts) {
    const Floor f = measure(p, peakOps, 512, 12345);
    const double ratio = f.floorNs / 4.2;
    char name[64];
    std::snprintf(name, sizeof(name), "w%u_c%u_r%u_%s_%u", p.w, p.c, p.rbar,
                  hsvm::toString(p.mode), p.rounds);
    std::printf("%-22s %8.2f %8.2f %8.2f %8.2f %8.2f %9.2f %9.2f %6.2f\n",
                name, f.windowNs, f.scatterNs, f.maskNs, f.psiNs,
                f.dispatchNs, f.sumNs, f.floorNs, ratio);
    if (fh) {
      std::fprintf(fh,
                   "%s    {\"point\": \"%s\", \"w\": %u, \"c\": %u, \"r_bar\": %u, "
                   "\"rounds\": %u, \"psi\": \"%s\", \"window_ns\": %.3f, "
                   "\"scatter_ns\": %.3f, \"mask_ns\": %.3f, \"psi_ns\": %.3f, "
                   "\"dispatch_ns\": %.3f, \"sum_ns\": %.3f, \"analytic_ops\": %.1f, "
                   "\"analytic_ns\": %.3f, \"floor_ns\": %.3f, \"ratio\": %.3f}",
                   first ? "" : ",\n", name, p.w, p.c, p.rbar, p.rounds,
                   hsvm::toString(p.mode), f.windowNs, f.scatterNs, f.maskNs,
                   f.psiNs, f.dispatchNs, f.sumNs, f.analyticOps, f.analyticNs,
                   f.floorNs, ratio);
      first = false;
    }
    if (f.floorNs < best) {
      best = f.floorNs;
      bestName = name;
    }
  }

  if (fh) {
    std::fprintf(fh, "\n  ],\n  \"best_point\": \"%s\",\n  \"best_floor_ns\": %.3f,\n"
                     "  \"best_ratio\": %.3f\n}\n",
                 bestName.c_str(), best, best / 4.2);
    std::fclose(fh);
  }
  std::printf("\nbest: %s floor=%.2f ns ratio=%.2f\n", bestName.c_str(), best,
              best / 4.2);
  return 0;
}
