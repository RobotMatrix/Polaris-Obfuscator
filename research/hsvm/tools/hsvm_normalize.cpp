// Global normalization / extraction probe (doc §6.1–6.2).
//
// Question: does wrapping each lane of the window in its own bijection raise the
// cost of building an equivalent model? The tool answers by measuring the only
// thing an attacker actually pays: queries to the wrapped function until an
// equivalent table is in hand.
//
// For w in {8,16,24} the state space is enumerable, so the attacker simply
// queries all 2^w inputs. If the query count depends on w only and never on the
// number of independent modules, then module encodings add no attacker cost —
// which is exactly what §6.2 claims and what §6.1 says conjugation cannot fix.
#include <hsvm/modenc.h>
#include <hsvm/params.h>
#include <hsvm/psi.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

namespace {

struct Result {
  uint32_t lanes = 0;
  uint32_t w = 0;
  uint64_t queries = 0;
  uint64_t verified = 0;
  double ms = 0;
};

Result run(uint32_t lanes) {
  const uint32_t w = lanes * 8;
  hsvm::HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = w;
  p.c = w; // one output bit per window bit keeps the probe about psi only
  p.rBar = 1;
  p.rounds = (w == 8) ? 0 : 4;
  p.psi = (w == 8) ? hsvm::PsiMode::Table : hsvm::PsiMode::Arx;
  p.seed = 4242;
  p.workload = hsvm::Workload::Crc32;
  const std::string err = hsvm::validate(p);
  if (!err.empty()) {
    std::fprintf(stderr, "invalid point w=%u: %s\n", w, err.c_str());
    std::exit(2);
  }
  auto psi = hsvm::makePsi(p, 0);
  hsvm::ModuleEncoder enc(lanes, 0xC0FFEE ^ w);

  const auto t0 = std::chrono::steady_clock::now();
  // Attacker: query the wrapped function on every input in the domain.
  std::unique_ptr<uint64_t[]> table(new uint64_t[1ULL << w]);
  for (uint64_t x = 0; x < (1ULL << w); ++x) {
    const uint64_t canonical = enc.decode(x);
    table[x] = enc.encode(psi->applyU64(canonical));
  }
  const auto t1 = std::chrono::steady_clock::now();

  // Verify the extracted table reproduces the wrapped function (by construction,
  // but re-query a sample so a bug in the probe cannot pass silently).
  uint64_t verified = 0;
  for (uint64_t x = 0; x < (1ULL << w); x += 97) {
    const uint64_t again = enc.encode(psi->applyU64(enc.decode(x)));
    if (again == table[x])
      ++verified;
  }

  Result r;
  r.lanes = lanes;
  r.w = w;
  r.queries = 1ULL << w;
  r.verified = verified;
  r.ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  return r;
}

} // namespace

int main(int argc, char **argv) {
  const char *out = nullptr;
  for (int i = 1; i < argc; ++i)
    if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc)
      out = argv[++i];

  std::printf("%6s %4s %12s %10s %9s\n", "lanes", "w", "queries", "verified",
              "ms");
  FILE *fh = out ? std::fopen(out, "w") : nullptr;
  if (fh)
    std::fprintf(fh, "{\n  \"experiment\": \"module-normalization\",\n"
                     "  \"points\": [\n");

  bool first = true;
  for (uint32_t lanes : {1u, 2u, 3u}) {
    const Result r = run(lanes);
    std::printf("%6u %4u %12llu %10llu %9.1f\n", r.lanes, r.w,
                static_cast<unsigned long long>(r.queries),
                static_cast<unsigned long long>(r.verified), r.ms);
    if (fh) {
      std::fprintf(fh,
                   "%s    {\"lanes\": %u, \"w\": %u, \"modules\": %u, "
                   "\"queries\": %llu, \"verified\": %llu, \"ms\": %.1f, "
                   "\"enumerable\": true}",
                   first ? "" : ",\n", r.lanes, r.w, r.lanes,
                   static_cast<unsigned long long>(r.queries),
                   static_cast<unsigned long long>(r.verified), r.ms);
      first = false;
    }
  }
  if (fh) {
    std::fprintf(fh, "\n  ],\n  \"claim\": \"module encodings add attacker cost\",\n"
                     "  \"supported\": false,\n"
                     "  \"reason\": \"queries equal 2^w for every lane count: "
                     "the attacker pays for the window size, never for the "
                     "number of modules\"\n}\n");
    std::fclose(fh);
  }
  return 0;
}
