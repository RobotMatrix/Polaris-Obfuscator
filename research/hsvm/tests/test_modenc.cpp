#include <hsvm/modenc.h>

#include "test_harness.h"

#include <set>
#include <vector>

using namespace hsvm;

namespace {

void testRoundtrip() {
  for (uint32_t lanes = 1; lanes <= 4; ++lanes) {
    ModuleEncoder e(lanes, 77 + lanes);
    bool ok = true;
    for (uint64_t x = 0; x < (1ULL << (8 * lanes)); x += 13) {
      if (e.decode(e.encode(x)) != x)
        ok = false;
    }
    char name[64];
    std::snprintf(name, sizeof(name), "lanes=%u: decode(encode(x)) == x", lanes);
    CHECK(ok, name);
  }
}

void testPerLaneBijection() {
  ModuleEncoder e(2, 5);
  bool ok = true;
  for (uint64_t low = 0; low < 256; ++low) {
    std::set<uint64_t> seen;
    for (uint64_t hi = 0; hi < 256; ++hi)
      seen.insert(e.encode((hi << 8) | low));
    if (seen.size() != 256)
      ok = false;
  }
  CHECK(ok, "each lane maps 256 inputs onto 256 outputs");
}

void testLanesAreIndependent() {
  ModuleEncoder e(2, 9);
  // Changing the low lane must not disturb the high lane's byte.
  bool ok = true;
  for (uint64_t v = 0; v < 4096; v += 7) {
    const uint64_t a = e.encode(v);
    const uint64_t b = e.encode(v ^ 0x01ULL);
    if ((a >> 8) != (b >> 8))
      ok = false;
  }
  CHECK(ok, "encoding one lane leaves the other lanes untouched");
}

void testSeedSensitivity() {
  ModuleEncoder a(1, 1), b(1, 2);
  bool differs = false;
  for (uint64_t x = 0; x < 256; ++x)
    if (a.encode(x) != b.encode(x))
      differs = true;
  CHECK(differs, "different seeds give different per-lane bijections");
}

void testNonIdentity() {
  ModuleEncoder e(1, 3);
  size_t changed = 0;
  for (uint64_t x = 0; x < 256; ++x)
    if (e.encode(x) != x)
      ++changed;
  CHECK(changed > 200, "the encoding is not close to the identity");
}

} // namespace

int main() {
  testRoundtrip();
  testPerLaneBijection();
  testLanesAreIndependent();
  testSeedSensitivity();
  testNonIdentity();
  return hsvm_test::summary("modenc");
}
