//===- test_params.cpp - parameter validation tests ----------------------===//
#include "hsvm/params.h"
#include "test_harness.h"

#include <cstdio>
#include <string>

using namespace hsvm;

namespace {

HsvmParams tablePoint() {
  HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = 8;
  p.c = 8;
  p.rBar = 2;
  p.rounds = 0;
  p.psi = PsiMode::Table;
  p.seed = 12345;
  p.workload = Workload::Crc32;
  return p;
}

HsvmParams spnPoint() {
  HsvmParams p = tablePoint();
  p.w = 48;
  p.c = 16;
  p.rBar = 4;
  p.rounds = 4;
  p.psi = PsiMode::Spn;
  return p;
}

void testValidPoints() {
  CHECK(validate(tablePoint()).empty(), "table point is valid");
  CHECK(validate(spnPoint()).empty(), "spn point is valid");

  HsvmParams wide = spnPoint();
  wide.w = 64;
  wide.rounds = 8;
  CHECK(validate(wide).empty(), "w=64 spn point is valid");

  HsvmParams small = tablePoint();
  small.n = 8;
  small.m = 3;
  small.w = 8;
  small.c = 2;
  small.rBar = 2;
  CHECK(validate(small).empty(), "minimum-size point is valid");
}

void testRejections() {
  auto expectReject = [](HsvmParams p, const char *needle, const char *name) {
    const std::string r = validate(p);
    CHECK(!r.empty() && r.find(needle) != std::string::npos, name);
  };

  HsvmParams p = tablePoint();
  p.m = p.n;
  expectReject(p, "m must be < n", "m == n rejected");

  p = tablePoint();
  p.m = 0;
  expectReject(p, "m must be at least 1", "m == 0 rejected");

  p = tablePoint();
  p.w = p.n + 1;
  expectReject(p, "w must be <= n", "w > n rejected");

  p = tablePoint();
  p.c = p.n + 1;
  expectReject(p, "c must be <= n", "c > n rejected");

  p = tablePoint();
  p.rBar = 0;
  expectReject(p, "r_bar must be at least 1", "r_bar == 0 rejected");

  p = tablePoint();
  p.c = 300;
  p.rBar = 2; // 600 > 512
  expectReject(p, "c * r_bar must be <= n", "scatter overflow rejected");

  p = tablePoint();
  p.w = 32; // table mode cap is 16
  expectReject(p, "table mode requires w <= 16", "table w=32 rejected");

  p = tablePoint();
  p.rounds = 4;
  expectReject(p, "table mode requires rounds == 0",
               "table mode with rounds rejected");

  p = spnPoint();
  p.w = 12;
  expectReject(p, "multiple of 8", "spn w=12 rejected");

  p = spnPoint();
  p.rounds = 0;
  expectReject(p, "rounds >= 1", "spn rounds == 0 rejected");

  p = spnPoint();
  p.rounds = 17;
  expectReject(p, "rounds exceeds", "spn rounds > 16 rejected");

  p = tablePoint();
  p.seed = 0;
  expectReject(p, "seed must be nonzero", "seed == 0 rejected");

  p = tablePoint();
  p.n = 4;
  expectReject(p, "n must be at least 8", "n < 8 rejected");
}

void testDerivedValues() {
  HsvmParams p = tablePoint();
  CHECK(p.kernelDim() == 256, "kernelDim == n - m");
  CHECK(p.stateWords() == 8, "512 bits is 8 words");
  CHECK(p.scatterNonzeros() == 16, "scatter nonzeros == c * r_bar");
  CHECK(p.tableBytes() == 256, "w=8,c=8 table is 256 bytes");

  p.w = 16;
  p.c = 16;
  CHECK(p.tableBytes() == 131072, "w=16,c=16 table is 128 KiB");

  HsvmParams s = spnPoint();
  CHECK(s.tableBytes() == 0, "spn mode has no table");
}

void testHashAndJson() {
  const HsvmParams a = tablePoint();
  const HsvmParams b = tablePoint();
  CHECK(toCanonicalJson(a) == toCanonicalJson(b), "canonical JSON is stable");
  CHECK(paramsHash(a) == paramsHash(b), "params hash is stable");

  const std::string json = toCanonicalJson(a);
  CHECK(json.find("\"c\":8") != std::string::npos, "JSON has c field");
  CHECK(json.find("\"workload\":\"crc32\"") != std::string::npos,
        "workload is a string");
  CHECK(json.find(' ') == std::string::npos, "canonical JSON has no spaces");
  CHECK(paramsHash(a).size() == 16, "params hash is 16 hex chars");

  HsvmParams seedChanged = a;
  seedChanged.seed = a.seed + 1;
  CHECK(paramsHash(seedChanged) != paramsHash(a), "seed changes the hash");

  HsvmParams psiChanged = a;
  psiChanged.psi = PsiMode::Spn;
  psiChanged.w = 48;
  psiChanged.rounds = 4;
  CHECK(paramsHash(psiChanged) != paramsHash(a), "psi mode changes the hash");

  // Provenance must be separate from the parameter identity.
  CHECK(provenanceJson().find("git_commit") != std::string::npos,
        "provenance has git_commit");
  CHECK(provenanceJson().find("kernel_version") != std::string::npos,
        "provenance has kernel_version");
}

} // namespace

int main() {
  testValidPoints();
  testRejections();
  testDerivedValues();
  testHashAndJson();
  return hsvm_test::summary("params");
}
