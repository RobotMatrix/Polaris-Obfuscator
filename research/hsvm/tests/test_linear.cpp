//===- test_linear.cpp - linear ablation properties ------------------------===//
//
// Stage 0's claim is that F(s,i) = s ^ v(i) leaves the hidden state redundant.
// The tests below pin that down mechanically:
//   * every step is exactly one XOR of the per-slot mask;
//   * the observable projection never depends on memory/input contents;
//   * masks differ per slot (otherwise the trace diff would be ambiguous).
//
//===----------------------------------------------------------------------===//
#include "hsvm/machine.h"
#include "hsvm/programs.h"
#include "test_harness.h"

#include <set>
#include <string>
#include <vector>

using namespace hsvm;

namespace {

HsvmParams mkParams(uint64_t seed) {
  HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = 8;
  p.c = 8;
  p.rBar = 2;
  p.rounds = 0;
  p.psi = PsiMode::Table;
  p.seed = seed;
  p.workload = Workload::Crc32;
  return p;
}

std::vector<std::string> runTrajectory(uint64_t seed, uint8_t memByte) {
  Machine vm(mkParams(seed), VmMode::Linear);
  vm.loadProgram(programAllOps());
  vm.fillRegs(0x12345678u);
  std::vector<uint8_t> mem(Machine::kMemBytes, memByte);
  vm.writeMem(0, mem.data(), static_cast<uint32_t>(mem.size()));
  vm.run(1000);

  std::vector<std::string> out;
  for (const auto &rec : vm.trace())
    out.push_back(toHex(rec.xBefore) + toHex(rec.xAfter));
  return out;
}

void testStepIsOneXor() {
  Machine vm(mkParams(4242), VmMode::Linear);
  vm.loadProgram(programAllOps());
  vm.fillRegs(0xA5A5A5A5u);
  vm.run(1000);

  CHECK(vm.halted(), "allops halts");
  CHECK(vm.steps() == kNumOpcodes, "allops executes one step per opcode");
  CHECK(vm.trace().size() == kNumOpcodes, "one trace record per step");
  CHECK(vm.vTable().size() == kNumOpcodes, "one mask per instruction slot");

  bool xorOk = true;
  for (const auto &rec : vm.trace()) {
    if (rec.pc >= vm.vTable().size()) {
      xorOk = false;
      continue;
    }
    BitVector expected = rec.xBefore;
    expected.xorWith(matVec(vm.projection(), vm.vTable()[rec.pc]));
    if (expected != rec.xAfter)
      xorOk = false;
  }
  CHECK(xorOk, "x_after == x_before ^ H*v(i) for every step");
}

void testMasksDistinct() {
  Machine vm(mkParams(4242), VmMode::Linear);
  vm.loadProgram(programAllOps());
  std::set<std::string> masks;
  for (const auto &mask : vm.vTable())
    masks.insert(toHex(mask));
  CHECK(masks.size() == vm.vTable().size(), "masks are distinct per slot");
}

void testInputIndependence() {
  // Memory contents are input. In linear mode they cannot influence the state
  // trajectory at all: that is the zero-protection property stage 0 records.
  const auto a = runTrajectory(99, 0x00);
  const auto b = runTrajectory(99, 0xFF);
  CHECK(a.size() == b.size() && !a.empty(), "both runs produced traces");
  CHECK(a == b, "different memory inputs give identical x trajectories");

  Machine vm1(mkParams(99), VmMode::Linear);
  Machine vm2(mkParams(99), VmMode::Linear);
  vm1.loadProgram(programAllOps());
  vm2.loadProgram(programAllOps());
  vm1.fillRegs(0x12345678u);
  vm2.fillRegs(0x12345678u);
  std::vector<uint8_t> m1(Machine::kMemBytes, 0x11);
  std::vector<uint8_t> m2(Machine::kMemBytes, 0x22);
  vm1.writeMem(0, m1.data(), static_cast<uint32_t>(m1.size()));
  vm2.writeMem(0, m2.data(), static_cast<uint32_t>(m2.size()));
  vm1.run(100);
  vm2.run(100);
  bool same = true;
  for (uint32_t i = 0; i < vm1.regCount(); ++i)
    if (vm1.reg(i) != vm2.reg(i))
      same = false;
  CHECK(same, "final register file is independent of memory input");
}

void testStateDump() {
  Machine vm(mkParams(7), VmMode::Linear);
  vm.loadProgram(programAllOps());
  vm.fillRegs(1);
  vm.setStateDumpEnabled(true);
  vm.run(100);
  CHECK(vm.stateDump().size() == vm.steps() + 1,
        "state dump has one record per boundary");
  bool diffOk = true;
  for (uint32_t t = 0; t + 1 < vm.stateDump().size(); ++t) {
    BitVector delta = vm.stateDump()[t];
    delta.xorWith(vm.stateDump()[t + 1]);
    const uint32_t pc = vm.trace()[t].pc;
    if (delta != vm.vTable()[pc])
      diffOk = false;
  }
  CHECK(diffOk, "adjacent states differ by exactly the slot mask (A2 premise)");
}

} // namespace

int main() {
  testStepIsOneXor();
  testMasksDistinct();
  testInputIndependence();
  testStateDump();
  return hsvm_test::summary("linear");
}
