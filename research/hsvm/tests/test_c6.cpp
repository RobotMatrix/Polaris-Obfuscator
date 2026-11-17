#include <hsvm/c6.h>

#include <hsvm/machine.h>
#include <hsvm/programs.h>

#include "test_harness.h"

using namespace hsvm;

namespace {

void testCleanSession() {
  IntegrityMonitor m(0x1234);
  m.checkpoint(EvidencePlane::ControlFlow, 7, 7);
  m.checkpoint(EvidencePlane::Memory, 11, 11);
  m.checkpoint(EvidencePlane::Timing, 13, 13);
  m.endEpoch(3);
  CHECK(m.state() == RiskState::Green, "clean session stays green");
  CHECK(m.mismatches() == 0, "clean session records no mismatch");
  CHECK(m.poisonMask() == 0, "green session does not poison output");
  CHECK(m.chain().verify(0x1234), "clean chain verifies with the instance key");
}

void testSinglePlaneTamper() {
  IntegrityMonitor m(0xABCDEF);
  m.checkpoint(EvidencePlane::ControlFlow, 7, 7);
  m.checkpoint(EvidencePlane::Memory, 11, 12); // memory plane edited
  m.checkpoint(EvidencePlane::Timing, 13, 13);
  m.endEpoch(3);
  CHECK(m.state() == RiskState::Red, "one plane mismatch raises red");
  CHECK(m.mismatches() == 1, "one mismatch counted");
  CHECK(m.poisonMask() != 0, "red session poisons output");
}

void testRepeatedTamperKills() {
  IntegrityMonitor m(1);
  for (int i = 0; i < 3; ++i)
    m.checkpoint(EvidencePlane::Memory, 1, 2);
  CHECK(m.state() == RiskState::Dead, "three mismatches reach dead");
  CHECK(m.poisonMask() != 0, "dead session poisons output");
}

void testSkippedPlane() {
  IntegrityMonitor m(2);
  m.checkpoint(EvidencePlane::ControlFlow, 1, 1);
  m.endEpoch(3); // only one of three planes reported
  CHECK(m.state() == RiskState::Yellow, "missing plane yields yellow");
  CHECK(m.missed() == 1, "missed plane counted");
}

void testForgeryWithoutKey() {
  IntegrityMonitor m(0x5EED);
  m.checkpoint(EvidencePlane::ControlFlow, 7, 7);
  m.checkpoint(EvidencePlane::Memory, 11, 11);

  // The attacker can read the tags and the algorithm, but not the instance key.
  EvidenceChain forged;
  forged.begin(0);
  forged.append(EvidencePlane::ControlFlow, 7, 7);
  forged.append(EvidencePlane::Memory, 11, 11);
  CHECK(!forged.verify(0x5EED), "chain rebuilt without the key does not verify");

  // A rebuilt chain is self-consistent, so the testable property here is that
  // order matters: the same checkpoints in another order give another digest,
  // so an attacker cannot slide one checkpoint past another.
  EvidenceChain in_order, reordered;
  in_order.begin(0x5EED);
  in_order.append(EvidencePlane::ControlFlow, 7, 7);
  in_order.append(EvidencePlane::Memory, 11, 11);
  reordered.begin(0x5EED);
  reordered.append(EvidencePlane::Memory, 11, 11);
  reordered.append(EvidencePlane::ControlFlow, 7, 7);
  CHECK(in_order.digest() != reordered.digest(),
        "checkpoint order changes the chain digest");
}

void testChainSensitivity() {
  EvidenceChain a, b;
  a.begin(9);
  b.begin(9);
  a.append(EvidencePlane::ControlFlow, 1, 1);
  a.append(EvidencePlane::Memory, 2, 2);
  b.append(EvidencePlane::ControlFlow, 1, 1);
  b.append(EvidencePlane::Memory, 2, 3); // one expected value differs
  CHECK(a.digest() != b.digest(), "one changed checkpoint changes the digest");
  // A chain is self-consistent by construction, so the testable property is
  // key binding: the same tags do not verify under another instance key.
  CHECK(a.verify(9) && b.verify(9), "each chain verifies with its own key");
  CHECK(!a.verify(10) && !b.verify(10),
        "chain does not verify under a different instance key");
}

void testPoisonIsDataOnly() {
  IntegrityMonitor clean(3), dirty(3);
  clean.checkpoint(EvidencePlane::Memory, 5, 5);
  dirty.checkpoint(EvidencePlane::Memory, 5, 6);
  // §12.4: the mask is data, so the same input with the same risk yields the
  // same poison — there is no per-step branch to observe.
  CHECK(clean.poisonMask() == 0 && dirty.poisonMask() != 0,
        "poison distinguishes clean from tampered without branching");
  const uint64_t m1 = dirty.poisonMask();
  const uint64_t m2 = dirty.poisonMask();
  CHECK(m1 == m2, "poison mask is stable for a fixed chain");
}

void testMachineIntegration() {
  HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = 8;
  p.c = 8;
  p.rBar = 2;
  p.rounds = 0;
  p.psi = PsiMode::Table;
  p.seed = 4242;
  p.workload = Workload::Crc32;

  Machine clean(p, VmMode::Linear);
  CHECK(clean.loadProgram(programAllOps()), "allops loads");
  clean.fillRegs(0x12345678);
  IntegrityMonitor m1(0xA1);
  clean.setIntegrityMonitor(&m1);
  clean.run();
  CHECK(m1.state() == RiskState::Green && m1.mismatches() == 0,
        "untampered run keeps the control-flow plane green");
  CHECK(m1.chain().size() > 0, "every step appended a checkpoint");

  Machine patched(p, VmMode::Linear);
  CHECK(patched.loadProgram(programAllOps()), "allops loads (second copy)");
  patched.fillRegs(0x12345678);
  CHECK(patched.patchInstructionByte(1, 4, 0x7F), "operand byte patched");
  IntegrityMonitor m2(0xA1);
  patched.setIntegrityMonitor(&m2);
  patched.run();
  CHECK(m2.state() != RiskState::Green,
        "patching an instruction trips the control-flow plane");
  CHECK(m2.poisonMask() != 0, "tampered run yields a poison mask");

  // Memory plane: the shadow copy follows writeMem, so a direct poke shows up.
  Machine mem(p, VmMode::Linear);
  CHECK(mem.loadProgram(programAllOps()), "allops loads (memory test)");
  mem.fillRegs(0x12345678);
  const uint8_t payload[4] = {0xDE, 0xAD, 0xBE, 0xEF};
  mem.writeMem(0x40, payload, 4);
  IntegrityMonitor m3(0xB2);
  mem.setIntegrityMonitor(&m3);
  mem.verifyMemoryPlane();
  CHECK(m3.state() == RiskState::Green,
        "memory written through writeMem keeps the plane green");

  mem.pokeMemory(0x41, 0x00); // bypasses writeMem
  mem.verifyMemoryPlane();
  CHECK(m3.state() == RiskState::Red,
        "a direct memory poke trips the memory plane");
}

} // namespace

int main() {
  testCleanSession();
  testSinglePlaneTamper();
  testRepeatedTamperKills();
  testSkippedPlane();
  testForgeryWithoutKey();
  testChainSensitivity();
  testPoisonIsDataOnly();
  testMachineIntegration();
  return hsvm_test::summary("c6");
}
