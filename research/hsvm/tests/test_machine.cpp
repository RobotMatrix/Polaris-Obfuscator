//===- test_machine.cpp - plain-mode differential tests --------------------===//
//
// The interpreter is only trustworthy if it matches an independent native
// implementation on many inputs. Every case below compares a VM result against
// a hand-written reference that shares no code with the interpreter.
//
//===----------------------------------------------------------------------===//
#include "hsvm/machine.h"
#include "hsvm/programs.h"
#include "test_harness.h"

#include <cstring>
#include <vector>

using namespace hsvm;

namespace {

HsvmParams mkParams() {
  HsvmParams p;
  p.n = 512;
  p.m = 256;
  p.w = 8;
  p.c = 8;
  p.rBar = 2;
  p.rounds = 0;
  p.psi = PsiMode::Table;
  p.seed = 777;
  p.workload = Workload::Crc32;
  return p;
}

void testSum() {
  Rng rng(1001);
  bool ok = true;
  bool halted = true;
  for (int i = 0; i < 100; ++i) {
    const uint32_t n = (i == 0) ? 0 : (i == 1) ? 1 : (rng() % 500);
    Machine vm(mkParams(), VmMode::Plain);
    if (!vm.loadProgram(programSum()))
      ok = false;
    vm.setReg(0, n);
    vm.run(1000000);
    if (vm.faulted() || !vm.halted())
      halted = false;
    if (vm.reg(0) != nativeSum(n))
      ok = false;
  }
  CHECK(ok, "sum: 100 inputs match nativeSum");
  CHECK(halted, "sum: every run halts without faulting");
}

void testCrc() {
  Rng rng(2002);
  bool ok = true;
  for (int i = 0; i < 100; ++i) {
    const uint32_t len = 4 * (1 + (rng() % 16)); // 4..64 bytes
    std::vector<uint8_t> buf(len);
    fillDeterministic(buf.data(), len, rng());

    Machine vm(mkParams(), VmMode::Plain);
    vm.loadProgram(programCrc());
    vm.writeMem(0, buf.data(), len);
    vm.setReg(0, len);
    vm.run(1000000);
    if (vm.faulted() || !vm.halted() ||
        vm.reg(0) != nativeCrc(buf.data(), len))
      ok = false;
  }
  CHECK(ok, "crc: 100 inputs match nativeCrc");
}

void testCopyXor() {
  Rng rng(3003);
  bool ok = true;
  bool memoryOk = true;
  for (int i = 0; i < 100; ++i) {
    const uint32_t len = 4 * (1 + (rng() % 16));
    std::vector<uint8_t> src(len);
    std::vector<uint8_t> refDst(len, 0);
    fillDeterministic(src.data(), len, rng());

    Machine vm(mkParams(), VmMode::Plain);
    vm.loadProgram(programCopyXor());
    vm.writeMem(0, src.data(), len);
    vm.setReg(0, len);
    vm.run(1000000);

    const uint32_t ref = nativeCopyXor(refDst.data(), src.data(), len,
                                       kCopyXorKey);
    if (vm.faulted() || !vm.halted() || vm.reg(0) != ref)
      ok = false;
    for (uint32_t j = 0; j + 4 <= len; j += 4) {
      const uint32_t expect =
          static_cast<uint32_t>(refDst[j]) |
          (static_cast<uint32_t>(refDst[j + 1]) << 8) |
          (static_cast<uint32_t>(refDst[j + 2]) << 16) |
          (static_cast<uint32_t>(refDst[j + 3]) << 24);
      if (vm.readMem32(kCopyXorDst + j) != expect)
        memoryOk = false;
    }
  }
  CHECK(ok, "copy_xor: 100 inputs match nativeCopyXor");
  CHECK(memoryOk, "copy_xor: destination memory matches the native copy");
}

void testFaults() {
  {
    Machine vm(mkParams(), VmMode::Plain);
    Asm a;
    a.op(Opcode::Ld, 1, 0, 0, 0x1000); // address 0x1000 is out of range
    a.op(Opcode::Halt);
    vm.loadProgram(a.code());
    vm.run(100);
    CHECK(vm.faulted(), "out-of-range load faults");
  }
  {
    Machine vm(mkParams(), VmMode::Plain);
    std::vector<uint8_t> code(kInstrBytes, 0);
    code[0] = 0x7F; // unknown opcode
    vm.loadProgram(code);
    vm.run(100);
    CHECK(vm.faulted(), "unknown opcode faults");
  }
  {
    Machine vm(mkParams(), VmMode::Plain);
    Asm a;
    a.op(Opcode::Ld, 1, 0, 0, 2); // unaligned
    a.op(Opcode::Halt);
    vm.loadProgram(a.code());
    vm.run(100);
    CHECK(vm.faulted(), "unaligned load faults");
  }
  {
    Machine vm(mkParams(), VmMode::Plain);
    CHECK(!vm.loadProgram(std::vector<uint8_t>(7, 0)), "7-byte program rejected");
    CHECK(!vm.loadProgram({}), "empty program rejected");
  }
  {
    Machine vm(mkParams(), VmMode::Plain);
    vm.loadProgram(programSum());
    vm.setReg(0, 100000);
    vm.run(100); // step budget expires first
    CHECK(!vm.halted() && !vm.faulted(), "step budget stops without halting");
  }
}

} // namespace

int main() {
  testSum();
  testCrc();
  testCopyXor();
  testFaults();
  return hsvm_test::summary("machine");
}
