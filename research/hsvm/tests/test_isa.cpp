//===- test_isa.cpp - instruction encoding tests --------------------------===//
#include "hsvm/instr.h"
#include "test_harness.h"

#include <set>
#include <string>

using namespace hsvm;

int main() {
  std::set<uint8_t> values;
  int named = 0;
  for (uint32_t i = 0; i < kNumOpcodes; ++i) {
    const auto op = static_cast<Opcode>(i);
    values.insert(static_cast<uint8_t>(op));
    if (std::string(opcodeName(op)) != "?")
      ++named;
  }
  CHECK(values.size() == kNumOpcodes, "opcode values are unique");
  CHECK(named == static_cast<int>(kNumOpcodes), "every opcode has a name");

  bool roundtrip = true;
  for (uint32_t i = 0; i < kNumOpcodes; ++i) {
    for (int k = 0; k < 40; ++k) {
      Instr in;
      in.op = static_cast<uint8_t>(i);
      in.dst = static_cast<uint8_t>(k);
      in.a = static_cast<uint8_t>(k + 1);
      in.b = static_cast<uint8_t>(k + 2);
      in.imm = 0x12345678u ^ static_cast<uint32_t>(k);
      uint8_t bytes[kInstrBytes];
      encodeInstr(in, bytes);
      const Instr out = decodeInstr(bytes);
      if (out.op != in.op || out.dst != in.dst || out.a != in.a ||
          out.b != in.b || out.imm != in.imm)
        roundtrip = false;
    }
  }
  CHECK(roundtrip, "encode/decode roundtrip for every opcode");

  Instr jmp;
  jmp.op = static_cast<uint8_t>(Opcode::Jmp);
  jmp.imm = static_cast<uint32_t>(-3);
  CHECK(disassemble(jmp) == "jmp -3", "jmp disassembly shows a signed offset");

  Instr add;
  add.op = static_cast<uint8_t>(Opcode::Add);
  add.dst = 1, add.a = 2, add.b = 3;
  CHECK(disassemble(add) == "add r1, r2, r3", "add disassembly");

  Instr ld;
  ld.op = static_cast<uint8_t>(Opcode::Ld);
  ld.dst = 4, ld.a = 5, ld.imm = 8;
  CHECK(disassemble(ld) == "ld r4, [r5+0x8]", "ld disassembly");

  Asm asm_;
  asm_.op(Opcode::Movi, 1, 0, 0, 0x42);
  asm_.patch(0, 0x99);
  CHECK(decodeInstr(asm_.code().data()).imm == 0x99, "Asm::patch rewrites imm");

  return hsvm_test::summary("isa");
}
