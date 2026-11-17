#include "hsvm/mir.h"
#include "hsvm/programs.h"
#include "test_harness.h"

using namespace hsvm;

// Slice 1 of stage 5: the lifter must be lossless and must refuse garbage.
int main() {
  // Every opcode round-trips with the same operand bytes.
  for (uint32_t k = 0; k < kNumOpcodes; ++k) {
    std::vector<uint8_t> code;
    const uint32_t imm = 0xA1B2C3D4u;
    code.push_back(static_cast<uint8_t>(k));
    code.push_back(0x11);
    code.push_back(0x22);
    code.push_back(0x33);
    for (int s = 0; s < 32; s += 8)
      code.push_back(static_cast<uint8_t>((imm >> s) & 0xFF));
    std::vector<MirOp> ops;
    CHECK(lift(code, &ops), "one instruction lifts");
    CHECK(ops.size() == 1, "one instruction yields one MirOp");
    CHECK(static_cast<uint32_t>(ops[0].op) == k, "opcode preserved");
    CHECK(ops[0].dst == 0x11 && ops[0].a == 0x22 && ops[0].b == 0x33,
          "register bytes preserved");
    CHECK(ops[0].imm == imm, "immediate decoded little-endian");
    CHECK(emit(ops) == code, "emit(lift(x)) == x");
  }

  // A whole program round-trips.
  const std::vector<uint8_t> prog = programAllOps();
  std::vector<MirOp> ops;
  CHECK(lift(prog, &ops), "allops lifts");
  CHECK(ops.size() == prog.size() / kInstrBytes, "instruction count matches");
  CHECK(emit(ops) == prog, "allops round-trips byte for byte");

  // Garbage is refused, not silently decoded.
  std::vector<MirOp> bad;
  CHECK(!lift({0x00, 0x01, 0x02}, &bad), "truncated input is refused");
  CHECK(!lift({0x11, 0, 0, 0, 0, 0, 0, 0}, &bad), "unknown opcode is refused");
  CHECK(bad.empty(), "refused input leaves no partial output");

  // High register indices survive: the ISA addresses 64 registers.
  std::vector<uint8_t> wide(8, 0);
  wide[0] = static_cast<uint8_t>(Opcode::Mov);
  wide[1] = 0x3F;
  wide[2] = 0x3F;
  std::vector<MirOp> wops;
  CHECK(lift(wide, &wops) && wops[0].dst == 0x3F && wops[0].a == 0x3F,
        "top register index preserved");

  return hsvm_test::summary("mir");
}
