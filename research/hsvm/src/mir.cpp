#include "hsvm/mir.h"

namespace hsvm {

namespace {
constexpr uint32_t kBytes = kInstrBytes;
}

bool lift(const std::vector<uint8_t> &code, std::vector<MirOp> *out) {
  if (!out)
    return false;
  if (code.size() % kBytes != 0)
    return false;
  out->clear();
  out->reserve(code.size() / kBytes);
  for (size_t off = 0; off < code.size(); off += kBytes) {
    const uint8_t raw = code[off];
    if (raw >= kNumOpcodes)
      return false; // unknown opcode: refuse rather than guess
    MirOp op;
    op.op = static_cast<Opcode>(raw);
    op.dst = code[off + 1];
    op.a = code[off + 2];
    op.b = code[off + 3];
    op.imm = static_cast<uint32_t>(code[off + 4]) |
             (static_cast<uint32_t>(code[off + 5]) << 8) |
             (static_cast<uint32_t>(code[off + 6]) << 16) |
             (static_cast<uint32_t>(code[off + 7]) << 24);
    out->push_back(op);
  }
  return true;
}

std::vector<uint8_t> emit(const std::vector<MirOp> &ops) {
  std::vector<uint8_t> code;
  code.reserve(ops.size() * kBytes);
  for (const MirOp &op : ops) {
    code.push_back(static_cast<uint8_t>(op.op));
    code.push_back(op.dst);
    code.push_back(op.a);
    code.push_back(op.b);
    code.push_back(static_cast<uint8_t>(op.imm & 0xFF));
    code.push_back(static_cast<uint8_t>((op.imm >> 8) & 0xFF));
    code.push_back(static_cast<uint8_t>((op.imm >> 16) & 0xFF));
    code.push_back(static_cast<uint8_t>((op.imm >> 24) & 0xFF));
  }
  return code;
}

} // namespace hsvm
