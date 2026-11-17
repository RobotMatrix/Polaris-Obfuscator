//===- machine.cpp - HSV virtual machine ----------------------------------===//
#include "hsvm/machine.h"

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace hsvm {

namespace {

struct SplitMix {
  uint64_t s;
  explicit SplitMix(uint64_t seed) : s(seed) {}
  uint64_t next() {
    uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
};

} // namespace

std::string toHex(const BitVector &v) {
  static const char *digits = "0123456789abcdef";
  const uint32_t n = v.size();
  const uint32_t nibbles = (n + 3) / 4;
  std::string out;
  out.reserve(nibbles);
  // Most significant nibble first, so the string is the big-endian rendering
  // of the bit vector (bit n-1 is the first hex digit's MSB).
  for (int nib = static_cast<int>(nibbles) - 1; nib >= 0; --nib) {
    unsigned val = 0;
    for (uint32_t j = 0; j < 4; ++j) {
      const uint32_t bit = static_cast<uint32_t>(nib) * 4 + j;
      if (bit < n && v.get(bit))
        val |= (1u << j);
    }
    out.push_back(digits[val]);
  }
  return out;
}

Machine::Machine(const HsvmParams &p, VmMode mode) : p_(p), mode_(mode) {
  requireValid(p);
  if (p.n % 32 != 0)
    throw std::invalid_argument(
        "Machine: n must be a multiple of 32 (register file layout)");
  regCount_ = p.n / 32;
  if (regCount_ == 0 || regCount_ > kMaxRegs)
    throw std::invalid_argument("Machine: n/32 registers outside [1,16]");

  regs_.assign(regCount_, 0);
  mem_.assign(kMemBytes, 0);

  Rng rng(p.seed ^ 0xD1B54A32D192ED03ULL);
  H_ = BitMatrix::randomFullRowRank(p.m, p.n, rng);
  buildVTables();
}

void Machine::buildVTables() {
  v_.clear();
  if (mode_ != VmMode::Linear)
    return;
  const uint32_t slots = programSlots();
  v_.reserve(slots);
  for (uint32_t slot = 0; slot < slots; ++slot) {
    const Instr in = decodeInstr(code_.data() + slot * kInstrBytes);
    SplitMix sm(p_.seed ^ (0x9E3779B97F4A7C15ULL * (slot + 1)) ^
                (static_cast<uint64_t>(in.op) << 48) ^
                (static_cast<uint64_t>(in.dst) << 40) ^
                (static_cast<uint64_t>(in.a) << 32) ^
                (static_cast<uint64_t>(in.b) << 24) ^ in.imm);
    BitVector mask(p_.n);
    for (uint32_t w = 0; w < (p_.n + 63) / 64; ++w)
      mask.words()[w] = sm.next();
    // Mask the tail word through BitVector's own accessors by rebuilding it.
    BitVector clean(p_.n);
    for (uint32_t i = 0; i < p_.n; ++i)
      if (mask.get(i))
        clean.set(i, true);
    v_.push_back(std::move(clean));
  }
}

bool Machine::loadProgram(const std::vector<uint8_t> &code, std::string *err) {
  if (code.empty() || code.size() % kInstrBytes != 0) {
    if (err)
      *err = "program size must be a nonzero multiple of 8";
    return false;
  }
  code_ = code;
  pristine_ = code;
  shadow_ = mem_;
  pc_ = 0;
  t_ = 0;
  halted_ = false;
  faulted_ = false;
  faultReason_.clear();
  trace_.clear();
  stateDump_.clear();
  buildVTables();
  return true;
}

bool Machine::patchInstructionByte(uint32_t slot, uint32_t byteOff, uint8_t value) {
  if (slot >= programSlots() || byteOff >= kInstrBytes)
    return false;
  code_[static_cast<size_t>(slot) * kInstrBytes + byteOff] = value;
  return true;
}

void Machine::setReg(uint32_t idx, uint32_t value) {
  assert(idx < regCount_ && "setReg out of range");
  regs_[idx] = value;
}

uint32_t Machine::reg(uint32_t idx) const {
  assert(idx < regCount_ && "reg out of range");
  return regs_[idx];
}

void Machine::fillRegs(uint32_t value) {
  for (auto &r : regs_)
    r = value;
}

void Machine::writeMem(uint32_t addr, const void *src, uint32_t len) {
  assert(addr + len <= kMemBytes && "writeMem out of range");
  std::memcpy(mem_.data() + addr, src, len);
  if (shadow_.size() == mem_.size())
    std::memcpy(shadow_.data() + addr, src, len);
}

void Machine::pokeMemory(uint32_t addr, uint8_t value) {
  if (addr < mem_.size())
    mem_[addr] = value; // shadow deliberately untouched
}

void Machine::verifyMemoryPlane() {
  if (!monitor_)
    return;
  auto fnv = [](const std::vector<uint8_t> &b) {
    uint32_t h = 0x811c9dc5u;
    for (uint8_t c : b)
      h = (h ^ c) * 0x01000193u;
    return static_cast<uint64_t>(h);
  };
  monitor_->checkpoint(EvidencePlane::Memory, fnv(mem_), fnv(shadow_));
}

uint32_t Machine::readMem32(uint32_t addr) const {
  assert(addr + 4 <= kMemBytes && "readMem32 out of range");
  return static_cast<uint32_t>(mem_[addr]) |
         (static_cast<uint32_t>(mem_[addr + 1]) << 8) |
         (static_cast<uint32_t>(mem_[addr + 2]) << 16) |
         (static_cast<uint32_t>(mem_[addr + 3]) << 24);
}

BitVector Machine::stateBits() const {
  BitVector s(p_.n);
  for (uint32_t r = 0; r < regCount_; ++r)
    for (uint32_t b = 0; b < 32; ++b)
      if ((regs_[r] >> b) & 1u)
        s.set(r * 32 + b, true);
  return s;
}

BitVector Machine::project() const { return matVec(H_, stateBits()); }

void Machine::fault(const char *why) {
  faulted_ = true;
  faultReason_ = why;
}

bool Machine::step() {
  if (halted_ || faulted_)
    return false;
  if (pc_ >= programSlots()) {
    fault("pc out of range");
    return true;
  }

  const Instr in = decodeInstr(code_.data() + static_cast<size_t>(pc_) * kInstrBytes);

  if (monitor_) {
    const size_t off = static_cast<size_t>(pc_) * kInstrBytes;
    uint64_t observed = 0, expected = 0;
    for (uint32_t b = 0; b < kInstrBytes; ++b) {
      observed |= static_cast<uint64_t>(code_[off + b]) << (8 * b);
      expected |= static_cast<uint64_t>(pristine_[off + b]) << (8 * b);
    }
    monitor_->checkpoint(EvidencePlane::ControlFlow, observed, expected);
  }

  if (traceEnabled_) {
    TraceRecord rec;
    rec.t = t_;
    rec.pc = pc_;
    rec.op = in.op;
    rec.xBefore = project();
    trace_.push_back(std::move(rec));
  }

  if (mode_ == VmMode::Linear) {
    // F(s,i) = s XOR v(i); no data dependency, no arithmetic.
    BitVector s = stateBits();
    s.xorWith(v_[pc_]);
    for (uint32_t r = 0; r < regCount_; ++r) {
      uint32_t word = 0;
      for (uint32_t b = 0; b < 32; ++b)
        if (s.get(r * 32 + b))
          word |= (1u << b);
      regs_[r] = word;
    }
    if (static_cast<Opcode>(in.op) == Opcode::Halt) {
      halted_ = true;
    } else {
      ++pc_;
    }
    ++t_;
    if (traceEnabled_)
      trace_.back().xAfter = project();
    return true;
  }

  // ---- Plain mode: real register-machine semantics ----
  if (!regOk(in.dst) && (in.op == static_cast<uint8_t>(Opcode::Movi) ||
                         in.op == static_cast<uint8_t>(Opcode::Mov) ||
                         in.op == static_cast<uint8_t>(Opcode::Add) ||
                         in.op == static_cast<uint8_t>(Opcode::Sub) ||
                         in.op == static_cast<uint8_t>(Opcode::Xor) ||
                         in.op == static_cast<uint8_t>(Opcode::And) ||
                         in.op == static_cast<uint8_t>(Opcode::Or) ||
                         in.op == static_cast<uint8_t>(Opcode::Shl) ||
                         in.op == static_cast<uint8_t>(Opcode::Shr) ||
                         in.op == static_cast<uint8_t>(Opcode::Mul) ||
                         in.op == static_cast<uint8_t>(Opcode::Ld))) {
    fault("dst register out of range");
    return true;
  }

  const auto op = static_cast<Opcode>(in.op);
  const uint32_t aVal = regOk(in.a) ? regs_[in.a] : 0;
  const uint32_t bVal = regOk(in.b) ? regs_[in.b] : 0;
  uint32_t nextPc = pc_ + 1;

  switch (op) {
  case Opcode::Nop:
    break;
  case Opcode::Movi:
    regs_[in.dst] = in.imm;
    break;
  case Opcode::Mov:
    if (!regOk(in.a)) {
      fault("mov source out of range");
      return true;
    }
    regs_[in.dst] = aVal;
    break;
  case Opcode::Add:
  case Opcode::Sub:
  case Opcode::Xor:
  case Opcode::And:
  case Opcode::Or:
  case Opcode::Mul:
  case Opcode::Shl:
  case Opcode::Shr: {
    if (!regOk(in.a) || !regOk(in.b)) {
      fault("arithmetic operand out of range");
      return true;
    }
    uint32_t res = 0;
    switch (op) {
    case Opcode::Add: res = aVal + bVal; break;
    case Opcode::Sub: res = aVal - bVal; break;
    case Opcode::Xor: res = aVal ^ bVal; break;
    case Opcode::And: res = aVal & bVal; break;
    case Opcode::Or: res = aVal | bVal; break;
    case Opcode::Mul: res = aVal * bVal; break;
    case Opcode::Shl: res = aVal << (bVal & 31u); break;
    case Opcode::Shr: res = aVal >> (bVal & 31u); break;
    default: break;
    }
    regs_[in.dst] = res;
    break;
  }
  case Opcode::Ld: {
    if (!regOk(in.a)) {
      fault("ld address register out of range");
      return true;
    }
    const uint32_t addr = aVal + in.imm;
    if (!memOk(addr)) {
      fault("ld address out of range or unaligned");
      return true;
    }
    regs_[in.dst] = readMem32(addr);
    break;
  }
  case Opcode::St: {
    if (!regOk(in.a) || !regOk(in.b)) {
      fault("st operand out of range");
      return true;
    }
    const uint32_t addr = aVal + in.imm;
    if (!memOk(addr)) {
      fault("st address out of range or unaligned");
      return true;
    }
    const uint32_t val = regs_[in.b];
    mem_[addr] = static_cast<uint8_t>(val & 0xFF);
    mem_[addr + 1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    mem_[addr + 2] = static_cast<uint8_t>((val >> 16) & 0xFF);
    mem_[addr + 3] = static_cast<uint8_t>((val >> 24) & 0xFF);
    break;
  }
  case Opcode::Jmp:
    nextPc = static_cast<uint32_t>(static_cast<int64_t>(pc_) + in.simm());
    break;
  case Opcode::Brz:
    if (!regOk(in.a)) {
      fault("brz register out of range");
      return true;
    }
    nextPc = (aVal == 0)
                 ? static_cast<uint32_t>(static_cast<int64_t>(pc_) + in.simm())
                 : pc_ + 1;
    break;
  case Opcode::Halt:
    halted_ = true;
    nextPc = pc_;
    break;
  default:
    fault("unknown opcode");
    return true;
  }

  ++t_;
  if (!halted_)
    pc_ = nextPc;
  if (traceEnabled_)
    trace_.back().xAfter = project();
  return true;
}

uint64_t Machine::run(uint64_t maxSteps) {
  uint64_t n = 0;
  if (dumpStates_)
    stateDump_.push_back(stateBits());
  while (n < maxSteps && !halted_ && !faulted_) {
    step();
    ++n;
    if (dumpStates_)
      stateDump_.push_back(stateBits());
  }
  return n;
}

} // namespace hsvm
