//===- programs.cpp - test programs and native references -----------------===//
#include "hsvm/programs.h"

#include "hsvm/instr.h"

#include <cstring>

namespace hsvm {

namespace {

void fillDeterministicImpl(uint8_t *buf, uint32_t len, uint64_t seed) {
  uint64_t s = seed;
  uint32_t i = 0;
  while (i < len) {
    s += 0x9E3779B97F4A7C15ULL;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z ^= z >> 31;
    for (int b = 0; b < 8 && i < len; ++b, ++i)
      buf[i] = static_cast<uint8_t>((z >> (8 * b)) & 0xFF);
  }
}

} // namespace

const std::vector<uint8_t> &programSum() {
  static const std::vector<uint8_t> code = [] {
    Asm a;
    a.op(Opcode::Movi, 1, 0, 0, 0);       // 0: r1 = 0 (acc)
    a.op(Opcode::Mov, 2, 0, 0, 0);        // 1: r2 = n (r0)
    a.op(Opcode::Movi, 3, 0, 0, 1);       // 2: r3 = 1
    a.op(Opcode::Brz, 0, 2, 0, 5);        // 3: if n == 0 -> 8
    a.op(Opcode::Add, 1, 1, 2, 0);        // 4: r1 += r2
    a.op(Opcode::Sub, 2, 2, 3, 0);        // 5: r2 -= 1
    a.op(Opcode::Brz, 0, 2, 0, 2);        // 6: if r2 == 0 -> 8
    a.op(Opcode::Jmp, 0, 0, 0, static_cast<uint32_t>(-3)); // 7: -> 4
    a.op(Opcode::Mov, 0, 1, 0, 0);        // 8: r0 = r1
    a.op(Opcode::Halt, 0, 0, 0, 0);       // 9
    return a.code();
  }();
  return code;
}

const std::vector<uint8_t> &programCrc() {
  static const std::vector<uint8_t> code = [] {
    Asm a;
    a.op(Opcode::Movi, 1, 0, 0, 0);       // 0: acc = 0
    a.op(Opcode::Movi, 5, 0, 0, 0);       // 1: addr = 0
    a.op(Opcode::Movi, 8, 0, 0, 5);       // 2: r8 = 5
    a.op(Opcode::Movi, 9, 0, 0, 27);      // 3: r9 = 27
    a.op(Opcode::Movi, 10, 0, 0, 4);      // 4: r10 = 4
    a.op(Opcode::Mov, 2, 0, 0, 0);        // 5: r2 = len  (outside the loop)
    a.op(Opcode::Ld, 3, 5, 0, 0);         // 6: r3 = mem32[addr]
    a.op(Opcode::Xor, 1, 1, 3, 0);        // 7: acc ^= r3
    a.op(Opcode::Shl, 4, 1, 8, 0);        // 8: r4 = acc << 5
    a.op(Opcode::Shr, 6, 1, 9, 0);        // 9: r6 = acc >> 27
    a.op(Opcode::Or, 1, 4, 6, 0);         // 10: acc = rotl(acc,5)
    a.op(Opcode::Add, 5, 5, 10, 0);       // 11: addr += 4
    a.op(Opcode::Sub, 2, 2, 10, 0);       // 12: len -= 4
    a.op(Opcode::Brz, 0, 2, 0, 2);        // 13: if len == 0 -> 15
    a.op(Opcode::Jmp, 0, 0, 0, static_cast<uint32_t>(-8)); // 14: -> 6
    a.op(Opcode::Mov, 0, 1, 0, 0);        // 15: r0 = acc
    a.op(Opcode::Halt, 0, 0, 0, 0);       // 16
    return a.code();
  }();
  return code;
}

const std::vector<uint8_t> &programCopyXor() {
  static const std::vector<uint8_t> code = [] {
    Asm a;
    a.op(Opcode::Movi, 1, 0, 0, 0);       // 0: acc = 0
    a.op(Opcode::Movi, 5, 0, 0, 0);       // 1: src = 0
    a.op(Opcode::Movi, 6, 0, 0, kCopyXorDst); // 2: dst = 0x800
    a.op(Opcode::Movi, 7, 0, 0, kCopyXorKey); // 3: key
    a.op(Opcode::Movi, 10, 0, 0, 4);      // 4: r10 = 4
    a.op(Opcode::Mov, 2, 0, 0, 0);        // 5: r2 = len
    a.op(Opcode::Ld, 3, 5, 0, 0);         // 6: r3 = mem32[src]
    a.op(Opcode::Xor, 3, 3, 7, 0);        // 7: r3 ^= key
    a.op(Opcode::St, 0, 6, 3, 0);         // 8: mem32[dst] = r3
    a.op(Opcode::Xor, 1, 1, 3, 0);        // 9: acc ^= r3
    a.op(Opcode::Add, 5, 5, 10, 0);       // 10: src += 4
    a.op(Opcode::Add, 6, 6, 10, 0);       // 11: dst += 4
    a.op(Opcode::Sub, 2, 2, 10, 0);       // 12: len -= 4
    a.op(Opcode::Brz, 0, 2, 0, 2);        // 13: if len == 0 -> 15
    a.op(Opcode::Jmp, 0, 0, 0, static_cast<uint32_t>(-8)); // 14: -> 6
    a.op(Opcode::Mov, 0, 1, 0, 0);        // 15: r0 = acc
    a.op(Opcode::Halt, 0, 0, 0, 0);       // 16
    return a.code();
  }();
  return code;
}

const std::vector<uint8_t> &programAllOps() {
  static const std::vector<uint8_t> code = [] {
    Asm a;
    for (uint32_t i = 0; i < 16u; ++i) // Tld needs a host table; excluded until the pass emits it
      a.op(static_cast<Opcode>(i), static_cast<uint8_t>(i % 16),
           static_cast<uint8_t>((i + 1) % 16), static_cast<uint8_t>((i + 2) % 16),
           i * 0x01010101u);
    return a.code();
  }();
  return code;
}

const std::vector<uint8_t> *findProgram(const std::string &name) {
  if (name == "sum")
    return &programSum();
  if (name == "crc")
    return &programCrc();
  if (name == "copy_xor")
    return &programCopyXor();
  if (name == "allops")
    return &programAllOps();
  return nullptr;
}

uint32_t nativeSum(uint32_t n) {
  uint32_t acc = 0;
  while (n != 0) {
    acc += n;
    --n;
  }
  return acc;
}

uint32_t nativeCrc(const uint8_t *data, uint32_t len) {
  uint32_t acc = 0;
  for (uint32_t i = 0; i + 4 <= len; i += 4) {
    const uint32_t w = static_cast<uint32_t>(data[i]) |
                       (static_cast<uint32_t>(data[i + 1]) << 8) |
                       (static_cast<uint32_t>(data[i + 2]) << 16) |
                       (static_cast<uint32_t>(data[i + 3]) << 24);
    acc ^= w;
    acc = (acc << 5) | (acc >> 27);
  }
  return acc;
}

uint32_t nativeCopyXor(uint8_t *dst, const uint8_t *src, uint32_t len,
                       uint32_t key) {
  uint32_t acc = 0;
  for (uint32_t i = 0; i + 4 <= len; i += 4) {
    const uint32_t w = static_cast<uint32_t>(src[i]) |
                       (static_cast<uint32_t>(src[i + 1]) << 8) |
                       (static_cast<uint32_t>(src[i + 2]) << 16) |
                       (static_cast<uint32_t>(src[i + 3]) << 24);
    const uint32_t v = w ^ key;
    dst[i] = static_cast<uint8_t>(v & 0xFF);
    dst[i + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    dst[i + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    dst[i + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    acc ^= v;
  }
  return acc;
}

void fillDeterministic(uint8_t *buf, uint32_t len, uint64_t seed) {
  fillDeterministicImpl(buf, len, seed);
}

} // namespace hsvm
