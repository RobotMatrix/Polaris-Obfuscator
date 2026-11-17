//===- programs.h - test programs and their native references --------------===//
//
// Three small programs cover the operation classes in plan D-11:
//   sum       arithmetic + branch + loop
//   crc       load + xor + shifts + rotate + loop
//   copy_xor  load + store + xor + loop over memory
// plus "allops", which contains every opcode once and is only meaningful in
// linear mode (it exists so attack A1 can cover the whole opcode table).
//
// Every program leaves its result in r0. The native reference functions
// implement exactly the same arithmetic, so the differential test can compare
// them without trusting the interpreter.
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_PROGRAMS_H
#define HSV_M_PROGRAMS_H

#include <cstdint>
#include <string>
#include <vector>

namespace hsvm {

const std::vector<uint8_t> &programSum();
const std::vector<uint8_t> &programCrc();
const std::vector<uint8_t> &programCopyXor();
const std::vector<uint8_t> &programAllOps();

// Returns nullptr when the name is unknown.
const std::vector<uint8_t> *findProgram(const std::string &name);

uint32_t nativeSum(uint32_t n);
uint32_t nativeCrc(const uint8_t *data, uint32_t len);
uint32_t nativeCopyXor(uint8_t *dst, const uint8_t *src, uint32_t len,
                       uint32_t key);

// Deterministic filler so "random input" is reproducible from (seed, index).
void fillDeterministic(uint8_t *buf, uint32_t len, uint64_t seed);

inline constexpr uint32_t kCopyXorDst = 0x800;
inline constexpr uint32_t kCopyXorKey = 0xA5A5A5A5u;

} // namespace hsvm

#endif // HSV_M_PROGRAMS_H
