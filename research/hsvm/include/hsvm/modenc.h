// Module-level re-encoding of psi (doc §6.1–6.3).
//
// Each 8-bit lane of the window is wrapped in its own random bijection, with the
// inverse available to the legitimate side. The point of the wrapper is to test
// the document's claim that modular encodings do not survive a global
// normalization attack (§6.2) and that conjugation adds no attacker cost (§6.1).
#pragma once

#include <cstdint>
#include <vector>

namespace hsvm {

class ModuleEncoder {
public:
  // lanes: number of 8-bit lanes (window must be lanes*8 bits).
  ModuleEncoder(uint32_t lanes, uint64_t seed);

  uint64_t encode(uint64_t value) const;
  uint64_t decode(uint64_t value) const;

  uint32_t lanes() const { return lanes_; }
  // Number of distinct per-lane bijections, i.e. how many independent "modules"
  // an attacker would have to align if module structure mattered.
  uint32_t modules() const { return lanes_; }

private:
  uint32_t lanes_ = 0;
  std::vector<uint8_t> fwd_; // lanes * 256
  std::vector<uint8_t> inv_; // lanes * 256
};

} // namespace hsvm
