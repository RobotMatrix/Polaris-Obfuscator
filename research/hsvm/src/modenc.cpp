#include <hsvm/modenc.h>

#include <algorithm>
#include <numeric>
#include <stdexcept>

namespace hsvm {

namespace {
uint64_t splitmix(uint64_t &s) {
  uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}
} // namespace

ModuleEncoder::ModuleEncoder(uint32_t lanes, uint64_t seed) : lanes_(lanes) {
  if (lanes == 0 || lanes > 8)
    throw std::invalid_argument("ModuleEncoder: lanes must be in [1,8]");
  fwd_.assign(static_cast<size_t>(lanes) * 256, 0);
  inv_.assign(static_cast<size_t>(lanes) * 256, 0);
  uint64_t s = seed;
  for (uint32_t l = 0; l < lanes; ++l) {
    std::vector<uint8_t> perm(256);
    std::iota(perm.begin(), perm.end(), 0);
    for (int i = 255; i > 0; --i) {
      const int j = static_cast<int>(splitmix(s) % static_cast<uint64_t>(i + 1));
      std::swap(perm[i], perm[j]);
    }
    for (int i = 0; i < 256; ++i) {
      fwd_[static_cast<size_t>(l) * 256 + i] = perm[i];
      inv_[static_cast<size_t>(l) * 256 + perm[i]] = static_cast<uint8_t>(i);
    }
  }
}

uint64_t ModuleEncoder::encode(uint64_t value) const {
  uint64_t out = 0;
  for (uint32_t l = 0; l < lanes_; ++l) {
    const uint8_t b = static_cast<uint8_t>((value >> (8 * l)) & 0xFF);
    out |= static_cast<uint64_t>(fwd_[static_cast<size_t>(l) * 256 + b])
           << (8 * l);
  }
  return out;
}

uint64_t ModuleEncoder::decode(uint64_t value) const {
  uint64_t out = 0;
  for (uint32_t l = 0; l < lanes_; ++l) {
    const uint8_t b = static_cast<uint8_t>((value >> (8 * l)) & 0xFF);
    out |= static_cast<uint64_t>(inv_[static_cast<size_t>(l) * 256 + b])
           << (8 * l);
  }
  return out;
}

} // namespace hsvm
