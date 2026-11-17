#include <hsvm/c6.h>

namespace hsvm {

const char *toString(EvidencePlane p) {
  switch (p) {
  case EvidencePlane::ControlFlow:
    return "control-flow";
  case EvidencePlane::Memory:
    return "memory";
  case EvidencePlane::Timing:
    return "timing";
  }
  return "?";
}

const char *toString(RiskState s) {
  switch (s) {
  case RiskState::Green:
    return "green";
  case RiskState::Yellow:
    return "yellow";
  case RiskState::Red:
    return "red";
  case RiskState::Dead:
    return "dead";
  }
  return "?";
}

namespace {
// Avalanche-friendly 64-bit mix; not a cryptographic hash and does not claim to
// be one. Its only job is that forging a chain without the key requires
// guessing 64 bits per link.
inline uint64_t rotl(uint64_t x, uint32_t n) {
  return (x << n) | (x >> (64 - n));
}
} // namespace

uint64_t EvidenceChain::mix(uint64_t prev, EvidencePlane plane,
                            uint64_t observed, uint64_t expected) const {
  uint64_t h = prev ^ key_;
  h ^= static_cast<uint64_t>(plane) * 0x9E3779B97F4A7C15ULL;
  h = rotl(h, 27) * 0xBF58476D1CE4E5B9ULL;
  h ^= observed * 0x94D049BB133111EBULL;
  h = rotl(h, 31) ^ expected;
  h *= 0xD6E8FEB86659FD93ULL;
  h ^= h >> 32;
  return h;
}

void EvidenceChain::begin(uint64_t instance_key) {
  key_ = instance_key;
  tags_.clear();
  points_.clear();
}

void EvidenceChain::append(EvidencePlane plane, uint64_t observed,
                           uint64_t expected) {
  const uint64_t prev = tags_.empty() ? key_ : tags_.back();
  tags_.push_back(mix(prev, plane, observed, expected));
  points_.push_back(Checkpoint{plane, observed, expected});
}

bool EvidenceChain::verify(uint64_t instance_key) const {
  uint64_t prev = instance_key;
  for (size_t i = 0; i < tags_.size(); ++i) {
    const Checkpoint &p = points_[i];
    if (mix(prev, p.plane, p.observed, p.expected) != tags_[i])
      return false;
    prev = tags_[i];
  }
  return true;
}

IntegrityMonitor::IntegrityMonitor(uint64_t instance_key) {
  chain_.begin(instance_key);
}

void IntegrityMonitor::advance(RiskState next) {
  if (static_cast<uint8_t>(next) > static_cast<uint8_t>(state_))
    state_ = next;
}

void IntegrityMonitor::checkpoint(EvidencePlane plane, uint64_t observed,
                                  uint64_t expected) {
  chain_.append(plane, observed, expected);
  ++planes_seen_;
  if (observed != expected) {
    ++mismatches_;
    advance(mismatches_ >= 3 ? RiskState::Dead : RiskState::Red);
  }
}

void IntegrityMonitor::endEpoch(uint32_t expected_planes) {
  if (planes_seen_ < expected_planes) {
    ++missed_;
    advance(RiskState::Yellow);
  }
  planes_seen_ = 0;
}

uint64_t IntegrityMonitor::poisonMask() const {
  // Green -> 0 (output unchanged). Any higher state poisons deterministically
  // but not in a way that tells the attacker which plane tripped.
  if (state_ == RiskState::Green)
    return 0;
  uint64_t m = 0xA24BAED4963EE407ULL ^ chain_.digest();
  if (state_ == RiskState::Dead)
    m ^= m >> 17;
  return m;
}

} // namespace hsvm
