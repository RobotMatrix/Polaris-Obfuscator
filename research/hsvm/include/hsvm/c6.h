// C6: execution-integrity evidence layer (doc §12.2–12.4).
//
// Design constraints taken from the document, not invented here:
//   §12.2  checks span several planes (control flow / memory / timing) so that
//          patching one plane leaves the others inconsistent;
//   §12.3  evidence is a chained structure with a per-instance key, and the
//          risk state machine is Green->Yellow->Red->Dead;
//   §12.4  a detection bit must not become a branch lever — the result feeds
//          output poisoning, never a control-flow decision.
//
// What this does NOT claim: it cannot make tampering impossible. An attacker
// who owns the process can patch the checks too. The property we can test is
// that evidence produced without the per-instance key does not verify, and that
// a single-plane edit is caught by the remaining planes.
#pragma once

#include <cstdint>
#include <vector>

namespace hsvm {

enum class EvidencePlane : uint8_t { ControlFlow = 0, Memory = 1, Timing = 2 };

const char *toString(EvidencePlane p);

enum class RiskState : uint8_t {
  Green = 0, // every plane consistent
  Yellow = 1, // a checkpoint was skipped (possible but not proven tamper)
  Red = 2,    // at least one plane mismatch
  Dead = 3,   // repeated mismatch: stop trusting the session
};

const char *toString(RiskState s);

struct Checkpoint {
  EvidencePlane plane;
  uint64_t observed; // what the checker measured
  uint64_t expected; // what it should be (derived from the hidden state)
};

// A chained digest: tag_i = mix(tag_{i-1}, plane, observed, expected) under a
// per-instance key. Without the key the chain cannot be extended consistently,
// so an attacker who rewrites one checkpoint must rewrite every later tag.
class EvidenceChain {
public:
  void begin(uint64_t instance_key);
  void append(EvidencePlane plane, uint64_t observed, uint64_t expected);
  bool verify(uint64_t instance_key) const;

  size_t size() const { return tags_.size(); }
  uint64_t digest() const { return tags_.empty() ? 0 : tags_.back(); }
  const std::vector<uint64_t> &tags() const { return tags_; }

private:
  uint64_t mix(uint64_t prev, EvidencePlane plane, uint64_t observed,
               uint64_t expected) const;
  uint64_t key_ = 0;
  std::vector<uint64_t> tags_;
  std::vector<Checkpoint> points_;
};

// Monitors one session. Checkpoints are expected once per epoch per plane; a
// missing plane at verification time yields Yellow (skip), a mismatch yields
// Red, and three mismatches yield Dead.
class IntegrityMonitor {
public:
  explicit IntegrityMonitor(uint64_t instance_key);

  void checkpoint(EvidencePlane plane, uint64_t observed, uint64_t expected);
  void endEpoch(uint32_t expected_planes);

  RiskState state() const { return state_; }
  uint32_t mismatches() const { return mismatches_; }
  uint32_t missed() const { return missed_; }

  // §12.4: the state must not steer control flow. Callers fold this mask into
  // the data path (xors into the result) instead of branching on it.
  uint64_t poisonMask() const;

  const EvidenceChain &chain() const { return chain_; }

private:
  void advance(RiskState next);
  EvidenceChain chain_;
  RiskState state_ = RiskState::Green;
  uint32_t mismatches_ = 0;
  uint32_t missed_ = 0;
  uint32_t planes_seen_ = 0;
};

} // namespace hsvm
