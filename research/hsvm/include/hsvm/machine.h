//===- machine.h - HSV virtual machine (Plain and Linear ablations) --------===//
//
// Two execution modes share one ISA, one state layout and one trace format:
//
//   Plain  : real register-machine semantics. This is the "plain VM" baseline
//            of the cost model (plan §5.5) and the differential-test oracle
//            for later compiler work.
//
//   Linear : the V0.1 ablation F(s,i) = s XOR v(i). Semantics are deliberately
//            NOT executed: the transition only XORs a per-slot mask into the
//            whole state. This is what stage 0 falsifies - the observable
//            projection x = H s then evolves with no hidden state and no data
//            dependency at all.
//
// State layout: regs_[r] holds state bits [32r, 32r+32). PC and memory are
// outside s (they are separately observable), matching plan D-06.
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_MACHINE_H
#define HSV_M_MACHINE_H

#include "hsvm/gf2.h"
#include "hsvm/c6.h"
#include "hsvm/instr.h"
#include "hsvm/params.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hsvm {

enum class VmMode { Plain, Linear };

struct TraceRecord {
  uint64_t t = 0;
  uint32_t pc = 0;
  uint8_t op = 0;
  BitVector xBefore;
  BitVector xAfter;
};

std::string toHex(const BitVector &v);

class Machine {
public:
  static constexpr uint32_t kMemBytes = 4096;
  static constexpr uint32_t kMaxRegs = 16;

  // ISA v2: Tld reads from a host-provided read-only table outside the 4 KiB VM
  // memory (the white-box tables are 64 KiB each).
  void setTable(const uint8_t *t, uint32_t bytes) { table_ = t; tableBytes_ = bytes; }
  bool tableOk(uint32_t addr) const {
    return table_ != nullptr && addr <= tableBytes_ - 4 && (addr & 3u) == 0;
  }
  uint32_t readTable32(uint32_t addr) const {
    return (uint32_t)table_[addr] | ((uint32_t)table_[addr + 1] << 8) |
           ((uint32_t)table_[addr + 2] << 16) | ((uint32_t)table_[addr + 3] << 24);
  }
  const uint8_t *table_ = nullptr;
  uint32_t tableBytes_ = 0;

  // Throws std::invalid_argument when the parameter point cannot be hosted by
  // the 16 x 32-bit register file (that is a harness limit, not a scheme rule).
  Machine(const HsvmParams &p, VmMode mode);

  bool loadProgram(const std::vector<uint8_t> &code, std::string *err = nullptr);

  void setReg(uint32_t idx, uint32_t value);
  uint32_t reg(uint32_t idx) const;
  void fillRegs(uint32_t value);
  void writeMem(uint32_t addr, const void *src, uint32_t len);
  uint32_t readMem32(uint32_t addr) const;

  // Executes until HALT, fault, or maxSteps. Returns the number of steps
  // actually executed.
  uint64_t run(uint64_t maxSteps = 1000000);

  bool halted() const { return halted_; }
  bool faulted() const { return faulted_; }
  const std::string &faultReason() const { return faultReason_; }
  uint64_t steps() const { return t_; }

  BitVector stateBits() const;
  BitVector project() const;

  const std::vector<TraceRecord> &trace() const { return trace_; }
  void setTraceEnabled(bool on) { traceEnabled_ = on; }
  void clearTrace() { trace_.clear(); }

  // Per-step canonical state history (A2 stand-in). Disabled by default so a
  // normal run does not pay for it.
  void setStateDumpEnabled(bool on) { dumpStates_ = on; }
  const std::vector<BitVector> &stateDump() const { return stateDump_; }

  // C6 hook: every executed instruction is compared with the pristine copy
  // taken at loadProgram, reported on the ControlFlow plane. The caller owns
  // the monitor and decides what to do with the resulting risk state.
  void setIntegrityMonitor(IntegrityMonitor *mon) { monitor_ = mon; }
  // Debug/test hook: patch one byte of the live program image, i.e. simulate an
  // attacker who owns the process and rewrites code in place.
  bool patchInstructionByte(uint32_t slot, uint32_t byteOff, uint8_t value);
  // Test hook: write memory without going through writeMem, i.e. simulate an
  // attacker who poked the buffer directly instead of following the VM.
  void pokeMemory(uint32_t addr, uint8_t value);
  // Memory plane: compare the live buffer against the shadow kept in sync by
  // writeMem. A mismatch means somebody wrote outside the VM's own path.
  void verifyMemoryPlane();
  // Fault detection (C6 answer to DFA): the step transition is computed twice
  // and compared. A glitch that corrupts one copy is caught here instead of
  // leaking a faulty ciphertext. Detection is reported on the Memory plane as
  // "state self-consistency".
  void setFaultCheckEnabled(bool on) { faultCheck_ = on; }
  // Test hook: simulates an attacker glitching one state bit between the two
  // computations (the DFA model: one faulty copy, one correct copy).
  void injectFault(uint32_t stateBit) { pendingFaultBit_ = stateBit + 1; }
  uint64_t faultsDetected() const { return faultsDetected_; }

  const std::vector<BitVector> &vTable() const { return v_; }
  // Read-only views used by the differential harness (V-03). They observe, they
  // do not change behaviour.
  uint32_t pcValue() const { return pc_; }
  // One instruction, for the differential harness: same code path as run().
  bool stepOnce() { return step(); }
  const std::vector<uint8_t> &code() const { return code_; }
  const BitMatrix &projection() const { return H_; }
  const HsvmParams &params() const { return p_; }
  uint32_t regCount() const { return regCount_; }
  uint32_t programSlots() const {
    return static_cast<uint32_t>(code_.size() / kInstrBytes);
  }

private:
  bool step();
  void fault(const char *why);
  bool regOk(uint32_t idx) const { return idx < regCount_; }
  bool memOk(uint32_t addr) const {
    return addr <= kMemBytes - 4 && (addr & 3u) == 0;
  }
  void buildVTables();

  HsvmParams p_;
  VmMode mode_;
  BitMatrix H_;
  std::vector<BitVector> v_;
  std::vector<uint32_t> regs_;
  std::vector<uint8_t> mem_;
  std::vector<uint8_t> code_;
  std::vector<uint8_t> pristine_; // load-time image, used by the C6 hook
  std::vector<uint8_t> shadow_;  // memory as the VM last wrote it (C6 memory plane)
  IntegrityMonitor *monitor_ = nullptr;
  bool faultCheck_ = false;
  uint32_t pendingFaultBit_ = 0; // 0 = none, otherwise bit index + 1
  uint64_t faultsDetected_ = 0;
  uint32_t regCount_ = 0;
  uint32_t pc_ = 0;
  uint64_t t_ = 0;
  bool halted_ = false;
  bool faulted_ = false;
  bool traceEnabled_ = true;
  bool dumpStates_ = false;
  std::string faultReason_;
  std::vector<TraceRecord> trace_;
  std::vector<BitVector> stateDump_;
};

} // namespace hsvm

#endif // HSV_M_MACHINE_H
