//===- psi.h - keyed nonlinear window functions ---------------------------===//
//
// psi_i : F2^w -> F2^c, the only nonlinear component of the C1 transition
// (F(s,i) = s XOR v(i) XOR E_i psi_i(s[A_i])).
//
// Two families, both deterministic from (seed, instruction index):
//   PsiTable : full 2^w lookup table. Legal only for w <= 16; used for
//              correctness and as the "weak" comparison point, because an
//              attacker who can query it enumerates it in 2^w queries.
//   PsiSpn   : keyed SPN over w/8 lanes, table-free at the source level
//              (S-box generated in code, 4x4/3x3/2x2 GF(2^8) diffusion).
//
// The SPN S-box is affine-equivalent to the AES inverse map: x -> A*inv(x) + c
// with A a random invertible 8x8 bit matrix. That keeps the Walsh spectrum
// (max linear bias 2^-3) while keying the table, so a random permutation's
// worse bias does not silently weaken the experiment.
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_PSI_H
#define HSV_M_PSI_H

#include "hsvm/gf2.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace hsvm {

class Psi {
public:
  virtual ~Psi() = default;
  virtual uint32_t inputBits() const = 0;
  virtual uint32_t outputBits() const = 0;
  virtual BitVector apply(const BitVector &in) const = 0;

  // Allocation-free entry point used by the cost probe and (later) by the
  // emitted kernel: w <= 64, so the window fits a uint64.
  virtual uint64_t applyU64(uint64_t in) const = 0;

  // True when apply is a bijection on F2^w (required for the SPN round-trip
  // test, meaningless for a truncated table with c != w).
  virtual bool invertible() const { return false; }
  virtual BitVector invert(const BitVector &out) const {
    (void)out;
    return BitVector();
  }
  virtual const char *kind() const = 0;
};

class PsiTable : public Psi {
public:
  PsiTable(uint32_t w, uint32_t c, uint64_t seed, uint32_t index);

  uint32_t inputBits() const override { return w_; }
  uint32_t outputBits() const override { return c_; }
  BitVector apply(const BitVector &in) const override;
  uint64_t applyU64(uint64_t in) const override;
  bool invertible() const override { return c_ == w_; }
  BitVector invert(const BitVector &out) const override;
  const char *kind() const override { return "table"; }

  // Exposed for tests: 2^w entries, each c bits.
  const std::vector<uint16_t> &table() const { return table_; }

private:
  uint32_t w_ = 0, c_ = 0;
  std::vector<uint16_t> table_;
  std::vector<uint16_t> inverse_;
};

// ARX family: add-rotate-xor rounds over the whole window. Cheaper than the SPN
// (no field multiplies, no S-box), but with lower algebraic degree, so it is an
// addendum construction, not a point of the registered grid.
class PsiArx : public Psi {
public:
  PsiArx(uint32_t w, uint32_t rounds, uint64_t seed, uint32_t index);

  uint32_t inputBits() const override { return w_; }
  uint32_t outputBits() const override { return w_; }
  BitVector apply(const BitVector &in) const override;
  uint64_t applyU64(uint64_t in) const override;
  const char *kind() const override { return "arx"; }

private:
  uint32_t w_ = 0, rounds_ = 0;
  uint64_t keys_[8] = {};
};

class PsiSpn : public Psi {
public:
  PsiSpn(uint32_t w, uint32_t rounds, uint64_t seed, uint32_t index);

  uint32_t inputBits() const override { return w_; }
  uint32_t outputBits() const override { return w_; }
  BitVector apply(const BitVector &in) const override;
  uint64_t applyU64(uint64_t in) const override;
  bool invertible() const override { return true; }
  BitVector invert(const BitVector &out) const override;
  const char *kind() const override { return "spn"; }

  const uint8_t *sbox() const { return sbox_; }

private:
  uint64_t runRounds(uint64_t in, bool inverse) const;

  uint32_t w_ = 0, lanes_ = 0, rounds_ = 0;
  uint8_t sbox_[256]{};
  uint8_t invSbox_[256]{};
  std::vector<uint8_t> roundKeys_; // (rounds+1) * lanes
};

// Factory driven by the parameter point: table for w<=16, spn otherwise
// (the caller has already validated the point).
std::unique_ptr<Psi> makePsi(const struct HsvmParams &p, uint32_t index);

// GF(2^8) helpers, exposed for tests.
uint8_t gf256Mul(uint8_t a, uint8_t b);
uint8_t gf256Inv(uint8_t a);

} // namespace hsvm

#endif // HSV_M_PSI_H
