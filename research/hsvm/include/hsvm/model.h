//===- model.h - C1 nonlinear transition model ----------------------------===//
//
// F(s,i) = s XOR v(i) XOR E_i psi_i(s[A_i])   (doc §3.2.2 / §5.1)
//
// This class is the host-side oracle for stage 1: the same formula the compiler
// pass will emit, but callable one step at a time so Gamma, the affine test and
// the cost probe can be measured without a binary.
//
// The differential D_i(s,delta) = H(F(s^delta,i) ^ F(s,i)) is the object §3.2.2
// actually asks about. Because delta is drawn from ker(H), the s and v terms
// cancel exactly, so the model evaluates D through the precomputed HE columns
// instead of running the full transition twice.
//
//===----------------------------------------------------------------------===//
#ifndef HSV_M_MODEL_H
#define HSV_M_MODEL_H

#include "hsvm/gf2.h"
#include "hsvm/params.h"
#include "hsvm/psi.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace hsvm {

struct GammaResult {
  uint32_t instr = 0;
  double gamma = 0.0;
  uint64_t trials = 0;
  double ciLo = 0.0;
  double ciHi = 0.0;
};

struct AffineResult {
  bool affine = false;
  uint32_t dim = 0;      // dim(pi_A(K))
  uint64_t checked = 0;  // second-derivative checks performed
  bool exhaustive = false;
};

class NonlinearModel {
public:
  // Throws std::invalid_argument when the point cannot be hosted (w > 64).
  explicit NonlinearModel(const HsvmParams &p);

  const HsvmParams &params() const { return p_; }
  const BitMatrix &projection() const { return H_; }
  const BitMatrix &kernelBasisMatrix() const { return K_; }
  uint32_t instructionCount() const {
    return static_cast<uint32_t>(specs_.size());
  }

  BitVector step(const BitVector &s, uint32_t i) const;

  // Allocation-free step on the caller's word buffer ((n+63)/64 words).
  // This is the shape the emitted kernel will use, so the cost probe measures
  // it rather than the BitVector convenience path.
  void stepWords(uint64_t *words, uint32_t i) const;
  BitVector windowVector(const BitVector &s, uint32_t i) const;
  BitVector kernelSample(const BitVector &r) const { return matVec(K_, r); }

  // D_i(s, delta) for delta in ker(H); zero vector means no observable
  // coupling for this (state, direction).
  BitVector differential(uint32_t i, const BitVector &s,
                         const BitVector &delta) const;

  GammaResult gamma(uint32_t i, const std::vector<BitVector> &states,
                    uint32_t dirsPerState, Rng &rng) const;

  // Second-derivative test on pi_A(K). Exhaustive when dim <= 16, otherwise
  // sampled; the result records which was used.
  AffineResult affineTest(uint32_t i, const BitVector &s, Rng &rng,
                          bool allowExhaustive = true) const;

  const std::vector<uint32_t> &window(uint32_t i) const {
    return specs_[i].win;
  }

private:
  struct Spec {
    std::vector<uint32_t> win;
    BitVector v;
    std::vector<uint64_t> vWords;
    std::vector<std::vector<uint32_t>> scatter; // c columns of r_bar positions
    struct ScatterPos {
      uint32_t word;
      uint64_t mask;
    };
    std::vector<std::vector<ScatterPos>> scatterWords;
    std::vector<ScatterPos> flatScatter;   // concatenated columns
    std::vector<uint32_t> scatterOffsets;  // c + 1 entries
    std::unique_ptr<Psi> psi;
    enum class Kind { Table, Spn, Arx } kind = Kind::Table;
    PsiTable *tablePtr = nullptr;
    PsiSpn *spnPtr = nullptr;
    PsiArx *arxPtr = nullptr;
    std::vector<BitVector> he; // H * E[:,j], j < c
  };

  BitVector evalD(uint32_t i, const BitVector &windowBase,
                  const BitVector &u) const;
  std::vector<uint64_t> projectedKernelBasis(uint32_t i) const;

  HsvmParams p_;
  BitMatrix H_;
  BitMatrix K_;
  std::vector<Spec> specs_;
};

} // namespace hsvm

#endif // HSV_M_MODEL_H
