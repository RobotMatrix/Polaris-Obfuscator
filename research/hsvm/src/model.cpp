//===- model.cpp - C1 nonlinear transition model --------------------------===//
#include "hsvm/model.h"

#include "hsvm/isa.h"

#include <cmath>
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

void wilson(double p, uint64_t n, double &lo, double &hi, double z = 1.96) {
  const double nn = static_cast<double>(n);
  const double denom = 1.0 + z * z / nn;
  const double center = (p + z * z / (2 * nn)) / denom;
  const double half =
      z * std::sqrt(p * (1 - p) / nn + z * z / (4 * nn * nn)) / denom;
  lo = center - half < 0 ? 0 : center - half;
  hi = center + half > 1 ? 1 : center + half;
}

} // namespace

NonlinearModel::NonlinearModel(const HsvmParams &p) : p_(p) {
  requireValid(p);
  if (p.w > 64)
    throw std::invalid_argument(
        "NonlinearModel: w > 64 is outside the modelled range");

  Rng rng(p.seed ^ 0xD1B54A32D192ED03ULL);
  H_ = BitMatrix::randomFullRowRank(p.m, p.n, rng);
  K_ = kernelBasis(H_);

  specs_.resize(kNumOpcodes);
  for (uint32_t i = 0; i < kNumOpcodes; ++i) {
    Spec &spec = specs_[i];
    SplitMix sm(p.seed ^ (0x9E3779B97F4A7C15ULL * (i + 7)));

    // Window: a random w-subset of the state bits (A_i).
    std::vector<uint32_t> perm(p.n);
    for (uint32_t k = 0; k < p.n; ++k)
      perm[k] = k;
    for (uint32_t k = 0; k < p.w; ++k) {
      const uint32_t j = k + static_cast<uint32_t>(sm.next() % (p.n - k));
      std::swap(perm[k], perm[j]);
      spec.win.push_back(perm[k]);
    }

    // Base mask v(i).
    spec.v = BitVector(p.n);
    for (uint32_t k = 0; k < p.n; ++k)
      if (sm.next() & 1)
        spec.v.set(k, true);

    // Scatter E_i: c columns, each r_bar distinct positions.
    spec.scatter.resize(p.c);
    for (uint32_t col = 0; col < p.c; ++col) {
      std::vector<uint32_t> pos(p.n);
      for (uint32_t k = 0; k < p.n; ++k)
        pos[k] = k;
      for (uint32_t k = 0; k < p.rBar; ++k) {
        const uint32_t j = k + static_cast<uint32_t>(sm.next() % (p.n - k));
        std::swap(pos[k], pos[j]);
        spec.scatter[col].push_back(pos[k]);
      }
    }

    spec.psi = makePsi(p, i);

    // Word-level mirrors for the allocation-free path.
    const uint32_t nw = (p.n + 63) / 64;
    spec.vWords.assign(nw, 0);
    for (uint32_t k = 0; k < p.n; ++k)
      if (spec.v.get(k))
        spec.vWords[k >> 6] |= (1ULL << (k & 63));
    spec.scatterWords.resize(p.c);
    spec.scatterOffsets.assign(p.c + 1, 0);
    for (uint32_t col = 0; col < p.c; ++col)
      for (uint32_t pos : spec.scatter[col])
        spec.scatterWords[col].push_back(
            {pos >> 6, 1ULL << (static_cast<uint64_t>(pos) & 63)});

    // Flattened scatter plus a concrete psi pointer: both remove per-step
    // vector indirection and virtual dispatch from the measured hot path.
    for (uint32_t col = 0; col < p.c; ++col) {
      spec.scatterOffsets[col] = static_cast<uint32_t>(spec.flatScatter.size());
      for (const auto &sp : spec.scatterWords[col])
        spec.flatScatter.push_back(sp);
    }
    spec.scatterOffsets[p.c] = static_cast<uint32_t>(spec.flatScatter.size());
    if (p.psi == PsiMode::Table) {
      spec.kind = Spec::Kind::Table;
      spec.tablePtr = static_cast<PsiTable *>(spec.psi.get());
    } else if (p.psi == PsiMode::Arx) {
      spec.kind = Spec::Kind::Arx;
      spec.arxPtr = static_cast<PsiArx *>(spec.psi.get());
    } else {
      spec.kind = Spec::Kind::Spn;
      spec.spnPtr = static_cast<PsiSpn *>(spec.psi.get());
    }

    // HE columns: H applied to each scatter column.
    spec.he.resize(p.c);
    for (uint32_t col = 0; col < p.c; ++col) {
      BitVector e(p.n);
      for (uint32_t pos : spec.scatter[col])
        e.flip(pos);
      spec.he[col] = matVec(H_, e);
    }
  }
}

BitVector NonlinearModel::windowVector(const BitVector &s, uint32_t i) const {
  const Spec &spec = specs_[i];
  BitVector win(p_.w);
  for (uint32_t k = 0; k < p_.w; ++k)
    if (s.get(spec.win[k]))
      win.set(k, true);
  return win;
}

BitVector NonlinearModel::step(const BitVector &s, uint32_t i) const {
  const Spec &spec = specs_[i];
  BitVector out = s;
  out.xorWith(spec.v);
  const BitVector y = spec.psi->apply(windowVector(s, i));
  for (uint32_t col = 0; col < p_.c; ++col) {
    if (!y.get(col))
      continue;
    for (uint32_t pos : spec.scatter[col])
      out.flip(pos);
  }
  return out;
}

void NonlinearModel::stepWords(uint64_t *words, uint32_t i) const {
  const Spec &spec = specs_[i];
  uint64_t win = 0;
  for (uint32_t k = 0; k < p_.w; ++k) {
    const uint32_t pos = spec.win[k];
    // Branchless: a data-dependent `if` here mispredicts on every random bit
    // and dominated the cost probe (about 3x slower than this form).
    win |= ((words[pos >> 6] >> (pos & 63)) & 1ULL) << k;
  }
  const uint64_t y = (spec.kind == Spec::Kind::Table)
                         ? spec.tablePtr->table()[win]
                         : (spec.kind == Spec::Kind::Arx)
                               ? spec.arxPtr->applyU64(win)
                               : spec.spnPtr->applyU64(win);
  const uint32_t nw = (p_.n + 63) / 64;
  for (uint32_t k = 0; k < nw; ++k)
    words[k] ^= spec.vWords[k];
  for (uint32_t col = 0; col < p_.c; ++col) {
    const uint64_t sel = 0ULL - ((y >> col) & 1ULL);
    if (sel == 0 && spec.scatterOffsets[col + 1] == spec.scatterOffsets[col])
      continue;
    for (uint32_t k = spec.scatterOffsets[col]; k < spec.scatterOffsets[col + 1];
         ++k)
      words[spec.flatScatter[k].word] ^= spec.flatScatter[k].mask & sel;
  }
}

BitVector NonlinearModel::evalD(uint32_t i, const BitVector &windowBase,
                                const BitVector &u) const {
  const Spec &spec = specs_[i];
  BitVector shifted = windowBase;
  shifted.xorWith(u);
  BitVector dy = spec.psi->apply(shifted);
  dy.xorWith(spec.psi->apply(windowBase));
  BitVector out(p_.m);
  for (uint32_t col = 0; col < p_.c; ++col)
    if (dy.get(col))
      out.xorWith(spec.he[col]);
  return out;
}

BitVector NonlinearModel::differential(uint32_t i, const BitVector &s,
                                       const BitVector &delta) const {
  const BitVector base = windowVector(s, i);
  return evalD(i, base, windowVector(delta, i));
}

std::vector<uint64_t> NonlinearModel::projectedKernelBasis(uint32_t i) const {
  const Spec &spec = specs_[i];
  // Incremental elimination indexed by the highest set bit, so the retained
  // vectors are independent by construction.
  std::vector<uint64_t> pivot(64, 0);
  for (uint32_t col = 0; col < K_.cols(); ++col) {
    uint64_t u = 0;
    for (uint32_t k = 0; k < p_.w; ++k)
      if (K_.get(spec.win[k], col))
        u |= (1ULL << k);
    while (u != 0) {
      const int hb = 63 - __builtin_clzll(u);
      if (pivot[static_cast<size_t>(hb)] != 0) {
        u ^= pivot[static_cast<size_t>(hb)];
      } else {
        pivot[static_cast<size_t>(hb)] = u;
        break;
      }
    }
  }
  std::vector<uint64_t> basis;
  for (uint64_t v : pivot)
    if (v != 0)
      basis.push_back(v);
  return basis;
}

GammaResult NonlinearModel::gamma(uint32_t i,
                                  const std::vector<BitVector> &states,
                                  uint32_t dirsPerState, Rng &rng) const {
  GammaResult res;
  res.instr = i;
  uint64_t hits = 0;
  uint64_t trials = 0;
  const uint32_t kcols = K_.cols();
  for (const auto &s : states) {
    for (uint32_t d = 0; d < dirsPerState; ++d) {
      const BitVector r = BitVector::random(kcols, rng);
      const BitVector delta = matVec(K_, r);
      const BitVector D = differential(i, s, delta);
      ++trials;
      if (D.popcount() != 0)
        ++hits;
    }
  }
  res.trials = trials;
  res.gamma = trials ? static_cast<double>(hits) / static_cast<double>(trials)
                     : 0.0;
  wilson(res.gamma, trials, res.ciLo, res.ciHi);
  return res;
}

AffineResult NonlinearModel::affineTest(uint32_t i, const BitVector &s,
                                        Rng &rng, bool allowExhaustive) const {
  AffineResult res;
  const std::vector<uint64_t> basis = projectedKernelBasis(i);
  res.dim = static_cast<uint32_t>(basis.size());
  const BitVector base = windowVector(s, i);

  auto eval = [&](uint64_t u) {
    BitVector ub(p_.w);
    for (uint32_t k = 0; k < p_.w; ++k)
      if ((u >> k) & 1ULL)
        ub.set(k, true);
    return evalD(i, base, ub);
  };

  const BitVector d0 = eval(0);
  if (res.dim == 0) {
    res.affine = true;
    res.exhaustive = true;
    return res;
  }

  if (allowExhaustive && res.dim <= 16) {
    res.exhaustive = true;
    const uint32_t total = 1u << res.dim;
    std::vector<BitVector> dbasis;
    dbasis.reserve(basis.size());
    for (uint64_t b : basis)
      dbasis.push_back(eval(b));
    bool affine = true;
    uint64_t checks = 0;
    for (uint32_t idx = 0; idx < total && affine; ++idx) {
      uint64_t u = 0;
      for (uint32_t b = 0; b < res.dim; ++b)
        if ((idx >> b) & 1u)
          u ^= basis[b];
      const BitVector du = (idx == 0) ? d0 : eval(u);
      for (uint32_t b = 0; b < res.dim; ++b) {
        const BitVector dub = (idx == 0) ? dbasis[b] : eval(u ^ basis[b]);
        BitVector lhs = du;
        lhs.xorWith(dub);
        BitVector rhs = d0;
        rhs.xorWith(dbasis[b]);
        ++checks;
        if (lhs != rhs) {
          affine = false;
          break;
        }
      }
    }
    res.affine = affine;
    res.checked = checks;
    return res;
  }

  // Sampled second-derivative test: report sample count, never a proof.
  res.exhaustive = false;
  bool affine = true;
  uint64_t checks = 0;
  for (int t = 0; t < 10000 && affine; ++t) {
    uint64_t u = 0, v = 0;
    for (uint32_t b = 0; b < res.dim; ++b) {
      if (rng() & 1)
        u ^= basis[b];
      if (rng() & 1)
        v ^= basis[b];
    }
    BitVector lhs = eval(u);
    lhs.xorWith(eval(u ^ v));
    BitVector rhs = eval(v);
    rhs.xorWith(d0);
    ++checks;
    if (lhs != rhs)
      affine = false;
  }
  res.affine = affine;
  res.checked = checks;
  return res;
}

} // namespace hsvm
