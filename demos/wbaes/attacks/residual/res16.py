"""Readers and decompositions for the F4 shape: 16-bit-output pair tables.

The construction under measurement pairs the four lanes of a column two by two and
pairs the *output rows* as well, so a column's partial sums are 16 bits wide:

    T_L01[a][b] = E01( MC[0][0]u0 ^ MC[0][1]u1 , MC[1][0]u0 ^ MC[1][1]u1 )
    T_R01[c][d] = E01( MC[0][2]u2 ^ MC[0][3]u3 , MC[1][0]u2 ^ MC[1][1]u3 )
    Y01 = E01^-1( T_L01 ^ T_R01 )              # 16-bit XOR, 16-bit values

with the same per-build affine 16-bit map E01 on both halves, and four 2^16-index
decode tables that apply E^-1, the column constant and the output bijection.

This module reads that layout out of an artifact and offers the three things an
attacker needs to look at:

  * `SepFit`   - is T[a][b] == X[a] ^ Y[b]?  (the dl4/BGE step, in 16-bit values)
  * `Decomp16` - the generalisation of reslib.Decomp to 16-bit-valued tables, plus
                 the 8-bit projections of the same table
  * `key_candidates16` - the gauge-invariant per-byte key test on a 16-bit axis

Nothing here assumes the generator's internals: every number is read from the
artifact's bytes (or, where stated, from the py_in.h / py_seal.h side files that a
build emits).
"""

import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import wblib as wb
import reslib as R

MC = wb.MC
S = wb.SBOX

# ---- F4 layout (wbaes_hybrid.h, HY_FAM_W16) ---------------------------------
FAM_W16 = 4
K_W16_L = 200          # 200..203: the four 16-bit-output pair tables
K_W16_D = 208          # 208..211: the four 2^16-index decode tables
W16_TAB = wb.U16       # one pair table: 2^16 entries * 2 B = 131072 B


def is_macho(path):
    with open(path, "rb") as f:
        return f.read(4) in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")


def load(table_path, workdir, env_args=wb.DEFAULT_ENV):
    """Unmask a raw F4 table (as gen_hybrid writes it) and hand back (art, seed, secs).

    `workdir` must hold the hy_in.h / hy_seal.h the generator wrote next to the
    table. A Mach-O is refused rather than unmasked: the mask starts at the
    __hytab section, not at file byte 0, so treating the binary as a table yields
    bytes that are wrong everywhere while every read still "succeeds" (0/16 key
    bytes, no error). Use load_binary() for an exported artifact.
    """
    if is_macho(table_path):
        raise SystemExit(
            "%s is a Mach-O, not a raw table: the mask starts at __hytab, so reading "
            "the file as a table gives garbage. Use --binary / res16.load_binary()."
            % os.path.basename(table_path))
    t0 = time.time()
    art, seed = R.load_variant(table_path, workdir, env_args=env_args)
    return art, seed, time.time() - t0


def load_binary(path, seed=None, env_args=wb.DEFAULT_ENV):
    """Unmask the __hytab section of an exported artifact (wbaes_f4_max, ...)."""
    t0 = time.time()
    art, _t = R.load_shipped(path, seed=seed, cache=None, env_args=env_args)
    return art, art.seed, time.time() - t0


def col_base(col, rnd=0, direction=0):
    """Column slot base, exactly as wbaes_hybrid.h computes it."""
    if direction == 0:
        return wb.enc_col(rnd, col)
    return wb.dec_mc(rnd) + wb.COL * col


def pair_off(col, k, rnd=0, direction=0):
    """Byte offset of pair table k: col_base + k*HY_W16_TAB (wbaes_hybrid.h:335).

    The previous generation put a 256-entry lane table every 1024 B; F4 puts one
    2^16-entry pair table every HY_W16_TAB = 131072 B. k=0 is the same address in
    both, which is exactly why a reader that forgets the stride still looks
    half-right.
    """
    return col_base(col, rnd, direction) + k * W16_TAB


def pair_tag(col, k, rnd=0, direction=0):
    return wb.hy_tag(direction, rnd, col, K_W16_L + k)


def read_pair(art, off, tag):
    """One 2^16-index table at `off` as Q[a][b] (a = low index byte), 16-bit values."""
    r16 = art.tab_obj.r16
    return [[r16(off, a | (b << 8), tag) for b in range(256)] for a in range(256)]


def pair_tab(art, col, k, rnd=0, direction=0):
    """One 2^16-index pair table as Q[a][b] (a = low index byte), 16-bit values."""
    return read_pair(art, pair_off(col, k, rnd, direction), pair_tag(col, k, rnd, direction))


def pair_row(art, col, k, lane_off, rnd=0, direction=0):
    """One 256-entry axis of a pair table: the other index byte held at 0.

    lane_off = 0 -> vary the low index byte (the pair's first lane),
    lane_off = 1 -> vary the high index byte (the pair's second lane).
    """
    off = pair_off(col, k, rnd, direction)
    tag = pair_tag(col, k, rnd, direction)
    r16 = art.tab_obj.r16
    if lane_off == 0:
        return [r16(off, v, tag) for v in range(256)]
    return [r16(off, v << 8, tag) for v in range(256)]


def span_dims(Q, bits=16):
    """(row ranks, column ranks) of a table's GF(2) difference spans.

    F4 writes T[a][b] = A(phi(a)) ^ B(psi(b)) ^ c with A, B 8x8 blocks, so every
    row spans an affine 8-dimensional subspace and so does every column. Random
    bytes -- what a wrong offset returns -- span all 16. This is the cheap test
    for "did I read the right address": two 256-entry reads per dimension, no key
    test, no decomposition.
    """
    rr = [rank_of([Q[a][b] ^ Q[a][0] for b in range(256)], bits) for a in range(256)]
    cc = [rank_of([Q[a][b] ^ Q[0][b] for a in range(256)], bits) for b in range(256)]
    return sorted(set(rr)), sorted(set(cc))


def decode_tab(art, col, row, rnd=0, direction=0):
    """One 2^16-index decode table (8-bit values) as a flat 65536-entry list."""
    off = col_base(col, rnd, direction) + wb.BDY_OFF + row * wb.N
    tag = wb.hy_tag(direction, rnd, col, K_W16_D + row)
    r8 = art.tab_obj.r8
    return [r8(off, i, tag) for i in range(65536)]


# ---------------------------------------------------------------------------
# 1. the dl4/BGE step, in 16-bit values
def sep_fit(Q, samples=None):
    """Fit Q[a][b] == X[a] ^ Y[b] and report how many entries it reproduces.

    X[a] = Q[a][0], Y[b] = Q[0][b] ^ Q[0][0]: the rank-1 tensor the dl4 attack
    used. A 16-bit per-build permutation encoding on the *value* is not linear, so
    on dl5 this fit reproduces ~0 % of the off-axis entries; the question here is
    what it does when the value encoding has to be affine.
    """
    x = [Q[a][0] for a in range(256)]
    y = [Q[0][b] ^ Q[0][0] for b in range(256)]
    ok = bad = 0
    for a in range(256):
        xa = x[a]
        for b in range(256):
            if (xa ^ y[b]) == Q[a][b]:
                ok += 1
            else:
                bad += 1
    return ok, bad


# ---------------------------------------------------------------------------
# 2. the generalised decomposition
class Decomp16(object):
    """Decomp generalised to a w-bit value alphabet, and what it reports.

    reslib.Decomp needs, for every row a, f_a = Q[a][.] to be a *permutation of
    the 256 output values*, because it builds lam_a = f_a o f_0^-1 and reads the
    group off LAM. With 8-bit values a row has 256 entries, so "permutation" is
    possible. With w = 16 bits the alphabet has 65536 elements and a row still has
    256 entries: rows can at best be injective into a 2^16 alphabet, and
    lam_a : V_a -> V_0 is only defined where V_a = V_0.
    """

    def __init__(self, Q, label=""):
        self.label = label
        self.width = 16
        rows = Q
        self.row_distinct = [len(set(r)) for r in rows]
        imgs = [frozenset(r) for r in rows]
        # every row must be a bijection onto the *same* 256-element value set
        self.shared = sum(1 for im in imgs[1:] if im == imgs[0])
        self.max_overlap = max(len(im & imgs[0]) for im in imgs[1:]) if len(imgs) > 1 else 0
        self.defined = (self.row_distinct.count(256) == 256 and self.shared == 255)
        self.group = None
        if self.defined:
            # same construction as reslib.Decomp, over a 256-element value set
            vals = sorted(imgs[0])
            idx_of = {v: i for i, v in enumerate(vals)}
            rows2 = [bytes(idx_of[v] for v in r) for r in rows]
            d = R.Decomp(rows2)
            self.group = d
        self.ok = self.defined

    def report(self):
        return ("rows injective %d/256, rows sharing row-0's value set %d/255 "
                "(max overlap %d), LAM defined: %s"
                % (self.row_distinct.count(256), self.shared, self.max_overlap,
                   "yes" if self.defined else "no"))


def decomp_projection(Q, byte):
    """Decomp applied to one 8-bit projection of a 16-bit-valued table.

    Returns (ok, reason_or_group). This is the shape the previous generation was
    broken by: a 2^16-index table with 8-bit values whose rows are permutations.
    """
    P = [[(Q[a][b] >> (8 * byte)) & 255 for b in range(256)] for a in range(256)]
    try:
        d = R.Decomp(P)
        return True, d
    except ValueError as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# 3. the gauge-invariant key test, on a 16-bit-valued axis
def rank_of(vecs, bits=16):
    """GF(2) rank of a list of `bits`-wide vectors."""
    rows = list(vecs)
    rank = 0
    for bit in range(bits - 1, -1, -1):
        piv = None
        for r in range(rank, len(rows)):
            if (rows[r] >> bit) & 1:
                piv = r
                break
        if piv is None:
            continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        for r in range(rank + 1, len(rows)):
            if (rows[r] >> bit) & 1:
                rows[r] ^= rows[rank]
        rank += 1
    return rank


def affine_image_ok(x, val, need_rank=8, bits=16):
    """Generic form: val = A(x) ^ c for some GF(2)-linear A of rank >= need_rank.

    `bits` is the width of `val` (the domain is always the 8-bit index byte).
    need_rank=8, bits=8 is reslib.linear_image_ok; need_rank=8, bits=16 is the
    16-bit-value test; need_rank=1 allows a singular image, which is what a byte
    projection of a 16-bit word is when the corresponding 8x8 block is singular.
    """
    x0, v0 = x[0], val[0]
    mp = {}
    for i in range(256):
        xd = x[i] ^ x0
        vd = val[i] ^ v0
        old = mp.get(xd)
        if old is None:
            mp[xd] = vd
        elif old != vd:
            return False
    if len(mp) != 256:
        return False
    A = [mp.get(1 << j) for j in range(8)]
    if any(a is None for a in A):
        return False
    for xd, vd in mp.items():
        acc = 0
        t = xd
        j = 0
        while t:
            if t & 1:
                acc ^= A[j]
            t >>= 1
            j += 1
        if acc != vd:
            return False
    return rank_of(A, bits) >= need_rank


def affine_image_ok16(x, val, need_rank=8):
    """Is there a GF(2)-linear A: 8 -> 16 bits and a constant c with val = A(x) ^ c?

    Same test reslib.linear_image_ok runs on 8-bit values, with the rank check
    over 16 bits instead of 8 and no invertibility demand (a map into 16 bits
    cannot be invertible; the true one has rank 8).
    """
    x0, v0 = x[0], val[0]
    mp = {}
    for i in range(256):
        xd = x[i] ^ x0
        vd = val[i] ^ v0
        old = mp.get(xd)
        if old is None:
            mp[xd] = vd
        elif old != vd:
            return False
    if len(mp) != 256:
        return False
    A = [mp.get(1 << j) for j in range(8)]
    if any(a is None for a in A):
        return False
    for xd, vd in mp.items():
        acc = 0
        t = xd
        j = 0
        while t:
            if t & 1:
                acc ^= A[j]
            t >>= 1
            j += 1
        if acc != vd:
            return False
    return rank_of(A, 16) == need_rank


def lane_axis(p0i, src, g):
    """x[enc] = S(P0^-1[enc] ^ g): the 8-bit half-round value of one lane.

    One byte in, so the key question is the same as reslib's; the codomain of the
    unknown linear map is 16 bits here instead of 8.
    """
    inv = p0i[src]
    return [S[inv[enc] ^ g] for enc in range(256)]


def lane_vector16(p0i, src, g, lane, rows=(0, 1), M=MC):
    """The 16-bit word a lane actually contributes to two output rows.

    Only used to confirm the model (that the axis is a *linear image* of
    `lane_axis` at the true key); the attack itself never needs MC, because the
    coefficients fold into the unknown linear map.
    """
    out = []
    for u in lane_axis(p0i, src, g):
        w = 0
        for t, r in enumerate(rows):
            w |= wb.gmul(u, M[r][lane]) << (8 * t)
        out.append(w)
    return out


def key_candidates16(val, p0i, src, rows=(0, 1)):
    """All g in 0..255 with `val` an affine image of the lane's half-round.

    `val` is the 16-bit-valued axis of a pair table. Nothing about the 16-bit
    encoding or the MixColumns coefficients is needed: both are linear, so they
    are absorbed into the unknown A: 8 -> 16 bits.
    """
    out = []
    for g in range(256):
        if affine_image_ok16(lane_axis(p0i, src, g), val):
            out.append(g)
    return out


def gauge16_size():
    """|GL(16,2)| * 2^16: what a decomposition of a 16-bit value alphabet leaves."""
    g = 1
    for i in range(16):
        g *= (1 << 16) - (1 << i)
    return g * 65536
