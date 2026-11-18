"""Shared code for the four residual attacks on the dl5 artifact (wbaes_nl_clean).

Everything here only uses what an offline attacker can read out of the artifact —
the masked table section, the public round-0 input bijection P0, the mask seed —
plus the algebra that the artifact's own construction implies. Nothing in
demos/wbaes is imported at runtime except the constants the attack scripts already
use; the round function is re-derived from the table bytes, not from the generator.

The one piece of real mathematics in here is the decomposition of a 64K
pair-decode table. dl5 builds

    Q[a][b] = Z( D0[a] ^ D1[b] )            Z, D0, D1 random bijections

and claims that Z hides D0/D1 (WB-DESIGN-V2.md 12.4 item 1: "hidden shift,
not implemented, not claimed unsolved"). The structural fact used below:

  * every row  f_a(.) = Q[a][.]  is a permutation of the 256 output values, so
  * lam_a = f_a o f_0^-1  is well defined and
    lam_a(y) = Z( Z^-1(y) ^ (D0[a] ^ D0[0]) ),
  * therefore LAM = {lam_a} is a group of 256 involutions acting regularly on the
    output set, isomorphic to (Z2)^8, and every element of it is *known* from Q,

so the labelling D0[a] ^ D0[0] (resp. D1[b] ^ D1[0]) is recoverable up to an
automorphism of (Z2)^8 and a translation -- the "gauge" of the hidden shift.
The key test in hs_attack.py is invariant under exactly that gauge, which is why
the gauge can be left unknown (see hs_attack.py for the argument and the numbers).
"""

import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import wblib as wb

CHALLENGE_KEY = "4f065a03ee16cf8c31b15fd8f0344c66"
CHALLENGE_PT = "6bc1bee22e409f96e93d7e117393172a"
CHALLENGE_CT = "7672415a6313c58518fc95c9cb6922b8"


# ---------------------------------------------------------------------------
# GF(2^8) helpers with lookup tables, so the per-candidate tests stay cheap.
MUL = {m: [wb.gmul(i, m) for i in range(256)] for m in (1, 2, 3, 9, 11, 13, 14)}


def gmul_tab(m):
    t = MUL.get(m)
    if t is None:
        t = MUL[m] = [wb.gmul(i, m) for i in range(256)]
    return t


def p0_inverse(p0):
    """p0 is [16][256]: P0[i][pt] -> table index. Return the inverse mapping."""
    p0i = [[0] * 256 for _ in range(16)]
    for i in range(16):
        for v in range(256):
            p0i[i][p0[i][v]] = v
    return p0i


# ---------------------------------------------------------------------------
# artifact loading: Mach-O (shipped challenge) or a raw generated table
class Artifact(object):
    def __init__(self, tab, env, p0, label, seed=None, schedule=None):
        self.tab = tab                # unmasked table bytes (70,090,816)
        self.env = env
        self.p0 = p0                  # [16][256]
        self.p0i = p0_inverse(p0)
        self.label = label
        self.seed = seed
        self.schedule = schedule or [tab[wb.SCHED_OFF + r] for r in range(wb.HY_MC_ROUNDS)]
        self.tab_obj = wb.Tab(tab, env)

    def fam(self, rnd, direction=0):
        return self.schedule[rnd] if direction == 0 else self.tab[wb.SCHED_OFF + 16 + rnd]


def load_shipped(path=None, seed=None, cache=None, env_args=wb.DEFAULT_ENV):
    path = path or wb.DEFAULT_BIN
    env = wb.hy_env_mix(*env_args)
    t0 = time.time()
    if seed is None:
        seed, _frag, tried = wb.find_mask_seed(path, *wb.find_section(path, "__hytab"))
    tab = wb.load_plain_table(path, seed=seed, cache=cache)
    data = open(path, "rb").read()
    p0 = wb.find_input_bijection(data)[0][1]
    art = Artifact(tab, env, p0, path, seed)
    return art, time.time() - t0


PY_IN_H = re.compile(r"static const unsigned char HY_P0\[16\]\[256\] = \{(.*?)\n\};", re.S)
PY_SEAL = re.compile(r"HY_SEED_FRAG\[4\] = \{([^}]*)\}")


def load_variant(table_path, workdir, env_args=wb.DEFAULT_ENV, total=None):
    """Load a table written by a *modified* generator (a variant experiment) whose
    HY_TOTAL differs from the shipped one.

    Same inputs as load_generated -- the masked table plus the hy_in.h (round-0
    input bijection) and hy_seal.h (four seed words) the generator wrote next to
    it -- but the length check is taken from the file (or `total`) instead of
    wblib.HY_TOTAL, because a variant may append table regions. Every shipped
    offset is unchanged in the variants under attacks/residual/, so the readers in
    this module keep working.
    """
    env = wb.hy_env_mix(*env_args)
    masked = open(table_path, "rb").read()
    if total is not None and len(masked) != total:
        raise SystemExit("%s: %d bytes, expected %d" % (table_path, len(masked), total))
    in_h = open(os.path.join(workdir, "hy_in.h")).read()
    m = PY_IN_H.search(in_h)
    if not m:
        raise SystemExit("no HY_P0 block in %s/hy_in.h" % workdir)
    vals = [int(x) for x in re.findall(r"\d+", m.group(1))]
    if len(vals) != 16 * 256:
        raise SystemExit("HY_P0 block has %d values" % len(vals))
    p0 = [vals[256 * i:256 * (i + 1)] for i in range(16)]
    seal = open(os.path.join(workdir, "hy_seal.h")).read()
    words = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", PY_SEAL.search(seal).group(1))]
    seed = words[0] ^ words[1] ^ words[2] ^ words[3]
    tab = bytearray(masked)
    st = seed
    for i in range(len(tab)):
        st = wb.mask_next(st)
        tab[i] ^= (st >> 24) & 0xFF
    return Artifact(bytes(tab), env, p0, table_path, seed), seed


def load_generated(table_path, workdir, env_args=wb.DEFAULT_ENV):
    """Load an artifact written by gen_hybrid.cpp directly (not in a Mach-O).

    gen_hybrid also writes hy_in.h (the P0 bijection) and hy_seal.h (the four seed
    words, whose XOR is the mask seed) next to the table, so both are read from
    the scratch directory it ran in.
    """
    env = wb.hy_env_mix(*env_args)
    tab = bytearray(open(table_path, "rb").read())
    if len(tab) != wb.HY_TOTAL:
        raise SystemExit("%s: %d bytes, expected %d" % (table_path, len(tab), wb.HY_TOTAL))
    in_h = open(os.path.join(workdir, "hy_in.h")).read()
    m = PY_IN_H.search(in_h)
    if not m:
        raise SystemExit("no HY_P0 block in %s/hy_in.h" % workdir)
    vals = [int(x) for x in re.findall(r"\d+", m.group(1))]
    if len(vals) != 16 * 256:
        raise SystemExit("HY_P0 block has %d values" % len(vals))
    p0 = [vals[256 * i:256 * (i + 1)] for i in range(16)]
    seal = open(os.path.join(workdir, "hy_seal.h")).read()
    words = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", PY_SEAL.search(seal).group(1))]
    seed = words[0] ^ words[1] ^ words[2] ^ words[3]
    st = seed
    for i in range(len(tab)):
        st = wb.mask_next(st)
        tab[i] ^= (st >> 24) & 0xFF
    return Artifact(bytes(tab), env, p0, table_path, seed)


# ---------------------------------------------------------------------------
# one 64K pair-decode table
def q_read(art, col, row, pair, round=0, direction=0):
    """Read Q[row][col][pair] (64K bytes) as Q[a][b], a = low index byte."""
    qk = wb.K_T32_Q if art.fam(round, direction) == wb.FAM_T32 else wb.K_T32K_Q
    off = wb.enc_col(round, col) + wb.Q_OFF + (2 * row + pair) * wb.N
    tag = wb.hy_tag(direction, round, col, qk + 2 * row + pair)
    r8 = art.tab_obj.r8
    return [bytes(r8(off, a | (b << 8), tag) for b in range(256)) for a in range(256)]


def lane_word(art, col, k, round=0, direction=0):
    """The 256 32-bit lane words of round 0 for lane k of a column."""
    kw = wb.K_T32_W if art.fam(round, direction) == wb.FAM_T32 else wb.K_T32K_W
    off = wb.enc_col(round, col) + k * wb.W1024
    tag = wb.hy_tag(direction, round, col, kw + k)
    return [art.tab_obj.r32t(off, enc, tag) for enc in range(256)]


# ---------------------------------------------------------------------------
# the hidden-shift decomposition of one Q table
class Decomp(object):
    """Q[a][b] = Z(D0[a] ^ D1[b])  ->  da[a], db[b] (D-values up to gauge), zf.

    da/db are byte labels valid up to an automorphism of (Z2)^8 and a translation,
    i.e. da = B(D0[a] ^ t) for an unknown linear bijection B and constant t. That
    is all Q can determine: (Z, D0, D1) -> (Z o A^-1, A o D0, A o D1) leaves Q
    unchanged for every A in GL(8, 2), and (D0 ^ t, D1 ^ t) does too.
    """

    def __init__(self, Q, keep_maps=False):
        rows = Q
        for a in range(256):
            if len(set(rows[a])) != 256:
                raise ValueError("row %d is not a permutation" % a)
        f0inv = [0] * 256
        for b, v in enumerate(rows[0]):
            f0inv[v] = b
        lam = [bytes(rows[a][f0inv[y]] for y in range(256)) for a in range(256)]
        idx = {}
        for a, p in enumerate(lam):
            idx[p] = a
        if len(idx) != 256:
            raise ValueError("lam is not injective (Q is not Z(D0[a]^D1[b]))")
        # the 256 lam's act regularly on the value set: v_a = lam_a(v0)
        v = [lam[a][0] for a in range(256)]
        if len(set(v)) != 256:
            raise ValueError("the lam action is not regular")
        invv = [0] * 256
        for a in range(256):
            invv[v[a]] = a

        def mul(a, b):
            return invv[lam[a][v[b]]]

        self.lam, self.idx, self.mul = lam, idx, mul
        ident = idx[bytes(range(256))]
        # basis of the group generated by the lam's: aS is a coset, so the
        # closure of S u {a} is S | aS and the check is O(|S|).
        S = {ident}
        basis = []
        for a in range(256):
            if a in S:
                continue
            coset = set(mul(a, s) for s in S)
            if coset - S:
                S |= coset
                basis.append(a)
        if len(S) != 256 or len(basis) != 8:
            raise ValueError("group is not (Z2)^8: |S|=%d basis=%d" % (len(S), len(basis)))
        coords = {ident: 0}
        for i, b in enumerate(basis):
            coords[b] = 1 << i
        frontier = list(coords)
        while frontier:
            nxt = []
            for x in frontier:
                for i, b in enumerate(basis):
                    z = mul(x, b)
                    if z not in coords:
                        coords[z] = coords[x] ^ (1 << i)
                        nxt.append(z)
            frontier = nxt
        if len(coords) != 256 or len(set(coords.values())) != 256:
            raise ValueError("coordinate map failed")
        self.basis = basis
        self.da = [coords[a] for a in range(256)]
        # the b axis: column permutations, mapped into the same group
        c0 = [rows[a][0] for a in range(256)]
        invc = [0] * 256
        for a, val in enumerate(c0):
            invc[val] = a
        db = []
        for b in range(256):
            mu = bytes(rows[invc[y]][b] for y in range(256))
            i = idx.get(mu)
            if i is None:
                raise ValueError("column map %d is not in the same group" % b)
            db.append(coords[i])
        self.db = db
        self.zf = self._rebuild(Q) if True else None
        self.ok = self.zf is not None and len(set(self.zf)) == 256
        if keep_maps:
            self.z_forward = {self.da[a] ^ self.db[b]: Q[a][b] for a in range(256) for b in range(256)}

    def _rebuild(self, Q):
        """Check Q[a][b] == Z(da[a] ^ db[b]) for one bijection Z, return Z."""
        z = [None] * 256
        for a in range(256):
            for b in range(256):
                k = self.da[a] ^ self.db[b]
                val = Q[a][b]
                if z[k] is None:
                    z[k] = val
                elif z[k] != val:
                    return None
        if any(x is None for x in z):
            return None
        return z

    def d_for(self, axis):
        return self.da if axis == 0 else self.db


# ---------------------------------------------------------------------------
# the key test: is `val` an affine image of the AES half-round for candidate g?
def linear_image_ok(x, val, need_invertible=True):
    """Does a GF(2)-linear map A (plus a constant) satisfy val = A(x) ^ const?

    `x` and `val` are 256-entry byte arrays indexed by the table's index byte.
    The gauge of the hidden shift is exactly an outer linear map on the lane
    values, so allowing an arbitrary A here makes the test gauge invariant.
    """
    x0 = x[0]
    v0 = val[0]
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
    if need_invertible:
        # the map on the 8 basis images must be independent
        rows = list(A)
        rank = 0
        for bit in range(7, -1, -1):
            piv = None
            for r in range(rank, 8):
                if rows[r] >> bit & 1:
                    piv = r
                    break
            if piv is None:
                continue
            rows[rank], rows[piv] = rows[piv], rows[rank]
            for r in range(8):
                if r != rank and (rows[r] >> bit & 1):
                    rows[r] ^= rows[rank]
            rank += 1
        if rank != 8:
            return False
    return True


def half_round_values(p0i, src, g, m, precomputed=None):
    """x[enc] = m * S(P0^-1[enc] ^ g) for one lane: the known-form function."""
    sm = MUL[m]
    inv = p0i[src]
    return [sm[wb.SBOX[inv[enc] ^ g]] for enc in range(256)]


def key_candidates(val, p0i, src, m):
    """All g in 0..255 with val an affine image of m*S(P0^-1(enc) ^ g)."""
    out = []
    for g in range(256):
        x = half_round_values(p0i, src, g, m)
        if linear_image_ok(x, val):
            out.append(g)
    return out


def gauge_size():
    """|GL(8,2)| * 2^8 - the number of (Z, D0, D1) triples Q cannot tell apart."""
    g = 1
    for i in range(8):
        g *= (1 << 8) - (1 << i)
    return g * 256


def round0_peel(art):
    """Full residual attack (a) on one artifact: decompose all 32 Q tables, then one
    gauge-invariant key test per (column, lane, row) byte position.

    Returns a dict with the decompositions, the candidate sets and the key (or None).
    """
    dec = {}
    for col in range(4):
        for row in range(4):
            for p in range(2):
                dec[(col, row, p)] = Decomp(q_read(art, col, row, p))
    cand_counts = []
    per_byte = {}
    detail = {}
    for col in range(4):
        for k in range(4):
            src = wb.sr_src(k + 4 * col)
            words = lane_word(art, col, k)
            detail[(col, k)] = []
            for row in range(4):
                dd = dec[(col, row, k // 2)].d_for(k % 2)
                val = [dd[(words[enc] >> (8 * row)) & 255] for enc in range(256)]
                cands = key_candidates(val, art.p0i, src, wb.MC[row][k])
                cand_counts.append(len(cands))
                detail[(col, k)].append((row, cands))
                if len(cands) == 1:
                    per_byte.setdefault(src, set()).add(cands[0])
    key = None
    if len(per_byte) == 16 and all(len(s) == 1 for s in per_byte.values()):
        key = bytes(next(iter(per_byte[i])) for i in range(16))
    return {"dec": dec, "cand": cand_counts, "per_byte": per_byte,
            "detail": detail, "key": key}


# ---------------------------------------------------------------------------
# address traces: recover the logical two-byte index of a 64K table
def trace_addresses(path):
    traces, pts = wb.read_traces(path)
    return [[r[0] for r in tr] for tr in traces], pts


def logical_index(addrs, base, size, env, tag):
    """Invert the runtime scatter of one 64K table, per trace."""
    out = []
    for tr in addrs:
        hit = None
        for a in tr:
            if base <= a < base + size:
                hit = a
                break
        if hit is None:
            raise SystemExit("table at 0x%x not touched by a trace" % base)
        out.append(wb.hy_scatter_inv(hit - base, env, tag) if size == wb.N else (hit - base))
    return out


def boundary_halves(art_or_env, addrs, col, row, round=0, direction=0, kind=None):
    env = art_or_env if isinstance(art_or_env, int) else art_or_env.env
    if kind is None:
        kind = wb.K_BDY_T32
    base = wb.enc_col(round, col) + wb.BDY_OFF + row * wb.N
    tag = wb.hy_tag(direction, round, col, kind + row)
    li = logical_index(addrs, base, wb.N, env, tag)
    return [x & 255 for x in li], [x >> 8 for x in li]
