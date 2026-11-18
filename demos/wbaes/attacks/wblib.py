"""Shared code for the dl4 attack scripts: GF(2^8), AES-128, the table layout the
generator writes, the address scatter the runtime uses, and a reader for a shipped
wbaes table section.

Everything here is stdlib only. The functions mirror, line for line, what
demos/wbaes/wbaes_hybrid.h and gen_hybrid.cpp do, because the attacks may only
use what an attacker can read out of the artifact: the Mach-O sections, the
public round-0 input bijection, the mask seed, the schedule block, and (for the
static attack) the unmasked table bytes.
"""

import os
import struct
import sys

# ---- GF(2^8) and AES --------------------------------------------------------
MC = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
IMC = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14))


def xtime(x):
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else (x << 1) & 0xFF


def gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p


def ginv(a):
    """Multiplicative inverse in GF(2^8); ginv(0) = 0 by the AES convention."""
    return gpow(a, 254)


def gpow(a, e):
    r = 1
    while e:
        if e & 1:
            r = gmul(r, a)
        a = gmul(a, a)
        e >>= 1
    return r


def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


SBOX = [0] * 256
for _i in range(256):
    _b = gpow(_i, 254)
    SBOX[_i] = _b ^ rotl8(_b, 1) ^ rotl8(_b, 2) ^ rotl8(_b, 3) ^ rotl8(_b, 4) ^ 0x63
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
assert SBOX[0] == 0x63 and SBOX[1] == 0x7C and len(set(SBOX)) == 256


def aes_key_expand(key):
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


def aes_encrypt(pt, key):
    rk = aes_key_expand(key)
    s = [pt[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[((i & 3) + 4 * (((i >> 2) + (i & 3)) & 3))] for i in range(16)]  # ShiftRows
        if r != 10:
            t = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                for row in range(4):
                    v = 0
                    for k in range(4):
                        v ^= gmul(a[k], MC[row][k])
                    t.append(v)
            s = t
        s = [s[i] ^ rk[r][i] for i in range(16)]
    return bytes(s)


# ---- table geometry (wbaes_hybrid.h) ---------------------------------------
# dl5 layout. One column slot per (direction, round, column):
#   [0, 4096)        F1/F3 lane tables / F2 coefficient tables / F0 pair front
#   [4096, 528384)   F1/F2/F3 eight 64K pair-decode tables
#   [528384, 536576) the 32-bit recoding: 12 forward + 12 inverse S-boxes, 12 constants
#   [536576, 798720) four 64K two-byte boundary tables
HY_MC_ROUNDS = 9
N = 65536
U32 = N * 4
U8 = N
U16 = N * 2
LANE_OFF = 0
Q_OFF = 4096
SPN_OFF = 528384
SPN_ROUNDS = 3
SPN_SI_OFF = 12 * 256
SPN_C_OFF = 24 * 256
SPN_BYTES = 8192
BDY_OFF = SPN_OFF + SPN_BYTES
COL = BDY_OFF + 4 * N                       # 798720
W1024 = 256 * 4
W256 = 256
ROUND = 4 * COL
MC_SIZE = HY_MC_ROUNDS * ROUND
PAIRS = 8 * U16
ENC_BYTES = MC_SIZE + PAIRS
DEC_ENTRY = PAIRS
DEC_STEP = ROUND + PAIRS
DEC_BYTES = DEC_ENTRY + HY_MC_ROUNDS * DEC_STEP + PAIRS
HY_TABLES = ENC_BYTES + DEC_BYTES
SCHED_OFF = HY_TABLES
SCHED_STRIDE = 16
SCHED_BYTES = 64
HY_TOTAL = HY_TABLES + SCHED_BYTES
assert COL == 798720 and HY_TOTAL == 70090816, (COL, HY_TOTAL)

FAM_PAIR, FAM_T32, FAM_T8, FAM_T32K = 0, 1, 2, 3
FAM_W16 = 4                    # the shipped generation: 16-bit column combining
FAM_NAMES = {0: "F0", 1: "F1", 2: "F2", 3: "F3", 4: "F4"}
K_PAIR_L = 0
K_T32_W = 16
K_T8_C = 32
K_T32K_W = 64
K_T32_Q, K_T8_Q, K_T32K_Q = 80, 88, 96
K_SPN_S, K_SPN_SI = 112, 124
K_BDY_PAIR, K_BDY_T32, K_BDY_T8, K_BDY_T32K = 136, 144, 152, 160
K_W16_L, K_W16_D = 200, 208    # F4: four pair tables (16-bit values), four decodes
W16_TAB = U16                  # one pair table: 2^16 entries * 2 B

S4 = (0x6, 0xB, 0x5, 0xC, 0x1, 0xF, 0x0, 0xE, 0x9, 0x2, 0x7, 0xD, 0xA, 0x4, 0x3, 0x8)


# ---- runtime scatter (the address obfuscation) -----------------------------
def hy_env_mix(pagesize, ncpu, cls):
    return (pagesize ^ (ncpu << 16) ^ ((cls * 0x01000193) & 0xFFFFFFFF) ^ 0xA5C31E87) & 0xFFFFFFFF


def hy_f8(x, k, rnd):
    x ^= (k >> ((rnd & 3) * 8)) & 0xFF
    x = (S4[x & 15] << 4) | S4[x >> 4]
    x = (x + (0x3D + rnd * 17)) & 0xFF
    x = ((x << 3) | (x >> 5)) & 0xFF
    x ^= (k >> 16) & 0xFF
    x ^= S4[x >> 4] << 4
    return x & 0xFF


def _tag_key(env, tag):
    return (env ^ ((tag * 0x9E3779B1) & 0xFFFFFFFF) ^ 0xA5C31E87) & 0xFFFFFFFF


def hy_scatter(x, env, tag):
    k = _tag_key(env, tag)
    left, right = x & 255, x >> 8
    for i in range(4):
        left, right = right, left ^ hy_f8(right, k, i)
    return ((left << 8) | right) & 0xFFFF


def hy_scatter_inv(y, env, tag):
    """Inverse of hy_scatter: the four Feistel rounds are undone in reverse, so the
    logical 16-bit index of a 64K table is recoverable from an address exactly."""
    k = _tag_key(env, tag)
    L = (y >> 8) & 0xFF          # hy_scatter packs the *internal* left half high
    R = y & 0xFF
    for i in range(3, -1, -1):
        L, R = R ^ hy_f8(L, k, i), L
    return (L | (R << 8)) & 0xFFFF


def hy_scatter8(x, env, tag):
    k = _tag_key(env, tag)
    return ((((k | 1) & 255) * x) + ((k >> 8) & 255)) & 0xFF


def hy_scatter8_inv(y, env, tag):
    """Inverse of hy_scatter8 for one tag: it is affine mod 256, so this is exact."""
    k = _tag_key(env, tag)
    a = (k | 1) & 255
    b = (k >> 8) & 255
    return ((y - b) * ginv_mod256(a)) & 0xFF


def ginv_mod256(a):
    a &= 255
    for x in range(1, 256):
        if (a * x) & 255 == 1:
            return x
    raise ValueError("not invertible mod 256")


def scatter_table(env, tag):
    """logical -> physical index for one 256-entry table (precomputed, 256 bytes)."""
    return bytes(hy_scatter8(x, env, tag) for x in range(256))


def hy_tag(direction, rnd, col, kind):
    return (direction << 24) | (rnd << 16) | (col << 8) | kind


def sr_src(dst):
    row, col = dst & 3, dst >> 2
    return row + 4 * ((col + row) & 3)


def isr_src(dst):
    row, col = dst & 3, dst >> 2
    return row + 4 * ((col - row + 4) & 3)


def enc_col(rnd, col):
    return rnd * ROUND + col * COL


def enc_final():
    return MC_SIZE


def dec_mc(step):
    return ENC_BYTES + DEC_ENTRY + step * DEC_STEP


# ---- Mach-O reading ---------------------------------------------------------
def find_section(path, want_sect="__hytab"):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\xcf\xfa\xed\xfe":
            endian = "<"
        elif magic == b"\xfe\xed\xfa\xcf":
            endian = ">"
        else:
            raise SystemExit("%s: not a thin 64-bit Mach-O (magic %s)" % (path, magic.hex()))
        f.seek(0)
        hdr = f.read(32)
        _, cputype, _, _, ncmds, sizeofcmds, _, _ = struct.unpack(endian + "IiiIIIII", hdr)
        cmds = f.read(sizeofcmds)
    off = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + "II", cmds, off)
        if cmd == 0x19:
            nsects = struct.unpack_from(endian + "I", cmds, off + 64)[0]
            base = off + 72
            for i in range(nsects):
                s = cmds[base + i * 80: base + (i + 1) * 80]
                if s[:16].rstrip(b"\x00").decode() == want_sect:
                    size = struct.unpack_from(endian + "Q", s, 40)[0]
                    fileoff = struct.unpack_from(endian + "I", s, 48)[0]
                    return fileoff, size
        off += cmdsize
    raise SystemExit("%s: no %s section" % (path, want_sect))


def find_input_bijection(data):
    """HY_P0, 16 permutations of 0..255, emitted by gen_hybrid into __TEXT,__const."""
    coff, csize = find_section_hdr(data, "__const")
    window = data[coff:coff + csize]
    hits = []
    for start in range(0, max(0, csize - 4096) + 1, 8):
        blk = window[start:start + 4096]
        if len(blk) < 4096:
            break
        if all(len(set(blk[i * 256:(i + 1) * 256])) == 256 for i in range(16)):
            hits.append((coff + start, [blk[i * 256:(i + 1) * 256] for i in range(16)]))
    return hits


def find_section_hdr(data, want_sect):
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            for i in range(nsects):
                s = data[off + 72 + i * 80: off + 72 + (i + 1) * 80]
                if s[:16].rstrip(b"\x00").decode() == want_sect:
                    return struct.unpack_from("<I", s, 48)[0], struct.unpack_from("<Q", s, 40)[0]
        off += cmdsize
    raise SystemExit("no %s section" % want_sect)


# ---- data-layer mask --------------------------------------------------------
def mask_next(state):
    x = state
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= x >> 17
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF


def _gf2_mat_mul(A, B, n=32):
    """32x32 GF(2) product with rows as ints (bit j of row i = A[i][j]).
    C row i = XOR of the rows of B selected by the set bits of A row i."""
    out = [0] * n
    for i in range(n):
        acc = 0
        row = A[i]
        while row:
            low = row & -row
            acc ^= B[low.bit_length() - 1]
            row ^= low
        out[i] = acc
    return out


def _xorshift_matrix():
    """One step of the 32-bit xorshift as a GF(2) linear map (rows = output bits)."""
    n = 32
    rows = []
    for i in range(n):
        # three xor-shift stages, applied to a basis vector
        x = 1 << i
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        rows.append(x & 0xFFFFFFFF)
    return rows


_MSTEP = _xorshift_matrix()


def _mat_apply(M, x):
    out = 0
    i = 0
    while x:
        if x & 1:
            out ^= M[i]
        x >>= 1
        i += 1
    return out & 0xFFFFFFFF


def mask_jump(seed, steps):
    """State after `steps` xorshift iterations, without iterating (matrix power)."""
    e = steps
    M = _MSTEP
    acc = None
    while e:
        if e & 1:
            acc = M if acc is None else _gf2_mat_mul(acc, M)
        M = _gf2_mat_mul(M, M)
        e >>= 1
    return _mat_apply(acc if acc is not None else _identity(), seed)


def _identity():
    return [1 << i for i in range(32)]


def unmask_window(masked_at, start, end, seed):
    """Unmask [start, end) of a masked table. `masked_at(i)` returns the ciphertext
    byte at table offset i. The keystream state at `start` is reached by matrix jump,
    so a window anywhere in the 69 MB table costs O(window), not O(start)."""
    st = mask_jump(seed, start)
    out = bytearray(end - start)
    for i in range(start, end):
        st = mask_next(st)
        out[i - start] = masked_at(i) ^ ((st >> 24) & 0xFF)
    return out


def find_mask_seed(binary, tab_off, tab_size):
    """Locate the seed: it is the XOR of four volatile const words next to each other
    in __const (gen_hybrid writes HY_SEED_FRAG[4] that way). Every 16-byte window is
    tried; the test is the schedule block, which must unmask to family bytes 0..3 with
    a matching check byte. Keystream at that offset is reached by matrix jump, so a
    candidate costs microseconds instead of a 69 MB walk."""
    data = open(binary, "rb").read()
    coff, csize = find_section_hdr(data, "__const")
    masked_tail = data[tab_off + SCHED_OFF: tab_off + SCHED_OFF + SCHED_BYTES]

    def at(i):
        return masked_tail[i - SCHED_OFF]
    seen = set()
    for start in range(coff, coff + csize - 16, 4):
        w = struct.unpack_from("<IIII", data, start)
        cand = (w[0] ^ w[1] ^ w[2] ^ w[3]) & 0xFFFFFFFF
        if cand in seen:
            continue
        seen.add(cand)
        plain = unmask_window(at, SCHED_OFF, SCHED_OFF + SCHED_BYTES, cand)
        ok = True
        for d in range(2):
            g = plain[d * SCHED_STRIDE: d * SCHED_STRIDE + HY_MC_ROUNDS + 1]
            # Family bytes: F0..F3 for the eight-bit generations, F4 for the
            # shipped one. A byte outside the set this library names means the
            # candidate seed is wrong (or the artifact is from a newer shape).
            if any(b not in FAM_NAMES for b in g[:HY_MC_ROUNDS]):
                ok = False
                break
            x = d
            for r in range(HY_MC_ROUNDS):
                x ^= g[r]
            if g[HY_MC_ROUNDS] != x:
                ok = False
                break
        if ok:
            return cand, start, len(seen)
    return None, None, len(seen)


def load_plain_table(binary, seed=None, cache=None):
    """Unmask the shipped table section. Returns the plain bytes."""
    if cache and os.path.exists(cache) and os.path.getsize(cache) == HY_TOTAL:
        return open(cache, "rb").read()
    tab_off, tab_size = find_section(binary, "__hytab")
    with open(binary, "rb") as f:
        f.seek(tab_off)
        masked = f.read(tab_size)
    if seed is None:
        seed, _, _ = find_mask_seed(binary, tab_off, tab_size)
        if seed is None:
            raise SystemExit("could not locate the mask seed; pass --seed")
    st = seed
    plain = bytearray(tab_size)
    for i in range(tab_size):
        st = mask_next(st)
        plain[i] = masked[i] ^ ((st >> 24) & 0xFF)
    plain = bytes(plain)
    if cache:
        with open(cache, "wb") as f:
            f.write(plain)
    return plain


# ---- scattered table reads (what the runtime does) -------------------------
class Tab(object):
    def __init__(self, buf, env):
        self.buf = buf
        self.env = env
        self._sc = {}

    def _scatter(self, tag):
        s = self._sc.get(tag)
        if s is None:
            s = scatter_table(self.env, tag)
            self._sc[tag] = s
        return s

    def r32t(self, off, logical, tag):
        a = off + self._scatter(tag)[logical] * 4
        return struct.unpack_from("<I", self.buf, a)[0]

    def r8t(self, off, logical, tag):
        return self.buf[off + self._scatter(tag)[logical]]

    def r8(self, off, logical, tag):
        return self.buf[off + hy_scatter(logical, self.env, tag)]

    def r16(self, off, logical, tag):
        return struct.unpack_from("<H", self.buf, off + hy_scatter(logical, self.env, tag) * 2)[0]

    def r32(self, off, logical, tag):
        return struct.unpack_from("<I", self.buf, off + hy_scatter(logical, self.env, tag) * 4)[0]


# ---- the 32-bit nonlinear recoding (mirror of wbaes_hybrid.h) --------------
# Three rounds of (XOR constant, per-byte bijection, 4x4 MDS mix). The mixing is
# the circulant (1,4,3,7) and its inverse the circulant (11,11,9,8).
MDS_W = (1, 4, 3, 7)
MDS_V = (11, 11, 9, 8)


def mds(y, w=MDS_W):
    t = [0] * 4
    for r in range(4):
        a = 0
        for k in range(4):
            a ^= gmul(y[k], w[(k - r + 4) & 3])
        t[r] = a
    y[:] = t


def spn_fwd(tab, cb, direction, rnd, col, y, env, log=None):
    for i in range(SPN_ROUNDS):
        for j in range(4):
            c = tab.buf[cb + SPN_OFF + SPN_C_OFF + i * 4 + j]
            off = cb + SPN_OFF + (i * 4 + j) * W256
            tag = hy_tag(direction, rnd, col, K_SPN_S + i * 4 + j)
            li = (y[j] ^ c) & 0xFF
            if log is not None:
                log(off + hy_scatter8(li, env, tag), li, 1)
            y[j] = tab.r8t(off, li, tag)
        mds(y)


def spn_inv(tab, cb, direction, rnd, col, y, env, log=None):
    for i in range(SPN_ROUNDS - 1, -1, -1):
        mds(y, MDS_V)
        for j in range(4):
            c = tab.buf[cb + SPN_OFF + SPN_C_OFF + i * 4 + j]
            off = cb + SPN_OFF + SPN_SI_OFF + (i * 4 + j) * W256
            tag = hy_tag(direction, rnd, col, K_SPN_SI + i * 4 + j)
            if log is not None:
                log(off + hy_scatter8(y[j], env, tag), y[j], 1)
            y[j] = tab.r8t(off, y[j], tag) ^ c


def rec_undo(tab, pbase, direction, rnd, state, env, log=None):
    for col in range(4):
        y = state[4 * col:4 * col + 4]
        spn_inv(tab, pbase + col * COL, direction, rnd, col, y, env, log)
        state[4 * col:4 * col + 4] = y


# ---- the table network, with optional access logging ----------------------
def mc_round(tab, base, rnd, direction, src_kind, state, env, log=None):
    """Mirror of hy_mc_round from wbaes_hybrid.h; log receives (offset, logical, width)."""
    fam = tab.buf[SCHED_OFF + direction * SCHED_STRIDE + rnd]
    out = [0] * 16
    for col in range(4):
        cb = base + col * COL
        b = [state[sr_src(k + 4 * col)] if src_kind == 1 else state[k + 4 * col] for k in range(4)]
        bdy = cb + BDY_OFF
        if fam in (FAM_T32, FAM_T32K):
            kw = K_T32K_W if fam == FAM_T32K else K_T32_W
            qb = K_T32K_Q if fam == FAM_T32K else K_T32_Q
            bk = K_BDY_T32K if fam == FAM_T32K else K_BDY_T32
            w = [0] * 4
            for k in range(4):
                off = cb + k * W1024
                tag = hy_tag(direction, rnd, col, kw + k)
                if log is not None:
                    log(off + tab._scatter(tag)[b[k]] * 4, b[k], 4)
                w[k] = tab.r32t(off, b[k], tag)
            for row in range(4):
                a = [(w[k] >> (8 * row)) & 255 for k in range(4)]
                off = cb + Q_OFF + (2 * row) * N
                tag = hy_tag(direction, rnd, col, qb + 2 * row)
                li = a[0] | (a[1] << 8)
                if log is not None:
                    log(off + hy_scatter(li, env, tag), li, 1)
                pl = tab.r8(off, li, tag)
                off = cb + Q_OFF + (2 * row + 1) * N
                tag = hy_tag(direction, rnd, col, qb + 2 * row + 1)
                li = a[2] | (a[3] << 8)
                if log is not None:
                    log(off + hy_scatter(li, env, tag), li, 1)
                pr = tab.r8(off, li, tag)
                off = bdy + row * N
                tag = hy_tag(direction, rnd, col, bk + row)
                li = pl | (pr << 8)
                if log is not None:
                    log(off + hy_scatter(li, env, tag), li, 1)
                out[row + 4 * col] = tab.r8(off, li, tag)
        elif fam == FAM_T8:
            v = [[0] * 4 for _ in range(4)]
            for k in range(4):
                for row in range(4):
                    off = cb + (k * 4 + row) * W256
                    tag = hy_tag(direction, rnd, col, K_T8_C + k * 4 + row)
                    if log is not None:
                        log(off + tab._scatter(tag)[b[k]], b[k], 1)
                    v[k][row] = tab.r8t(off, b[k], tag)
            for row in range(4):
                off = cb + Q_OFF + (2 * row) * N
                tag = hy_tag(direction, rnd, col, K_T8_Q + 2 * row)
                li = v[0][row] | (v[1][row] << 8)
                if log is not None:
                    log(off + hy_scatter(li, env, tag), li, 1)
                pl = tab.r8(off, li, tag)
                off = cb + Q_OFF + (2 * row + 1) * N
                tag = hy_tag(direction, rnd, col, K_T8_Q + 2 * row + 1)
                li = v[2][row] | (v[3][row] << 8)
                if log is not None:
                    log(off + hy_scatter(li, env, tag), li, 1)
                pr = tab.r8(off, li, tag)
                off = bdy + row * N
                tag = hy_tag(direction, rnd, col, K_BDY_T8 + row)
                li = pl | (pr << 8)
                if log is not None:
                    log(off + hy_scatter(li, env, tag), li, 1)
                out[row + 4 * col] = tab.r8(off, li, tag)
        else:
            off = cb
            tag = hy_tag(direction, rnd, col, K_PAIR_L)
            li = b[0] | (b[1] << 8)
            if log is not None:
                log(off + hy_scatter(li, env, tag) * 4, li, 4)
            left = tab.r32(off, li, tag)
            off = cb + U32
            tag = hy_tag(direction, rnd, col, K_PAIR_L + 1)
            li = b[2] | (b[3] << 8)
            if log is not None:
                log(off + hy_scatter(li, env, tag) * 4, li, 4)
            right = tab.r32(off, li, tag)
            for row in range(4):
                pl = (left >> (8 * row)) & 255
                pr = (right >> (8 * row)) & 255
                off = bdy + row * N
                tag = hy_tag(direction, rnd, col, K_BDY_PAIR + row)
                li = pl | (pr << 8)
                if log is not None:
                    log(off + hy_scatter(li, env, tag), li, 1)
                out[row + 4 * col] = tab.r8(off, li, tag)
        y = out[4 * col:4 * col + 4]
        spn_fwd(tab, cb, direction, rnd, col, y, env, log)
        out[4 * col:4 * col + 4] = y
    return out


def pair_map(tab, base, state, env, direction, rnd, wiring, log=None):
    out = [0] * 16
    for p in range(8):
        i0, i1 = p * 2, p * 2 + 1
        s0, s1 = i0, i1
        if wiring == 1:
            s0, s1 = sr_src(i0), sr_src(i1)
        elif wiring == 2:
            s0, s1 = isr_src(i0), isr_src(i1)
        off = base + p * U16
        tag = hy_tag(direction, rnd, p, 16 + wiring)
        li = state[s0] | (state[s1] << 8)
        if log is not None:
            log(off + hy_scatter(li, env, tag) * 2, li, 2)
        w = tab.r16(off, li, tag)
        out[i0] = w & 255
        out[i1] = (w >> 8) & 255
    return out


def encrypt(tab, p0, pt, env, log=None):
    s = [p0[i][pt[i]] for i in range(16)]
    for r in range(HY_MC_ROUNDS):
        if r:
            rec_undo(tab, enc_col(r - 1, 0), 0, r - 1, s, env, log)
        s = mc_round(tab, enc_col(r, 0), r, 0, 1, s, env, log)
    rec_undo(tab, enc_col(HY_MC_ROUNDS - 1, 0), 0, HY_MC_ROUNDS - 1, s, env, log)
    return bytes(pair_map(tab, enc_final(), s, env, 0, 9, 1, log))


# ---- trace file (same layout as trace_harness.cpp) ------------------------
REC = struct.Struct("<III")


def write_traces(path, traces, pts):
    with open(path, "wb") as f:
        for recs in traces:
            f.write(struct.pack("<I", len(recs)))
            f.write(b"".join(REC.pack(*r) for r in recs))
    with open(path + ".pts", "wb") as f:
        for pt in pts:
            f.write(bytes(pt))


def read_traces(path, pts_path=None):
    raw = open(path, "rb").read()
    off = 0
    traces = []
    while off < len(raw):
        n = struct.unpack_from("<I", raw, off)[0]
        off += 4
        traces.append([REC.unpack_from(raw, off + REC.size * i) for i in range(n)])
        off += REC.size * n
    pts = []
    pp = pts_path or path + ".pts"
    if not os.path.exists(pp) and path.endswith("_traces.bin"):
        pp = path[:-len("_traces.bin")] + "_pts.bin"
    if os.path.exists(pp):
        b = open(pp, "rb").read()
        pts = [b[16 * i:16 * i + 16] for i in range(len(b) // 16)]
    return traces, pts


def prng_pts(n, seed=0x12345678, skip=0):
    """Same plaintext stream the C harness writes: xorshift32, one byte per draw."""
    out = []
    st = seed
    for _ in range(skip):
        for _ in range(16):
            st ^= (st << 13) & 0xFFFFFFFF
            st ^= st >> 17
            st ^= (st << 5) & 0xFFFFFFFF
            st &= 0xFFFFFFFF
    for _ in range(n):
        pt = bytearray(16)
        for i in range(16):
            st ^= (st << 13) & 0xFFFFFFFF
            st ^= st >> 17
            st ^= (st << 5) & 0xFFFFFFFF
            st &= 0xFFFFFFFF
            pt[i] = (st >> 16) & 0xFF
        out.append(bytes(pt))
    return out


DEFAULT_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "..", "exported-binaries", "wbaes-challenge",
                           "macos", "wbaes_vm2_clean")
DEFAULT_ENV = (16384, 10, 128)   # hw.pagesize/hw.ncpu/hw.cachelinesize on the build host
