#!/usr/bin/env python3
"""Recover the white-box AES-128 key from a baked Polaris demo binary.

Reads only the shipped Mach-O. The generated table blob lives in the
__DATA,__hytab section; round 0 of that blob bakes

    entry[col,side][x,y][row] = Q[col,row,side]( S(x ^ k0) ^ S(y ^ k1) )

with k0/k1 two bytes of the master key (round 0 uses the master key directly and
has no input encoding), so every 64K entry table is a Latin square isotopic to
XOR. Grouping the entries by S(x^k0) ^ S(y^k1) for a candidate pair must yield a
constant encoded byte per group; the reference-pair identity

    B[1][y] == B[0][y']   where   S(y'^k1) = S(y^k1) ^ delta,  delta = S(k0)^S(1^k0)

turns that into a 256x256 search, and a second pair (0,2) removes the residual
k0 ambiguity.

dl3 added byte-indexed families (F1/F2/F3) and a round-family schedule at the end
of the table; the round-0 attack became a direct read: the table row held
MC[row][k]*S(x^k) verbatim, so MixColumns' coefficient 1 handed over the key byte
after one inverse S-box (recover_key_tbox). dl4 keeps every lane but puts a random
256-element bijection on it and its inverse inside a 64K decode table, so no
single row is MC[row][k]*S(x^k) any more and this tool's one-table test has
nothing to recognise; it stops with a message saying so instead of guessing.

    extract_key.py <baked-binary>                 # print the key
    extract_key.py <baked-binary> --verify        # also re-run the binary's
                                                  # self-test and compare with
                                                  # a local AES-128-ECB result

Stdlib only: no numpy, no Ghidra, no project headers.
"""

import argparse
import hashlib
import struct
import subprocess
import sys

# ---- layout constants (wbaes_hybrid.h) -------------------------------------
HY_MC_ROUNDS = 9
N = 65536
U32 = N * 4
U8 = N
U16 = N * 2
COL = U32 + U32 + 4 * U8
ROUND = 4 * COL
MC_SIZE = HY_MC_ROUNDS * ROUND
PAIRS = 8 * U16
ENC_BYTES = MC_SIZE + PAIRS
DEC_ENTRY = PAIRS
DEC_STEP = ROUND + PAIRS
DEC_BYTES = DEC_ENTRY + HY_MC_ROUNDS * DEC_STEP + PAIRS
HY_TABLES = ENC_BYTES + DEC_BYTES  # 69_206_016

# dl3 adds a round-family schedule block after the tables: one family byte per
# (direction, round) plus a check byte, sealed and masked with the rest.
SCHED_OFF = HY_TABLES
SCHED_STRIDE = 16
SCHED_BYTES = 64
HY_TOTAL = HY_TABLES + SCHED_BYTES  # 69_206_080; dl/dl2 lacked the block

FAM_PAIR, FAM_T32, FAM_T8, FAM_T32K = 0, 1, 2, 3
K_T32_W, K_T32_R = 16, 20
K_T8_C, K_T8_R = 32, 48
K_T32K_W = 64
W1024 = 256 * 4
W256 = 256

MC = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
S4 = (0x6, 0xB, 0x5, 0xC, 0x1, 0xF, 0x0, 0xE, 0x9, 0x2, 0x7, 0xD, 0xA, 0x4, 0x3, 0x8)


def xtime(x):
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else (x << 1) & 0xFF


def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = xtime(a)
        b >>= 1
    return p


def rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def gf_inv(x):
    """x^-1 = x^254 = x^128 * x^64 * x^32 * x^16 * x^8 * x^4 * x^2 (gen_hybrid.cpp chain)."""
    if not x:
        return 0
    x2 = gmul(x, x)
    x4 = gmul(x2, x2)
    x8 = gmul(x4, x4)
    x16 = gmul(x8, x8)
    x32 = gmul(x16, x16)
    x64 = gmul(x32, x32)
    x128 = gmul(x64, x64)
    p = gmul(x128, x64)
    for t in (x32, x16, x8, x4, x2):
        p = gmul(p, t)
    return p


SBOX = [gf_inv(i) ^ rotl8(gf_inv(i), 1) ^ rotl8(gf_inv(i), 2) ^ rotl8(gf_inv(i), 3)
        ^ rotl8(gf_inv(i), 4) ^ 0x63 for i in range(256)]
assert len(set(SBOX)) == 256 and SBOX[0] == 0x63 and SBOX[1] == 0x7C, "S-box chain broken"


# ---- table readers (wbaes_hybrid.h) ----------------------------------------
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


def hy_scatter(x, env, tag):
    k = (env ^ ((tag * 0x9E3779B1) & 0xFFFFFFFF) ^ 0xA5C31E87) & 0xFFFFFFFF
    left, right = x & 255, x >> 8
    for i in range(4):
        left, right = right, left ^ hy_f8(right, k, i)
    return ((left << 8) | right) & 0xFFFF


def hy_tag(direction, rnd, col, kind):
    return (direction << 24) | (rnd << 16) | (col << 8) | kind


def hy_sr_src(dst):
    row, col = dst & 3, dst >> 2
    return row + 4 * ((col + row) & 3)


# ---- Mach-O section lookup ------------------------------------------------
def find_section(path, want_sect="__hytab"):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\xcf\xfa\xed\xfe":
            endian = "<"
        elif magic == b"\xfe\xed\xfa\xcf":
            endian = ">"
        else:
            raise SystemExit(f"{path}: not a thin 64-bit Mach-O (magic {magic.hex()})")
        f.seek(0)
        hdr = f.read(32)
        _, cputype, _, _, ncmds, sizeofcmds, _, _ = struct.unpack(endian + "IiiIIIII", hdr)
        cmds = f.read(sizeofcmds)
    off = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + "II", cmds, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = struct.unpack_from(endian + "I", cmds, off + 64)[0]
            base = off + 72
            for i in range(nsects):
                s = cmds[base + i * 80: base + (i + 1) * 80]
                sectname = s[:16].rstrip(b"\x00").decode()
                if sectname == want_sect:
                    segname = s[16:32].rstrip(b"\x00").decode()
                    size = struct.unpack_from(endian + "Q", s, 40)[0]
                    fileoff = struct.unpack_from(endian + "I", s, 48)[0]
                    return cputype, segname, sectname, fileoff, size
        off += cmdsize
    raise SystemExit(f"{path}: no {want_sect} section found")


# ---- key recovery ---------------------------------------------------------
def read_row(table, env, col, side, row, reader=None):
    """64K entries of one round-0 (col,side) table, one output row, as B[x*256+y].

    The logical index in the table is x | (y << 8), so it is unpacked into the
    x-major layout the recovery expects. `reader` supplies table bytes, which is
    how a data-layer-masked build is read: only the offsets the recovery touches
    ever get unmasked.
    """
    rd = reader if reader is not None else table.__getitem__
    base = col * COL + (U32 if side else 0)
    tag = hy_tag(0, 0, col, side)
    out = bytearray(N)
    for logical in range(N):
        p = base + hy_scatter(logical, env, tag) * 4
        x = logical & 255
        y = logical >> 8
        out[x * 256 + y] = rd(p + row)
    return out


# ---- dl3: rounds whose tables are indexed by one byte ----------------------
def hy_scatter8(x, env, tag):
    """wbaes_hybrid.h hy_scatter8: odd multiplier mod 256, positions permuted per tag."""
    k = (env ^ ((tag * 0x9E3779B1) & 0xFFFFFFFF) ^ 0xA5C31E87) & 0xFFFFFFFF
    return ((((k | 1) & 255) * x) + ((k >> 8) & 255)) & 0xFF


def round_base(direction, rnd):
    if direction == 0:
        return rnd * ROUND
    return ENC_BYTES + DEC_ENTRY + rnd * DEC_STEP


def sched_family(get, direction, rnd):
    """The family byte the generator wrote for this (direction, round)."""
    return get(SCHED_OFF + direction * SCHED_STRIDE + rnd)


def read_wide_row(get, env, direction, rnd, col, k, kind_base, row):
    """One output row of a 256-entry 32-bit table, indexed by the encoded byte."""
    off = round_base(direction, rnd) + col * COL + k * W1024
    tag = hy_tag(direction, rnd, col, kind_base + k)
    return [get(off + hy_scatter8(enc, env, tag) * 4 + row) for enc in range(256)]


def read_t8_row(get, env, direction, rnd, col, k, row):
    """One 256-entry coefficient byte table (F2): MC[row][k] * S(clear)."""
    off = round_base(direction, rnd) + col * COL + (k * 4 + row) * W256
    tag = hy_tag(direction, rnd, col, K_T8_C + k * 4 + row)
    return [get(off + hy_scatter8(enc, env, tag)) for enc in range(256)]


INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def tbox_rows(get, env, direction, rnd, col, k, fam):
    """The four output rows of the table that source k feeds, indexed by enc byte."""
    if fam == FAM_T8:
        return [read_t8_row(get, env, direction, rnd, col, k, row) for row in range(4)]
    kb = K_T32_W if fam == FAM_T32 else K_T32K_W
    return [read_wide_row(get, env, direction, rnd, col, k, kb, row) for row in range(4)]


def recover_key_tbox(get, env, p0, fam):
    """Round-0 byte-indexed tables hand over the key; no search is needed.

    F1/F2 store MC[row][k] * S(P0i[enc] ^ key). MixColumns has a 1 in every row,
    so one output row per source returns S(x ^ k) verbatim: undo the round-0
    input bijection, apply the inverse S-box, and the key byte is immediate. The
    other three rows then have to agree on all 256 entries or the table is not
    the one we think it is.

    F3 multiplies every lane by its affine output encoding as well, so its rows
    are a * scalar ^ offset away from S(x ^ k); solving that is not implemented.
    """
    if fam == FAM_T32K:
        raise SystemExit("round 0 is FAM_T32K: lanes carry an affine scalar")
    if p0 is None:
        raise SystemExit("round 0 is byte-indexed: HY_P0 is needed to undo the input bijection")
    key = bytearray(16)
    for col in range(4):
        for k in range(4):
            src = hy_sr_src(k + 4 * col)
            rows = tbox_rows(get, env, 0, 0, col, k, fam)
            one = 2 if k < 2 else 0  # MC[2][0]=MC[2][1]=1, MC[0][2]=MC[0][3]=1
            key[src] = INV_SBOX[rows[one][p0[src][0]]]
            for row in range(4):
                m = MC[row][k]
                for a in range(256):
                    if rows[row][p0[src][a]] != gmul(m, SBOX[a ^ key[src]]):
                        raise SystemExit(
                            f"t-box mismatch col {col} k {k} row {row} x {a:02x}: "
                            "table is not MC[row][k]*S(x^k) - a dl4 build re-encodes "
                            "every lane through its own random bijection, and this "
                            "one-table test cannot undo that")
    return bytes(key)


def relabel(B, p0_0, p0_1):
    """Undo a round-0 input bijection: B'[a][b] = B[P0[a]][P0[b]]."""
    out = bytearray(N)
    for a in range(256):
        base = p0_0[a] * 256
        row = a * 256
        for b in range(256):
            out[row + b] = B[base + p0_1[b]]
    return out


def find_input_bijection(data):
    """Locate HY_P0 (16 x 256 permutations) emitted by gen_hybrid into __TEXT,__const."""
    hits = []
    try:
        _, _, _, coff, csize = find_section_bytes(data, "__const")
    except SystemExit:
        return hits
    window = data[coff:coff + csize]
    for start in range(0, max(0, csize - 4096) + 1):
        blk = window[start:start + 4096]
        if len(blk) < 4096:
            break
        if all(len(set(blk[i * 256:(i + 1) * 256])) == 256 for i in range(16)):
            hits.append((coff + start, [blk[i * 256:(i + 1) * 256] for i in range(16)]))
    return hits


def fnv1a16(key):
    """hy_mask_seed(): the data-layer mask seed is FNV-1a over the 16 key bytes."""
    h = 2166136261
    for b in key:
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h or 0x9E3779B9


def make_reader(table, seed):
    """XOR-keystream reader for a data-layer-masked table (xorshift32, seed = FNV(key))."""
    if seed is None:
        return None
    st = seed & 0xFFFFFFFF
    ks = bytearray()

    def get(i):
        nonlocal st
        while len(ks) <= i:
            x = st
            x ^= (x << 13) & 0xFFFFFFFF
            x ^= x >> 17
            x ^= (x << 5) & 0xFFFFFFFF
            st = x & 0xFFFFFFFF
            ks.append((st >> 24) & 0xFF)
        return table[i] ^ ks[i]

    return get


def scan_mask_seed_exact(data):
    """The seed that feeds the unmask xorshift: MOVZ/MOVK pair right before the loop."""
    try:
        _, _, _, toff, tsize = find_section_bytes(data, "__text")
    except SystemExit:
        return None
    n = tsize // 4
    insn = [struct.unpack_from("<I", data, toff + 4 * i)[0] for i in range(n)]

    def fields(v):
        return v & 0x1F, (v >> 5) & 0x1F, (v >> 10) & 0x3F, (v >> 16) & 0x1F, (v >> 22) & 3

    for i in range(2, n - 2):
        a, b, c = insn[i], insn[i + 1], insn[i + 2]
        if any((v & 0x7F000000) != 0x4A000000 for v in (a, b, c)):
            continue                      # not EOR (shifted register, 32-bit)
        da, na, ia, ma, sa = fields(a)
        db, nb, ib, mb, sb = fields(b)
        dc, nc, ic, mc, sc = fields(c)
        if not (da == na == ma == db == nb == mb == dc == nc == mc):
            continue
        if (sa, ia, sb, ib, sc, ic) != (0, 13, 1, 17, 0, 5):
            continue                      # x ^= x<<13; x ^= x>>17; x ^= x<<5
        for j in range(1, 12):
            if i - j - 1 < 0:
                break
            z, k = insn[i - j - 1], insn[i - j]
            if (z & 0x7F800000) == 0x52800000 and (k & 0x7F800000) == 0x72800000:
                if (z & 0x1F) == (k & 0x1F) == da and ((z >> 21) & 3) == 0 and ((k >> 21) & 3) == 1:
                    return (((k >> 5) & 0xFFFF) << 16) | ((z >> 5) & 0xFFFF)
    return None


def scan_mask_seed_frag(data):
    """dl2: seed = XOR of four words loaded as ldr wX,[xN,#{0,4,8,12}] before the loop."""
    segs, text = [], None
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            segs.append((vmaddr, vmsize, fileoff, filesize))
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            for i in range(nsects):
                s = data[off + 72 + i * 80: off + 72 + (i + 1) * 80]
                if s[:16].rstrip(b"\x00") == b"__text":
                    text = (struct.unpack_from("<I", s, 48)[0], struct.unpack_from("<Q", s, 40)[0])
        off += cmdsize
    if text is None:
        return None
    toff, tsize = text
    taddr = None
    for vmaddr, vmsize, fileoff, filesize in segs:
        if fileoff <= toff < fileoff + filesize:
            taddr = vmaddr + (toff - fileoff)
            break
    if taddr is None:
        return None

    def vm2file(addr):
        for vmaddr, vmsize, fileoff, filesize in segs:
            if vmaddr <= addr < vmaddr + vmsize:
                return fileoff + (addr - vmaddr)
        return None

    n = tsize // 4
    insn = [struct.unpack_from("<I", data, toff + 4 * i)[0] for i in range(n)]

    def fld(v):
        return v & 0x1F, (v >> 5) & 0x1F, (v >> 10) & 0x3F, (v >> 16) & 0x1F, (v >> 22) & 3

    def is_ldr_w(v):
        return (v & 0xFFC00000) == 0xB9400000

    def is_add_imm(v):
        return (v & 0xFF800000) == 0x91000000

    def is_adrp(v):
        return (v & 0x9F000000) == 0x90000000

    def adrp_page(i):
        v = insn[i]
        imm = (((v >> 5) & 0x7FFFF) << 2) | ((v >> 29) & 3)
        if imm & (1 << 20):
            imm -= 1 << 21
        return ((taddr + 4 * i) & ~0xFFF) + (imm << 12)

    def resolve(i, reg):
        for j in range(i - 1, max(-1, i - 12), -1):
            v = insn[j]
            if is_add_imm(v) and fld(v)[0] == reg and fld(v)[1] == reg:
                addv = ((v >> 10) & 0xFFF) << (12 if (v >> 22) & 1 else 0)
                for k in range(j - 1, max(-1, j - 8), -1):
                    if is_adrp(insn[k]) and fld(insn[k])[0] == reg:
                        return adrp_page(k) + addv
        return None

    for i in range(2, n - 2):
        a, b, c = insn[i], insn[i + 1], insn[i + 2]
        if any((v & 0x7F000000) != 0x4A000000 for v in (a, b, c)):
            continue
        fa, fb, fc = fld(a), fld(b), fld(c)
        if not (fa[0] == fa[1] == fa[3] == fb[0] == fb[1] == fb[3] == fc[0] == fc[1] == fc[3]):
            continue
        if (fa[4], fa[2], fb[4], fb[2], fc[4], fc[2]) != (0, 13, 1, 17, 0, 5):
            continue
        by_base = {}
        for j in range(max(0, i - 24), i):
            v = insn[j]
            if is_ldr_w(v):
                by_base.setdefault(fld(v)[1], {})[((v >> 10) & 0xFFF) * 4] = j
        for reg, ldrs in by_base.items():
            if set(ldrs) >= {0, 4, 8, 12}:
                addr = resolve(min(ldrs.values()), reg)
                fo = vm2file(addr) if addr is not None else None
                if fo is None:
                    continue
                words = struct.unpack_from("<4I", data, fo)
                return words[0] ^ words[1] ^ words[2] ^ words[3]
    return None


def scan_mask_seeds(data):
    """Candidate HY_MASK_SEED constants: adjacent MOVZ/MOVK w-register pairs in __text."""
    try:
        _, _, _, toff, tsize = find_section_bytes(data, "__text")
    except SystemExit:
        return []
    n = tsize // 4
    insn = [struct.unpack_from("<I", data, toff + 4 * i)[0] for i in range(n)]
    seeds = []
    for i in range(n - 1):
        a, b = insn[i], insn[i + 1]
        if (a & 0x7F800000) == 0x52800000 and (b & 0x7F800000) == 0x72800000:
            if (a & 0x1F) == (b & 0x1F) and ((a >> 21) & 3) == 0 and ((b >> 21) & 3) == 1:
                v = (((b >> 5) & 0xFFFF) << 16) | ((a >> 5) & 0xFFFF)
                if v and v not in seeds:
                    seeds.append(v)
    return seeds


_MUL = {1: list(range(256)), 2: [gmul(i, 2) for i in range(256)], 3: [gmul(i, 3) for i in range(256)]}


def rows_consistent(table, env, key, p0=None, reader=None):
    """All 32 row tables must be conflict-free for the recovered key."""
    for col in range(4):
        for side in range(2):
            dst0 = 4 * col + 2 * side
            k0, k1 = key[hy_sr_src(dst0)], key[hy_sr_src(dst0 + 1)]
            a = [SBOX[x ^ k0] for x in range(256)]
            b = [SBOX[y ^ k1] for y in range(256)]
            # (1,1) plus a second coefficient pair per side: two distinct rows are
            # enough to reject a bogus key without reading all four.
            for row in (2, 0):
                m0, m1 = MC[row][side * 2], MC[row][side * 2 + 1]
                left = [_MUL[m0][v] for v in a]
                right = [_MUL[m1][v] for v in b]
                B = read_row(table, env, col, side, row, reader)
                if p0 is not None:
                    B = relabel(B, p0[hy_sr_src(dst0)], p0[hy_sr_src(dst0 + 1)])
                seen = {}
                for i in range(N):
                    p = left[i >> 8] ^ right[i & 255]
                    v = B[i]
                    cur = seen.get(p)
                    if cur is None:
                        seen[p] = v
                    elif cur != v:
                        return False
    return True


def recover_key(table, env, p0=None, reader=None):
    """Eight round-0 tables -> 16 key bytes; p0 undoes an input bijection if present."""
    key = bytearray(16)
    for col in range(4):
        for side in range(2):
            row = 2 if side == 0 else 0        # MixColumns row whose coefficients are (1,1)
            dst0 = 4 * col + 2 * side
            B = read_row(table, env, col, side, row, reader)
            if p0 is not None:
                B = relabel(B, p0[hy_sr_src(dst0)], p0[hy_sr_src(dst0 + 1)])
            k0, k1 = recover_pair(B)
            key[hy_sr_src(dst0)] = k0
            key[hy_sr_src(dst0 + 1)] = k1
    return bytes(key)


def find_section_bytes(data, want_sect):
    """Same walk as find_section(), for callers that already hold the file bytes."""
    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise SystemExit("not a thin 64-bit Mach-O")
    ncmds, sizeofcmds = struct.unpack_from(endian + "II", data, 16)
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        if cmd == 0x19:
            nsects = struct.unpack_from(endian + "I", data, off + 64)[0]
            base = off + 72
            for i in range(nsects):
                s = data[base + i * 80: base + (i + 1) * 80]
                if s[:16].rstrip(b"\x00") == want_sect.encode():
                    segname = s[16:32].rstrip(b"\x00").decode()
                    return 0, segname, want_sect, struct.unpack_from(endian + "I", s, 48)[0], \
                        struct.unpack_from(endian + "Q", s, 40)[0]
        off += cmdsize
    raise SystemExit(f"no {want_sect} section found")


def recover_pair(B):
    """B indexed [x*256+y]; returns (k0, k1) for B[x][y] = Q(S(x^k0) ^ S(y^k1))."""
    xs = range(256)
    sbox = SBOX

    def deltas_for(k1, delta, ref_row):
        # check B[x=0][y] == B[x=ref][y'] with S(y'^k1) = S(y^k1) ^ delta
        inv = [0] * 256
        for y in xs:
            inv[sbox[y ^ k1]] = y
        for y in xs:
            yp = inv[sbox[y ^ k1] ^ delta]
            if B[yp] != B[ref_row * 256 + y]:
                return False
        return True

    sols = []
    for k1 in xs:
        vals = [sbox[y ^ k1] for y in xs]
        for delta in range(1, 256):
            # cheap prefilter on the first 8 y values
            inv = [0] * 256
            for y in xs:
                inv[vals[y]] = y
            ok = True
            for y in range(8):
                if B[inv[vals[y] ^ delta]] != B[256 + y]:
                    ok = False
                    break
            if ok and deltas_for(k1, delta, 1):
                sols.append((k1, delta))
    by_delta = {}
    for k0 in xs:
        by_delta.setdefault(sbox[k0] ^ sbox[1 ^ k0], []).append(k0)
    cands = [(k0, k1) for k1, delta in sols for k0 in by_delta.get(delta, [])]
    if not cands:
        raise SystemExit("recovery failed: no candidate pair (wrong env or not a baked table?)")
    good = [c for c in cands if deltas_for(c[1], SBOX[c[0]] ^ SBOX[2 ^ c[0]], 2)]
    if len(good) != 1:
        raise SystemExit(f"ambiguous candidates: {cands} -> {good}")
    return good[0]


# ---- AES-128-ECB (verification only) --------------------------------------
def aes128_encrypt_block(pt, key):
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = xtime(rcon)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    s = [pt[i] ^ w[i // 4][i % 4] for i in range(16)]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows
        if rnd != 10:
            out = []
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                for r in range(4):
                    out.append(gmul(col[0], MC[r][0]) ^ gmul(col[1], MC[r][1])
                               ^ gmul(col[2], MC[r][2]) ^ gmul(col[3], MC[r][3]))
            s = out
        s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
    return bytes(s)


def derive_env(args):
    if args.pagesize and args.ncpu and args.cls:
        ps, nc, cl = args.pagesize, args.ncpu, args.cls
    else:
        ps = int(subprocess.check_output(["sysctl", "-n", "hw.pagesize"]))
        nc = int(subprocess.check_output(["sysctl", "-n", "hw.ncpu"]))
        cl = int(subprocess.check_output(["sysctl", "-n", "hw.cachelinesize"]))
    return ps, nc, cl, hy_env_mix(ps, nc, cl)


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("binary")
    ap.add_argument("--pagesize", type=int, help="target hw.pagesize used for table generation")
    ap.add_argument("--ncpu", type=int)
    ap.add_argument("--cls", type=int, help="target hw.cachelinesize")
    ap.add_argument("--mask-seed", type=lambda s: int(s, 0),
                    help="XOR-mask seed for a data-layer build; default: scan __text")
    ap.add_argument("--verify", action="store_true",
                    help="run the binary's self-test and compare with local AES-128")
    args = ap.parse_args(argv)

    with open(args.binary, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    cputype, seg, sect, off, size = find_section(args.binary)
    if size not in (HY_TOTAL, HY_TABLES):
        # dl4/dl5 column slots are 798,720 B (pair-decode + recoding + 64K boundary
        # tables), so the blob is 70,090,816 B. The static peel this tool implements
        # only works on the earlier shapes; say so instead of failing as if the
        # binary were malformed.
        raise SystemExit(
            f"{seg},{sect} is {size} bytes, this tool models {HY_TOTAL} "
            f"(dl1-dl3 geometry). A 70,090,816-byte blob is dl4/dl5: round-0 cells are "
            f"arbitrary bijections (E / Z encodings), so this tool's row-equality peel does "
            f"not apply. Use demos/wbaes/attacks/ (wblib.py) and see README 1b/1c.")
    has_sched = size == HY_TOTAL  # dl/dl2 predate the schedule block
    with open(args.binary, "rb") as f:
        f.seek(off)
        table = f.read(size)
    ps, nc, cl, env = derive_env(args)
    print(f"binary  : {args.binary}")
    print(f"sha256  : {digest}")
    print(f"section : {seg},{sect} fileoff={off} size={size} (cputype 0x{cputype:08x})")
    print(f"env     : pagesize={ps} ncpu={nc} cls={cl} -> 0x{env:08x}")

    data = open(args.binary, "rb").read()
    p0cands = find_input_bijection(data)
    if args.mask_seed is not None:
        seeds = [args.mask_seed]
    else:
        exact = scan_mask_seed_exact(data)
        frag = scan_mask_seed_frag(data)
        seeds = []
        for s in (exact, frag):
            if s is not None and s not in seeds:
                seeds.append(s)
        if not seeds:
            seeds = scan_mask_seeds(data)
    if p0cands:
        print(f"round-0 input bijections found: {[c[0] for c in p0cands]}")
    if seeds:
        print(f"candidate mask seeds: {[f'0x{s:08x}' for s in seeds]}")

    modes = [(None, None, "plain round-0 index")]
    for off, cand in p0cands:
        modes.append((None, cand, f"round-0 input bijection @file offset {off}"))
    for s in seeds:
        modes.append((s, None, f"data-layer mask seed 0x{s:08x}"))
        for off, cand in p0cands:
            modes.append((s, cand, f"mask seed 0x{s:08x} + input bijection @{off}"))

    key, seed_used, mode, get, tbox = None, None, None, None, False
    for s, cand, label in modes:
        reader = make_reader(table, s)
        get = reader if reader is not None else table.__getitem__
        fam0 = sched_family(get, 0, 0) if has_sched else FAM_PAIR
        try:
            if fam0 in (FAM_T32, FAM_T8, FAM_T32K):
                # dl3: round 0 is a byte-indexed T-box, so the pair-table search
                # below does not describe it at all - read it the way it is built.
                k = recover_key_tbox(get, env, cand, fam0)
                label = f"{label}, round 0 family {fam0}"
                tbox = True
            else:
                k = recover_key(table, env, cand, reader)
                if not rows_consistent(table, env, k, cand, reader):
                    continue
                tbox = False
        except SystemExit:
            continue
        key, seed_used, mode = k, s, label
        break
    if key is None:
        raise SystemExit("recovery failed: no candidate key (wrong env, or a hardening we do not undo)")
    print(f"mode    : {mode}")
    if has_sched:
        names = {FAM_PAIR: "F0", FAM_T32: "F1", FAM_T8: "F2", FAM_T32K: "F3"}
        fams = [sched_family(get, d, r) for d in (0, 1) for r in range(HY_MC_ROUNDS)]
        print("schedule: enc " + " ".join(names.get(f, "??") for f in fams[:HY_MC_ROUNDS]))
        print("          dec " + " ".join(names.get(f, "??") for f in fams[HY_MC_ROUNDS:]))
    if seed_used is not None:
        fnv = fnv1a16(key)
        if fnv == seed_used:
            print(f"mask seed vs FNV-1a(key): 0x{fnv:08x} -> match")
        else:
            print(f"mask seed is not FNV-1a(key) (0x{seed_used:08x} vs 0x{fnv:08x}): "
                  "seed is independent, key proven by table structure + test vector")
    if tbox:
        for col in range(4):
            pairs = " ".join(f"key[{hy_sr_src(k + 4 * col):2d}]=0x{key[hy_sr_src(k + 4 * col)]:02x}"
                             for k in range(4))
            print(f"  col {col}: {pairs}")
    else:
        for col in range(4):
            for side in range(2):
                dst0 = 4 * col + 2 * side
                print(f"  col {col} side {side}: key[{hy_sr_src(dst0):2d}]=0x{key[hy_sr_src(dst0)]:02x} "
                      f"key[{hy_sr_src(dst0 + 1):2d}]=0x{key[hy_sr_src(dst0 + 1)]:02x}")
    print(f"AES-128 key: {key.hex()}")

    if args.verify:
        out = subprocess.run([args.binary], capture_output=True, text=True, timeout=120)
        fields = {}
        for line in out.stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip()] = v.strip()
        pt = bytes.fromhex(fields["plaintext"])
        binary_ct = bytes.fromhex(fields["ciphertext"])
        local = aes128_encrypt_block(pt, key)
        print(f"\nbinary self-test: {fields.get('vector-match')} / roundtrip {fields.get('roundtrip')}")
        print(f"binary ciphertext: {binary_ct.hex()}")
        print(f"local  AES-128 ECB: {local.hex()}")
        print(f"key reproduces the shipped binary: {'YES' if local == binary_ct else 'NO'}")
        return 0 if local == binary_ct else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
