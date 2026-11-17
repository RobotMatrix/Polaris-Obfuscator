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
HY_TOTAL = ENC_BYTES + DEC_BYTES  # 69_206_016

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
def read_row(table, env, col, side, row):
    """64K entries of one round-0 (col,side) table, one output row, as B[x*256+y].

    The logical index in the table is x | (y << 8), so it is unpacked into the
    x-major layout the recovery expects.
    """
    base = col * COL + (U32 if side else 0)
    tag = hy_tag(0, 0, col, side)
    out = bytearray(N)
    for logical in range(N):
        p = base + hy_scatter(logical, env, tag) * 4
        x = logical & 255
        y = logical >> 8
        out[x * 256 + y] = table[p + row]
    return out


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
    ap.add_argument("--verify", action="store_true",
                    help="run the binary's self-test and compare with local AES-128")
    args = ap.parse_args(argv)

    with open(args.binary, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    cputype, seg, sect, off, size = find_section(args.binary)
    if size != HY_TOTAL:
        raise SystemExit(f"{seg},{sect} is {size} bytes, expected HY_TOTAL={HY_TOTAL}")
    with open(args.binary, "rb") as f:
        f.seek(off)
        table = f.read(size)
    ps, nc, cl, env = derive_env(args)
    print(f"binary  : {args.binary}")
    print(f"sha256  : {digest}")
    print(f"section : {seg},{sect} fileoff={off} size={size} (cputype 0x{cputype:08x})")
    print(f"env     : pagesize={ps} ncpu={nc} cls={cl} -> 0x{env:08x}")

    key = bytearray(16)
    for col in range(4):
        for side in range(2):
            row = 2 if side == 0 else 0        # MixColumns row whose pair is (1,1)
            B = read_row(table, env, col, side, row)
            k0, k1 = recover_pair(B)
            dst0 = 4 * col + 2 * side
            key[hy_sr_src(dst0)] = k0
            key[hy_sr_src(dst0 + 1)] = k1
            print(f"  col {col} side {side}: key[{hy_sr_src(dst0):2d}]=0x{k0:02x} "
                  f"key[{hy_sr_src(dst0 + 1):2d}]=0x{k1:02x}")
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
