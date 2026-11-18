"""Extract the AES-128 key from any shipped `*_f4` (W16) white-box binary.

Self-contained route: it reads the round-0 input bijection out of the binary's
__TEXT,__const, unmasks the __hytab section, and recovers each key byte from one
of the 32 pair-table axes (4 columns x 4 tables x 2 axes) with a linear-fit test
that is invariant to the unknown 16x16 affine encoding.

    python3 w16_extract.py <binary> [--cache /tmp/x.bin] [--verify-hex <pt>]
"""
import argparse
import re
import sys
import time

_D = "/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/demos/wbaes/attacks"
sys.path.insert(0, _D)
sys.path.insert(0, _D + "/residual")
import wblib as wb
import res16                       # its affine-consistency test is the strict one

K_W16_L = 200
W16_TAB = wb.U16
MC = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]

# ---- the test -------------------------------------------------------------


def coords(points):
    """Coordinates of points[i] ^ points[0] over a basis of their span."""
    base = points[0]
    piv = {}
    out = []
    for p in points:
        v = p ^ base
        c = 0
        while v:
            hb = v.bit_length() - 1
            e = piv.get(hb)
            if e is None:
                piv[hb] = v
                c |= 1 << hb
                break
            v ^= e
        out.append(c)
    return out, len(piv)


def affine_image_ok(x, val):
    """Is `val` the image of `x` under one affine map (8-bit domain, 16-bit range)?

    A wrong key guess makes the two coordinate systems disagree on some point;
    the correct guess is the only one where every one of the 256 pairs fits a
    single linear map.
    """
    cv, dimv = coords(val)
    cp, dimp = coords(x)
    if dimp != dimv:
        return False
    piv = {}
    for c, im in zip(cp, cv):
        while c:
            hb = c.bit_length() - 1
            e = piv.get(hb)
            if e is None:
                piv[hb] = (c, im)
                break
            c ^= e[0]
            im ^= e[1]
        else:
            if im:
                return False
    return True


def key_candidates(val, p0i, src):
    return res16.key_candidates16(val, p0i, src)


# ---- I/O ------------------------------------------------------------------


def load_p0i(data):
    hits = wb.find_input_bijection(data)
    if not hits:
        raise SystemExit("no 16x256 permutation block found in __TEXT,__const")
    p0i = []
    for row in hits[0][1]:
        inv = [0] * 256
        for i, v in enumerate(row):
            inv[v] = i
        p0i.append(inv)
    return hits[0][0], p0i


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--cache", default=None, help="unmasked table cache path")
    ap.add_argument("--verify-hex", default="6bc1bee22e409f96e93d7e117393172a")
    a = ap.parse_args(argv)
    t0 = time.time()

    data = open(a.binary, "rb").read()
    off, p0i = load_p0i(data)
    print("input bijection at file offset", off)

    plain = wb.load_plain_table(a.binary, cache=a.cache)
    print("unmasked table:", len(plain), "bytes")
    tab = wb.Tab(plain, wb.hy_env_mix(*wb.DEFAULT_ENV))

    votes = {}
    tests = 0
    for col in range(4):
        for k in range(4):
            base = col * wb.COL + k * W16_TAB
            tag = wb.hy_tag(0, 0, col, K_W16_L + k)
            for axis in (0, 1):
                if axis == 0:
                    val = [tab.r16(base, i, tag) for i in range(256)]
                else:
                    val = [tab.r16(base, i << 8, tag) for i in range(256)]
                lane = 2 * (k & 1) + axis
                src = wb.sr_src(4 * col + lane)
                cands = key_candidates(val, p0i, src)
                tests += 256
                if len(cands) != 1:
                    print(f"  col{col} k{k} axis{axis} src{src}: {len(cands)} candidates!")
                    continue
                votes.setdefault(src, []).append(cands[0])

    bad = {i: v for i, v in votes.items() if len(set(v)) != 1}
    missing = [i for i in range(16) if i not in votes]
    if bad or missing:
        raise SystemExit(f"incomplete: {sorted(missing)}, conflicts: {bad}")

    key = bytes(votes[i][0] for i in range(16))
    pt = bytes.fromhex(a.verify_hex)
    ct = wb.aes_encrypt(pt, key)
    print("AES-128 key:", key.hex())
    print(f"AES-128({pt.hex()}) = {ct.hex()}")
    print(f"votes per position: {[len(votes[i]) for i in range(16)]}")
    print(f"{tests} affine-consistency tests, {time.time() - t0:.2f}s")


if __name__ == "__main__":
    main()
