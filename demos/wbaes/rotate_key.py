#!/usr/bin/env python3
"""Rotate the white-box AES key in wbaes_key.h.

The header holds the master key as four 4-byte shards XORed with four cover
bytes, each shard buried at its own offset inside 64 bytes of random filler,
with an FNV-1a check word for each shard. Rotating the key means rewriting
those blocks, the check words, the offsets and the self-test ciphertext; then
regenerating the hybrid table (gen_hybrid reads key_byte) and rebuilding the
demo, because the tables are the key.

    rotate_key.py                 # fresh random key
    rotate_key.py --key <32 hex>  # explicit key
    rotate_key.py --test-pt <32 hex>

Prints the new key and the matching AES-128-ECB ciphertext so the caller can
independently re-derive them with openssl.
"""

import argparse
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HEADER = os.path.join(HERE, "wbaes_key.h")
TESTVEC = os.path.join(HERE, "wbaes_testvec.h")
TESTVEC_TMPL = """// =============================================================================
// wbaes_testvec.h — 自检向量（唯一来源, rotate_key.py 生成）
//
// 由 rotate_key.py 与密钥同步生成；demo_wbaes.cpp 与 wbaes_key.h 都从这里引用，
// 不再各自硬编码一份（否则换钥后发布版自检必红）。
// 向量不是密钥，可以出现在发布二进制里。
// =============================================================================

%s

%s
"""
DEFAULT_PT = "6bc1bee22e409f96e93d7e117393172a"  # NIST SP800-38A ECB-AES128


def fnv1a(data):
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def aes_ecb(key, pt):
    out = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", key.hex(), "-nopad"],
        input=pt, capture_output=True, check=True)
    return out.stdout


def c_array(name, data, indent="    ", n=64):
    lines = ["static const uint8_t %s[%d] = {" % (name, n)]
    for i in range(0, n, 16):
        chunk = ",".join("0x%02x" % b for b in data[i:i + 16])
        lines.append(indent + chunk + ",")
    lines.append("};")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key")
    ap.add_argument("--test-pt", default=DEFAULT_PT)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    key = bytes.fromhex(args.key) if args.key else os.urandom(16)
    if len(key) != 16:
        raise SystemExit("key must be 16 bytes (32 hex chars)")
    pt = bytes.fromhex(args.test_pt)
    ct = aes_ecb(key, pt)

    import random
    rng = random.Random(args.seed) if args.seed is not None else random.SystemRandom()

    blocks = {k: [] for k in ("K", "C", "CH")}
    koff, coff, choff = [], [], []
    for s in range(4):
        # shard = random R; cover = R ^ key_chunk, so R ^ cover == key_chunk
        # and neither block element looks like key material.
        part = bytes(rng.randrange(256) for _ in range(4))
        cover = bytes(a ^ b for a, b in zip(part, key[4 * s:4 * s + 4]))
        chk = struct.pack("<I", fnv1a(part))

        # three disjoint 4-byte slots inside the 64-byte block
        slots = list(range(0, 61))
        rng.shuffle(slots)
        o = [slots[0], slots[1], slots[2]]
        while any(abs(a - b) < 4 for a in o for b in o if a is not b):
            rng.shuffle(slots)
            o = [slots[0], slots[1], slots[2]]
        koff.append(o[0])
        coff.append(o[1])
        choff.append(o[2])

        blk = {k: bytearray(rng.randrange(256) for _ in range(64))
               for k in ("K", "C", "CH")}
        blk["K"][o[0]:o[0] + 4] = part
        blk["C"][o[1]:o[1] + 4] = cover
        blk["CH"][o[2]:o[2] + 4] = chk
        for k in blocks:
            blocks[k].append(bytes(blk[k]))

    with open(HEADER, "r", encoding="utf-8") as fh:
        src = fh.read()

    import re
    for k in ("K", "C", "CH"):
        for s in range(4):
            name = "%sBLK%d" % (k, s)
            src = re.sub(r"static const uint8_t %s\[64\] = \{.*?\};" % name,
                         c_array(name, blocks[k][s]), src, flags=re.S)
    src = re.sub(r"static const uint8_t KOFF\[4\]  = \{[^}]*\};",
                 "static const uint8_t KOFF[4]  = {%s};"
                 % ",".join(map(str, koff)), src)
    src = re.sub(r"static const uint8_t COFF\[4\]  = \{[^}]*\};",
                 "static const uint8_t COFF[4]  = {%s};"
                 % ",".join(map(str, coff)), src)
    src = re.sub(r"static const uint8_t CHOFF\[4\] = \{[^}]*\};",
                 "static const uint8_t CHOFF[4] = {%s};"
                 % ",".join(map(str, choff)), src)
    with open(TESTVEC, "w", encoding="utf-8") as fh:
        fh.write(TESTVEC_TMPL % (c_array("test_pt", pt, n=16),
                                 c_array("test_ct", ct, n=16)))
    src = re.sub(r"// 密钥: [0-9a-f]{32} .*",
                 "// 密钥: %s (rotate_key.py, %s)"
                 % (key.hex(), __import__("datetime").date.today().isoformat()),
                 src)

    with open(HEADER, "w", encoding="utf-8") as fh:
        fh.write(src)

    print("key      : %s" % key.hex())
    print("test_pt  : %s" % pt.hex())
    print("test_ct  : %s" % ct.hex())
    print("offsets  : K=%s C=%s CH=%s" % (koff, coff, choff))
    print("header   : %s" % HEADER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
