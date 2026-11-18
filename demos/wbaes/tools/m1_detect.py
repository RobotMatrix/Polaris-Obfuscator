#!/usr/bin/env python3
"""m1_detect.py — what an attacker runs first, turned into a number.

Signals (all of them are things a person does with nm/otool/strings plus a hex
editor, not custom analysis):

  S1 symbol names      nm -a, matched against aes|wbaes|hsvm|hytab|sbox|mixcol|
                       rcon|kHyTab|test_pt|test_ct (6 pts each)
  S2 section names     otool -l; a custom section whose *name* says what it holds
                       is a free hint (15 pts each), and the count of custom
                       sections is reported even when the names are random
  S3 strings           __cstring contents and long keywords anywhere in the file
                       (3 pts each, capped)
  S4 S-box bytes       the 256-byte AES S-box and its inverse, and their 16-byte
                       prefixes, searched over the whole artifact (40 pts)
  S5 NIST vector       the FIPS-197/SP 800-38A plaintext and its ciphertext for
                       this build's key, searched over the whole artifact (40 pts)
  S6 table classifier  256-byte windows that are permutations AND 4-uniform, i.e.
                       an S-box row up to invertible maps on both sides; counted
                       over the table blob after the (trivial) unmask
                       (40 pts if any are found)
  S7 build metadata    toolchain/build paths and pass names (10 pts each)

Usage:
  python3 m1_detect.py --bin <path> [--seal <dir with hy_seal.h>] [--json]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from macho_scrub import MachO  # noqa: E402

SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])
INV_SBOX = bytes([SBOX.index(i) for i in range(256)])
NIST_PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
NIST_CT = bytes.fromhex("7672415a6313c58518fc95c9cb6922b8")

SYM_TELL = re.compile(
    r"aes|hsvm|hytab|sbox|mixcol|rcon|kHyTab|test_pt|test_ct|WBAES|hybrid|wbaes", re.I)
SECT_TELL = re.compile(r"hytab|hsvm|aes|sbox|wb|hy", re.I)
STR_TELL = re.compile(
    r"aes|wbaes|hsvm|hytab|sbox|mixcol|rcon|plaintext|ciphertext|vector-match|"
    r"roundtrip|backend-obfu", re.I)
# Every keyword here is >= 7 bytes: at 4 bytes a random match in 70 MB of
# high-entropy table data is likely ("LLVM" hit by chance once in testing), and a
# false positive is worse than a missing signal.
META = [b"/Users/", b"/tmp/wbaes", b"Polaris", b"clang version",
        b"sub,bcf", b"backend-obfu", b"gen_hybrid", b"hy_seal", b"wbaes_key.h"]


def nm_symbols(path):
    r = subprocess.run(["nm", "-a", path], capture_output=True, text=True)
    return [l.split()[-1] for l in r.stdout.splitlines() if l.strip()]


def cstrings(path):
    m = MachO(path)
    for seg, sect, so in m.sections():
        if sect == "__cstring":
            off = int.from_bytes(m.data[so + 48:so + 52], "little")
            size = int.from_bytes(m.data[so + 40:so + 48], "little")
            blob = bytes(m.data[off:off + size])
            return [s.decode("latin1") for s in blob.split(b"\0") if len(s) > 2]
    return []


def biggest_section(path, min_size=1 << 20):
    """The table blob, found by size. Renaming the section does not hide 70 MB."""
    m = MachO(path)
    best = None
    for seg, sect, so in m.sections():
        size = int.from_bytes(m.data[so + 40:so + 48], "little")
        off = int.from_bytes(m.data[so + 48:so + 52], "little")
        if size >= min_size and off:
            if best is None or size > best[2]:
                best = (sect, off, size, seg)
    return best


def frags_from_seal(path):
    txt = open(path).read()
    m = re.search(r"HY_SEED_FRAG\[4\]\s*=\s*\{([^}]*)\}", txt)
    return [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", m.group(1))][:4]


def scan_tables(path, seal_dir):
    best = biggest_section(path)
    if not best:
        return {"error": "no large section"}
    sect, off, size, seg = best
    frags = [0, 0, 0, 0]
    seal = os.path.join(seal_dir or "", "hy_seal.h")
    if seal_dir and os.path.exists(seal):
        frags = frags_from_seal(seal)
    exe = os.path.join(tempfile.gettempdir(), ".wbaes-m1scan")
    src = os.path.join(HERE, "m1scan.c")
    if (not os.path.exists(exe)) or os.path.getmtime(exe) < os.path.getmtime(src):
        subprocess.run(["cc", "-O2", "-o", exe, src], check=True)
    r = subprocess.run([exe, path, str(off), str(size)] + [hex(f) for f in frags],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return {"error": r.stderr.strip()}
    out = json.loads(r.stdout)
    out["section"] = sect
    out["seg"] = seg
    out["frags_used"] = bool(frags[0] or frags[1] or frags[2] or frags[3])
    return out


def detect(path, seal_dir=None, with_tables=True):
    data = open(path, "rb").read()
    sig = {}

    syms = nm_symbols(path)
    hits = [s for s in syms if SYM_TELL.search(s)]
    sig["S1_symbol_name_tells"] = {"count": len(hits), "hits": hits[:20],
                                   "points": min(60, 6 * len(hits))}

    m = MachO(path)
    custom, named = [], []
    for seg, sect, so in m.sections():
        if sect in ("__text", "__stubs", "__const", "__cstring", "__unwind_info",
                    "__got", "__data", "__bss", "__common"):
            continue
        custom.append("%s,%s" % (seg, sect))
        if SECT_TELL.search(sect):
            named.append(sect)
    sig["S2_section_name_tells"] = {"count": len(named), "named": named,
                                    "custom_sections": custom,
                                    "points": 15 * len(named)}

    strs = cstrings(path)
    str_hits = [s for s in strs if STR_TELL.search(s)]
    sig["S3_string_tells"] = {"count": len(str_hits), "hits": str_hits[:20],
                              "points": min(30, 3 * len(str_hits))}

    sbox_hits = {"full_sbox": data.count(SBOX), "full_inv": data.count(INV_SBOX),
                 "prefix16": data.count(SBOX[:16]),
                 "prefix16_inv": data.count(INV_SBOX[:16])}
    anybox = sum(sbox_hits.values())
    sig["S4_sbox_bytes"] = dict(sbox_hits, points=40 if anybox else 0)

    kat = {"nist_pt": data.count(NIST_PT), "nist_ct": data.count(NIST_CT)}
    sig["S5_nist_vector"] = dict(kat, points=40 if (kat["nist_pt"] or kat["nist_ct"]) else 0)

    if with_tables:
        t = scan_tables(path, seal_dir)
        sig["S6_sbox_class_tables"] = {
            "count": t.get("sbox_class_windows", 0),
            "perm_windows": t.get("perm_windows", 0),
            "section": t.get("section"), "size": t.get("table_bytes"),
            "first_offsets": t.get("first_offsets", [])[:4],
            "unmasked": t.get("frags_used"),
            "points": 40 if t.get("sbox_class_windows", 0) else 0,
        }

    meta_hits = {k.decode(): data.count(k) for k in META if data.count(k)}
    sig["S7_build_metadata"] = {"count": len(meta_hits), "hits": meta_hits,
                                "points": min(30, 10 * len(meta_hits))}

    total = sum(v["points"] for v in sig.values())
    return {"binary": path, "size": len(data), "signals": sig, "score": total}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--seal", default=None, help="dir holding hy_seal.h (for the unmask seed)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-tables", action="store_true")
    a = ap.parse_args()
    r = detect(a.bin, a.seal, with_tables=not a.no_tables)
    if a.json:
        print(json.dumps(r, indent=2))
        return
    print("M1 detectability — %s (%d bytes)" % (r["binary"], r["size"]))
    print("%-24s %8s %8s  %s" % ("signal", "count", "points", "detail"))
    for name, v in r["signals"].items():
        detail = ""
        if "hits" in v and isinstance(v["hits"], list):
            detail = ", ".join(str(x) for x in v["hits"][:6])
        elif "hits" in v:
            detail = ", ".join(list(v["hits"])[:6])
        elif "named" in v:
            detail = ", ".join(v["named"]) or ("custom: " + ", ".join(v["custom_sections"]))
        elif "nist_pt" in v:
            detail = "pt=%d ct=%d" % (v["nist_pt"], v["nist_ct"])
        elif "full_sbox" in v:
            detail = "full=%d/%d prefix16=%d/%d" % (v["full_sbox"], v["full_inv"],
                                                    v["prefix16"], v["prefix16_inv"])
        elif "perm_windows" in v:
            detail = "section=%s perms=%d first=%s" % (
                v.get("section"), v.get("perm_windows"), v.get("first_offsets"))
        print("%-24s %8s %8d  %s" % (name, v.get("count", ""), v.get("points", 0), detail))
    print("%-24s %8s %8d" % ("TOTAL", "", r["score"]))


if __name__ == "__main__":
    main()
