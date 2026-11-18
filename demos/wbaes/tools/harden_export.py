#!/usr/bin/env python3
"""harden_export.py — build the white-box demo in its "export-hardened" form.

Three independent treatments, in the order an attacker reads the artifact:

  1. table   every 256-entry S-box-shaped table is pre-composed with a per-build
             affine map, the inverse absorbed into the 64K decode tables it feeds
             (tools/hy_scrub.cpp). Byte-for-byte equality with the AES S-box and
             the S-box byte string are measured before and after; so is the
             differential-uniformity signature, which is invariant (see the
             report).
  2. self-check  the NIST known-answer vector is gone. A random vector is derived
             from the build seed at run time and only its FNV-1a-64 is compared,
             against a hash of the real AES answer computed here; nothing is
             printed unless the check fails.
  3. metadata  every custom section and every defined symbol gets a per-build
             name, local/debug symbols are dropped, and the KAT strings go away
             (tools/macho_scrub.py, post-link + ad-hoc re-sign).

The ciphertext must not change. Step 6 re-runs the build's own check, and
--probe builds a throwaway variant that prints the ciphertext of a caller-supplied
plaintext so M2 can compare it with the unhardened build byte for byte.

Usage:
  python3 harden_export.py --src <demos/wbaes> --out <build dir> --seed <string>
  python3 harden_export.py ... --probe        # also build wbaes_hard_probe
  python3 harden_export.py ... --skip-macho   # stop before the Mach-O pass
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CLANG = os.environ.get("POLARIS_CLANG",
                            "/Users/lasysloth/Bangcle/iOS/Polaris-Obfuscator/src/build/bin/clang++")
SOURCES = [
    "demo_wbaes.cpp", "wbaes_hybrid.h", "wbaes_hybrid.inc", "wbaes_vm.cpp",
    "wbaes_vm.h", "hy_tab.S", "hy_in.h", "hy_mask.h", "wbaes_key.h",
    "wbaes_testvec.h", "aes.h", "tiny_aes.c",
]
FLAGS = ["-O2", "-std=c++17", "-DWBAES_BAKED", "-DWBAES_NO_MIR", "-DWBAES_HAVE_VM"]


# --------------------------------------------------------------------------
# tiny AES-128 encrypter: the tool must know the right answer for the random
# self-check vector, and it must not ask the artifact it is hardening.
# --------------------------------------------------------------------------
SBOX = [
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
]
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def xt(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def gmul(a, b):
    p = 0
    while b:
        if b & 1:
            p ^= a
        a = xt(a)
        b >>= 1
    return p


def expand_key(key):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum((w[4 * r + c] for c in range(4)), []) for r in range(11)]


def aes128_encrypt(key, block):
    rk = expand_key(key)
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows (column-major)
        if rnd != 10:
            n = []
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                n += [gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3],
                      col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3],
                      col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3),
                      gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)]
            s = n
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)


def fnv1a64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def fnv1a32(data):
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return h


# --------------------------------------------------------------------------
def parse_key(src_dir):
    """wbaes_key.h stores the key as key = KBLK[s][KOFF[s]+b] ^ CBLK[s][COFF[s]+b]."""
    text = open(os.path.join(src_dir, "wbaes_key.h")).read()

    def block(name):
        m = re.search(r"%s\[64\]\s*=\s*\{(.*?)\};" % name, text, re.S)
        if not m:
            raise SystemExit("cannot find %s in wbaes_key.h" % name)
        return bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))

    def offs(name):
        m = re.search(r"%s\[4\]\s*=\s*\{([^}]*)\};" % name, text)
        return [int(x) for x in re.findall(r"\d+", m.group(1))]

    K = [block("KBLK%d" % s) for s in range(4)]
    C = [block("CBLK%d" % s) for s in range(4)]
    ko, co = offs("KOFF"), offs("COFF")
    key = bytes(K[i >> 2][ko[i >> 2] + (i & 3)] ^ C[i >> 2][co[i >> 2] + (i & 3)]
                for i in range(16))
    return key


def kat_plaintext(seed32):
    """The same xorshift the runtime uses; 16 bytes derived from the build seed."""
    s = seed32
    out = bytearray()
    for _ in range(16):
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        s &= 0xFFFFFFFF
        out.append((s >> 24) & 0xFF)
    return bytes(out)


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        sys.stderr.write("command failed (%d): %s\n%s\n%s\n"
                         % (r.returncode, " ".join(cmd), r.stdout[-4000:], r.stderr[-4000:]))
        raise SystemExit(1)
    return r


def patch_demo(path, key):
    """Two anchored edits. Fails loudly if the tree moved under us."""
    src = open(path).read()
    a1 = '''namespace wbaes_key {
static uint32_t g_key_tampered = 0;
#include "wbaes_testvec.h"
}'''
    if a1 not in src:
        raise SystemExit("anchor 1 not found in demo_wbaes.cpp (baked KAT include)")
    src = src.replace(a1, '''namespace wbaes_key {
static uint32_t g_key_tampered = 0;
#include "hy_kat.h"   // build-time random vector + hash of its real-AES answer
}''')

    a2 = '''    uint8_t ct[16], rt[16];
    wb.encrypt(wbaes_key::test_pt, ct);
    wb.decrypt(ct, rt);

    printf("plaintext : ");
    for (int i = 0; i < 16; i++) printf("%02x", wbaes_key::test_pt[i]);
    printf("\\nciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("\\nexpected  : ");
    for (int i = 0; i < 16; i++) printf("%02x", wbaes_key::test_ct[i]);
    printf("\\nroundtrip : ");
    for (int i = 0; i < 16; i++) printf("%02x", rt[i]);
    printf("\\n");
    bool vec = memcmp(ct, wbaes_key::test_ct, 16) == 0;
    bool round = memcmp(rt, wbaes_key::test_pt, 16) == 0;
    printf("vector-match: %s\\n", vec ? "PASS" : "FAIL");
    printf("roundtrip   : %s\\n", round ? "PASS" : "FAIL");'''
    if a2 not in src:
        raise SystemExit("anchor 2 not found in demo_wbaes.cpp (self-check block)")
    src = src.replace(a2, '''    // Self-check without a known-answer vector: the plaintext is derived from a
    // build-time seed, the answer is compared as an FNV-1a-64 hash, and bytes are
    // printed only when the check fails (M2: the hash was computed from real
    // AES-128 at export time, so a pass means the tables still compute AES).
    uint8_t pt[16], ct[16], rt[16];
    wbaes_key::hy_kat_plaintext(pt);
    wb.encrypt(pt, ct);
    wb.decrypt(ct, rt);
    const bool vec = wbaes_key::hy_fnv64(ct, 16) == HY_KAT_CT_FNV;
    const bool round = memcmp(rt, pt, 16) == 0;
    if (!vec || !round) {
        printf("check FAIL pt=");
        for (int i = 0; i < 16; i++) printf("%02x", pt[i]);
        printf(" ct=");
        for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
        printf(" rt=");
        for (int i = 0; i < 16; i++) printf("%02x", rt[i]);
        printf("\\n");
        return 1;
    }
    printf("check: ok\\n");''')
    open(path, "w").write(src)
    return {"anchor1": True, "anchor2": True}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", required=True)
    ap.add_argument("--clang", default=DEFAULT_CLANG)
    ap.add_argument("--probe", action="store_true")
    ap.add_argument("--bench", action="store_true")
    ap.add_argument("--vmtest", action="store_true")
    ap.add_argument("--m1", action="store_true")
    ap.add_argument("--strip", action="store_true",
                    help="link with -Wl,-x,-S so no local symbols or debug map survive")
    ap.add_argument("--skip-macho", action="store_true")
    a = ap.parse_args()

    src_dir = os.path.abspath(a.src)
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    log = {}

    # ---- 1. table ------------------------------------------------------
    for f in SOURCES:
        shutil.copy2(os.path.join(src_dir, f), os.path.join(out, f))
    if a.strip:
        FLAGS.append("-Wl,-x,-S")
    clang = a.clang
    run([clang, "-O2", "-std=c++17", "-I" + out, "-I" + src_dir,
         os.path.join(HERE, "hy_scrub.cpp"), "-o", os.path.join(out, "hy_scrub")])
    table_in = os.path.join(src_dir, "hy_table.bin")
    table_out = os.path.join(out, "hy_table.bin")
    r = run([os.path.join(out, "hy_scrub"), table_in, table_out, a.seed,
             "--stats", os.path.join(out, "scrub_stats.json")])
    scrub = json.loads(r.stdout)
    log["scrub"] = scrub

    # hy_seal.h: same mask seed, new hashes for the rewritten table
    seal_src = open(os.path.join(src_dir, "hy_seal.h")).read()
    seal = seal_src
    seal = re.sub(r"#define HY_TABLE_SEAL 0x[0-9a-f]+u",
                  "#define HY_TABLE_SEAL 0x%08xu" % scrub["seal"], seal)
    seal = re.sub(r"#define HY_TABLE_SEAL_S4096 0x[0-9a-f]+u",
                  "#define HY_TABLE_SEAL_S4096 0x%08xu" % scrub["seal_s4096"], seal)
    seal = re.sub(r"#define HY_TABLE_SEAL_S4096_P 0x[0-9a-f]+u",
                  "#define HY_TABLE_SEAL_S4096_P 0x%08xu" % scrub["seal_s4096_p"], seal)
    open(os.path.join(out, "hy_seal.h"), "w").write(seal)

    # ---- 2. self-check vector -----------------------------------------
    key = parse_key(src_dir)
    seed32 = int.from_bytes(hashlib.sha256(("kat|" + a.seed).encode()).digest()[:4], "big")
    pt = kat_plaintext(seed32)
    ct = aes128_encrypt(key, pt)
    kat = """// generated by tools/harden_export.py - do not edit
#pragma once
#include <cstdint>
// Build-time random self-check vector. The bytes are NOT stored: the plaintext is
// derived from this seed at run time, and only the FNV-1a-64 of the answer is
// kept. The hash below was computed from real AES-128-ECB at export time, so
// "check: ok" means the table network still computes AES.
#define HY_KAT_SEED 0x%08xu
#define HY_KAT_CT_FNV 0x%016xull
static inline uint32_t hy_kat_next(uint32_t *s) {
    uint32_t x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x;
    return x;
}
static inline void hy_kat_plaintext(uint8_t p[16]) {
    uint32_t s = HY_KAT_SEED;
    for (int i = 0; i < 16; i++) p[i] = (uint8_t)(hy_kat_next(&s) >> 24);
}
static inline uint64_t hy_fnv64(const uint8_t *p, unsigned n) {
    uint64_t h = 0xCBF29CE484222325ull;
    for (unsigned i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001B3ull; }
    return h;
}
""" % (seed32, fnv1a64(ct))
    open(os.path.join(out, "hy_kat.h"), "w").write(kat)
    log["kat"] = {"seed": "0x%08x" % seed32, "pt": pt.hex(), "ct": ct.hex(),
                  "fnv64": "0x%016x" % fnv1a64(ct)}

    # ---- 3. sources ----------------------------------------------------
    log["patch"] = patch_demo(os.path.join(out, "demo_wbaes.cpp"), key)

    # ---- 4/5. build ----------------------------------------------------
    run([clang] + FLAGS + ["-I" + out, "-I" + src_dir, "-mllvm", "-passes=hsvm",
                           "-c", "wbaes_vm.cpp", "-o", "wbaes_vm.o"], cwd=out)
    run([clang] + FLAGS + ["-I" + out, "-I" + src_dir, "demo_wbaes.cpp", "hy_tab.S",
                           "wbaes_vm.o", "-o", "wbaes_hard_raw"], cwd=out)
    log["binary_raw"] = os.path.join(out, "wbaes_hard_raw")

    # ---- 6. Mach-O -----------------------------------------------------
    if not a.skip_macho:
        run([sys.executable, os.path.join(HERE, "macho_scrub.py"),
             "--in", os.path.join(out, "wbaes_hard_raw"),
             "--out", os.path.join(out, "wbaes_hard"), "--seed", a.seed])
        log["binary"] = os.path.join(out, "wbaes_hard")
    else:
        log["binary"] = log["binary_raw"]

    # ---- 7. prove it runs ---------------------------------------------
    r = subprocess.run([log["binary"]], capture_output=True, text=True)
    log["run"] = {"rc": r.returncode, "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}
    if r.returncode != 0 or "check: ok" not in r.stdout:
        print(json.dumps(log, indent=2))
        raise SystemExit("hardened binary failed its own check")

    # ---- 8. optional probe build (ciphertext identity, M2) ------------
    if a.probe:
        probe_src = open(os.path.join(out, "demo_wbaes.cpp")).read()
        probe_src = probe_src.replace(
            '    WBAES wb;\n    wb.init();',
            '    if (argc > 1 && argv[1][0] == \'=\') {   // test-only: ct of a hex block\n'
            '        uint8_t in[16], o[16];\n'
            '        for (int i = 0; i < 16; i++) {\n'
            '            auto hx = [](char c) { return c <= \'9\' ? c - \'0\' : (c | 32) - \'a\' + 10; };\n'
            '            in[i] = (uint8_t)((hx(argv[1][1 + 2*i]) << 4) | hx(argv[1][2 + 2*i]));\n'
            '        }\n'
            '        WBAES wb2; wb2.init(); wb2.encrypt(in, o);\n'
            '        for (int i = 0; i < 16; i++) printf("%02x", o[i]);\n'
            '        printf("\\n"); return 0;\n'
            '    }\n'
            '    WBAES wb;\n    wb.init();')
        if "ct of a hex block" not in probe_src:
            raise SystemExit("probe anchor not found")
        open(os.path.join(out, "demo_wbaes_probe.cpp"), "w").write(probe_src)
        run([clang] + FLAGS + ["-I" + out, "-I" + src_dir, "demo_wbaes_probe.cpp",
                               "hy_tab.S", "wbaes_vm.o", "-o", "wbaes_hard_probe_raw"], cwd=out)
        run([sys.executable, os.path.join(HERE, "macho_scrub.py"),
             "--in", os.path.join(out, "wbaes_hard_probe_raw"),
             "--out", os.path.join(out, "wbaes_hard_probe"), "--seed", a.seed + "|probe"])
        log["binary_probe"] = os.path.join(out, "wbaes_hard_probe")

    # ---- 9. optional bench build (M3) ---------------------------------
    if a.bench:
        b = open(os.path.join(src_dir, "bench_wbaes.cpp")).read()
        b = b.replace("uint8_t ct[16], pt[16], rt[16];",
                      "uint8_t ct[16], pt[16], rt[16], kp[16];\n"
                      "    wbaes_key::hy_kat_plaintext(kp);")
        b = b.replace("wbaes_key::test_pt", "kp")
        b = b.replace("const bool vec = memcmp(ct, wbaes_key::test_ct, 16) == 0;",
                      "const bool vec = wbaes_key::hy_fnv64(ct, 16) == HY_KAT_CT_FNV;")
        open(os.path.join(out, "bench_wbaes.cpp"), "w").write(b)
        run([clang] + FLAGS + ["-I" + out, "-I" + src_dir, "bench_wbaes.cpp",
                               "hy_tab.S", "wbaes_vm.o", "-o", "wbaes_hard_bench"], cwd=out)
        log["bench"] = os.path.join(out, "wbaes_hard_bench")

    # ---- 10. optional VM negative test (proves the renamed section still feeds
    #          the lowered bytecode) --------------------------------------
    if a.vmtest:
        run([clang] + FLAGS + ["-DWBAES_VM_SCHEDTEST", "-I" + out, "-I" + src_dir,
                               os.path.join(HERE, "vm_negative_test.cpp"), "hy_tab.S",
                               "wbaes_vm.o", "-o", "wbaes_hard_vmtest"], cwd=out)
        r = subprocess.run([os.path.join(out, "wbaes_hard_vmtest")], capture_output=True, text=True)
        log["vm_negative"] = r.stdout.strip().splitlines()[-1]
        if r.returncode != 0:
            raise SystemExit("VM negative test failed on the hardened build")

    # ---- 11. optional M1 score of the result ---------------------------
    if a.m1:
        r = subprocess.run([sys.executable, os.path.join(HERE, "m1_detect.py"),
                            "--bin", log["binary"], "--seal", src_dir, "--json"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("m1_detect failed: " + r.stderr[-2000:])
        m1 = json.loads(r.stdout)
        log["m1"] = {"score": m1["score"],
                     "per_signal": {k: v["points"] for k, v in m1["signals"].items()}}

    json.dump(log, open(os.path.join(out, "harden_log.json"), "w"), indent=2)
    print(json.dumps({"kat": log["kat"], "run": log["run"],
                      "binary": log["binary"], "size": os.path.getsize(log["binary"])}, indent=2))
    print("scrub:", json.dumps(scrub))


if __name__ == "__main__":
    main()
