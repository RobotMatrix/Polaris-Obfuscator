#!/usr/bin/env python3
"""Build and run the randomised trace harness on a copy of the runtime.

Nothing in demos/wbaes is written: patch_header.py emits the randomised header
into the work directory, this script patches that copy with the five HY_TRACE
hooks (reusing trace_harness/build_traces.py's own hook table, so the hook sites
are byte-identical to the shipped harness), compiles harness_rnd.cpp against it,
and runs it.

Every block is seeded from a counter, and the seed is written to <prefix>_seeds.bin
next to the traces, so the permutation of every recorded trace is reproducible.

usage:
  python3 rnd/rnd_traces.py --k 16 --n 4096 --work /tmp/wbaes-rnd/k16
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
ATK = os.path.join(REPO, "demos", "wbaes", "attacks")
sys.path.insert(0, ATK)
sys.path.insert(0, os.path.join(ATK, "trace_harness"))
import wblib as wb
import build_traces as BT

BIN = os.path.join(REPO, "exported-binaries", "wbaes-challenge", "macos", "wbaes_vm2_clean")
CXX = os.path.join(REPO, "src", "build", "bin", "clang++")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=0, help="dummy table reads per round")
    ap.add_argument("--shuffle", type=int, default=None, help="default: 1 if k>0 else 0")
    ap.add_argument("--n", type=int, default=4096)
    ap.add_argument("--seed", default="0xC0FFEE01", help="base seed mixed with the block counter")
    ap.add_argument("--work", required=True)
    ap.add_argument("--binary", default=BIN)
    ap.add_argument("--cxx", default=CXX)
    ap.add_argument("--rebuild", action="store_true")
    a = ap.parse_args(argv)
    shuf = a.shuffle if a.shuffle is not None else (1 if a.k > 0 else 0)
    os.makedirs(a.work, exist_ok=True)

    env = wb.hy_env_mix(*wb.DEFAULT_ENV)

    # unmasked table + round-0 input bijection, both out of the shipped artifact
    tabf = os.path.join(a.work, "table_plain.bin")
    wb.load_plain_table(a.binary, cache=tabf)
    data = open(a.binary, "rb").read()
    hits = wb.find_input_bijection(data)
    p0f = os.path.join(a.work, "p0.bin")
    with open(p0f, "wb") as f:
        f.write(data[hits[0][0]:hits[0][0] + 4096])

    # randomised header (copy) + trace hooks (same table the shipped harness uses)
    hdr = os.path.join(a.work, "wbaes_hybrid_rnd.h")
    if a.rebuild or not os.path.exists(hdr):
        subprocess.run([sys.executable, os.path.join(HERE, "patch_header.py"), "--out", hdr],
                       check=True)
    with open(os.path.join(a.work, "hy_trace.h"), "w") as f:
        f.write(BT.patch_header(open(hdr).read(), env))

    exe = os.path.join(a.work, "harness_rnd_k%d_s%d" % (a.k, shuf))
    if a.rebuild or not os.path.exists(exe):
        subprocess.run([a.cxx, "-std=c++17", "-O2", "-I", a.work,
                        "-DHY_RND_K=%d" % a.k, "-DHY_RND_SHUFFLE=%d" % shuf,
                        "-o", exe, os.path.join(HERE, "harness_rnd.cpp")], check=True)

    pre = os.path.join(a.work, "rnd_k%d_s%d" % (a.k, shuf))
    out = subprocess.run([exe, tabf, p0f, str(a.n), a.seed, pre],
                         check=True, capture_output=True, text=True).stdout
    print("== K=%d shuffle=%d n=%d" % (a.k, shuf, a.n))
    print(out.strip())
    print("prefix: %s" % pre)
    return 0


if __name__ == "__main__":
    sys.exit(main())
