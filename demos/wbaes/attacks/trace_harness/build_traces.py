#!/usr/bin/env python3
"""Build the trace-enabled harness in a scratch directory and run it.

Nothing in demos/wbaes is modified: the runtime header is copied, the five
load/store helpers get a HY_TRACE hook, and the copy plus harness.cpp are compiled
with clang++. The table bytes come from the shipped artifact (section __hytab), the
round-0 input bijection from its __TEXT,__const, and the mask seed is located by the
schedule-block test.

usage: python3 build_traces.py [--binary BIN] [--n 64] [--work DIR] [--repo DIR]
                               [--keep-header] [--cxx clang++]
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import wblib as wb

HOOKS = [
    # hy_load32 (16-bit Feistel scatter, 32-bit entry)
    ("""    const uint8_t *p = tab + off + (uint32_t)s * 4u;
    return (uint32_t)p[0]""",
     """    const uint8_t *p = tab + off + (uint32_t)s * 4u;
    HY_TRACE(off + (uint32_t)s * 4u, logical, 4);
    return (uint32_t)p[0]"""),
    # hy_load8 (16-bit Feistel scatter)
    ("""    uint16_t s = hy_scatter(logical, env, tag);
    return tab[off + s];""",
     """    uint16_t s = hy_scatter(logical, env, tag);
    HY_TRACE(off + s, logical, 1);
    return tab[off + s];"""),
    # hy_load16 (pair-map tables)
    ("""    const uint8_t *p = tab + off + (uint32_t)s * 2u;
    return (uint16_t)(p[0]""",
     """    const uint8_t *p = tab + off + (uint32_t)s * 2u;
    HY_TRACE(off + (uint32_t)s * 2u, logical, 2);
    return (uint16_t)(p[0]"""),
    # hy_load32t (byte-indexed, affine scatter)
    ("""    const uint8_t *p = tab + off + (uint32_t)hy_scatter8(logical, env, tag) * 4u;
    return (uint32_t)p[0]""",
     """    const uint8_t *p = tab + off + (uint32_t)hy_scatter8(logical, env, tag) * 4u;
    HY_TRACE(off + (uint32_t)hy_scatter8(logical, env, tag) * 4u, logical, 4);
    return (uint32_t)p[0]"""),
    # hy_load8t (byte-indexed, affine scatter)
    ("""    return tab[off + hy_scatter8(logical, env, tag)];""",
     """    HY_TRACE(off + hy_scatter8(logical, env, tag), logical, 1);
    return tab[off + hy_scatter8(logical, env, tag)];"""),
]


def patch_header(src_text, env):
    for a, b in HOOKS:
        if src_text.count(a) != 1:
            raise SystemExit("header changed: hook anchor not found exactly once:\n%s"
                             % a.splitlines()[0])
    out = src_text
    for a, b in HOOKS:
        out = out.replace(a, b)
    out += "\n// injected by attacks/trace_harness/build_traces.py\n#define HY_ENV 0x%08xu\n" % env
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--binary", default=wb.DEFAULT_BIN)
    ap.add_argument("--repo", default=os.path.abspath(os.path.join(HERE, "..", "..", "..", "..")))
    ap.add_argument("--work", default=None, help="scratch dir (default: TMPDIR/wbaes-traces)")
    ap.add_argument("--n", type=int, default=64)
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--cxx", default="clang++")
    a = ap.parse_args(argv)

    work = a.work or os.path.join(os.environ.get("TMPDIR", "/tmp"), "wbaes-traces")
    os.makedirs(work, exist_ok=True)
    env = wb.hy_env_mix(a.pagesize, a.ncpu, a.cls)

    # 1. table section, round-0 bijection, mask seed
    tab_off, tab_size = wb.find_section(a.binary, "__hytab")
    data = open(a.binary, "rb").read()
    with open(os.path.join(work, "table_masked.bin"), "wb") as f:
        f.write(data[tab_off:tab_off + tab_size])
    hits = wb.find_input_bijection(data)
    if not hits:
        raise SystemExit("no round-0 input bijection in %s" % a.binary)
    p0_off = hits[0][0]
    with open(os.path.join(work, "p0.bin"), "wb") as f:
        f.write(data[p0_off:p0_off + 4096])
    seed, frag_off, tried = wb.find_mask_seed(a.binary, tab_off, tab_size)
    print("binary  : %s" % a.binary)
    print("table   : __hytab at 0x%x, %d bytes" % (tab_off, tab_size))
    print("P0      : __const + 0x%x" % (p0_off - wb.find_section_hdr(data, "__const")[0]))
    print("seed    : 0x%08x (%d candidates tried)" % (seed, tried))

    # 2. patched runtime header (copy only)
    hdr = os.path.join(a.repo, "demos", "wbaes", "wbaes_hybrid.h")
    text = open(hdr).read()
    with open(os.path.join(work, "hy_trace.h"), "w") as f:
        f.write(patch_header(text, env))
    print("header  : %s -> %s/hy_trace.h (5 hooks)" % (hdr, work))

    # 3. compile + run
    exe = os.path.join(work, "harness")
    cmd = [a.cxx, "-std=c++17", "-O2", "-I", work, "-o", exe,
           os.path.join(HERE, "harness.cpp")]
    subprocess.run(cmd, check=True)
    run = [exe, os.path.join(work, "table_masked.bin"), os.path.join(work, "p0.bin"),
           hex(seed), str(a.n), os.path.join(work, "dl4")]
    out = subprocess.run(run, check=True, capture_output=True, text=True).stdout
    print(out.strip())
    print("traces  : %s/dl4_traces.bin (+ dl4_pts.bin, dl4_table_plain.bin)" % work)
    print("\nrun: python3 %s/dca_attack.py --traces %s/dl4_traces.bin"
          % (os.path.dirname(HERE), work))
    return 0


if __name__ == "__main__":
    sys.exit(main())
