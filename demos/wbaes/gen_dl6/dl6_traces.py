#!/usr/bin/env python3
"""Build the dl6 trace harness and benchmark against one generated table.

Mirrors attacks/trace_harness/build_traces.py, but for the dl6 header (which has the
round-0 key layer) and for a table produced by gen_dl6 in a scratch directory rather
than a Mach-O section: the round-0 input bijection comes from the hy_in.h the
generator wrote next to the table, the mask seed from hy_seal.h.

The header copy gets the same three HY_TRACE hooks the committed harness uses, so
the traces are (offset, pre-scatter logical index, width) for every table access.

usage: python3 dl6_traces.py --table T --work W [--n 64] [--build DIR] [--cxx clang++]
"""

import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ATTACKS = os.path.abspath(os.path.join(HERE, "..", "attacks"))
sys.path.insert(0, REPO_ATTACKS)
import wblib as wb

HOOKS = [
    # hy_load32 (16-bit Feistel scatter, 32-bit entry) - the F1/F3 lane tables
    ("""    const uint8_t *p = tab + off + (uint32_t)s * 4u;
    return (uint32_t)p[0]""",
     """    const uint8_t *p = tab + off + (uint32_t)s * 4u;
    HY_TRACE(off + (uint32_t)s * 4u, logical, 4);
    return (uint32_t)p[0]"""),
    # hy_load32t (byte-indexed, affine scatter)
    ("""    const uint8_t *p = tab + off + (uint32_t)hy_scatter8(logical, env, tag) * 4u;
    return (uint32_t)p[0]""",
     """    const uint8_t *p = tab + off + (uint32_t)hy_scatter8(logical, env, tag) * 4u;
    HY_TRACE(off + (uint32_t)hy_scatter8(logical, env, tag) * 4u, logical, 4);
    return (uint32_t)p[0]"""),
    ("""    uint16_t s = hy_scatter(logical, env, tag);
    return tab[off + s];""",
     """    uint16_t s = hy_scatter(logical, env, tag);
    HY_TRACE(off + s, logical, 1);
    return tab[off + s];"""),
    ("""    const uint8_t *p = tab + off + (uint32_t)s * 2u;
    return (uint16_t)(p[0]""",
     """    const uint8_t *p = tab + off + (uint32_t)s * 2u;
    HY_TRACE(off + (uint32_t)s * 2u, logical, 2);
    return (uint16_t)(p[0]"""),
    ("""    return tab[off + hy_scatter8(logical, env, tag)];""",
     """    HY_TRACE(off + hy_scatter8(logical, env, tag), logical, 1);
    return tab[off + hy_scatter8(logical, env, tag)];"""),
]

PY_IN_H = re.compile(r"static const unsigned char HY_P0\[16\]\[256\] = \{(.*?)\n\};", re.S)
PY_SEAL = re.compile(r"HY_SEED_FRAG\[4\] = \{([^}]*)\}")


def patch_header(text, env):
    for a, _b in HOOKS:
        if text.count(a) != 1:
            raise SystemExit("hook anchor not found exactly once:\n%s" % a.splitlines()[0])
    out = text
    for a, b in HOOKS:
        out = out.replace(a, b)
    out += "\n// injected by gen_dl6/dl6_traces.py\n#define HY_ENV 0x%08xu\n" % env
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--table", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--n", type=int, default=64)
    ap.add_argument("--build", default=None)
    ap.add_argument("--pagesize", type=int, default=wb.DEFAULT_ENV[0])
    ap.add_argument("--ncpu", type=int, default=wb.DEFAULT_ENV[1])
    ap.add_argument("--cls", type=int, default=wb.DEFAULT_ENV[2])
    ap.add_argument("--cxx", default="clang++")
    ap.add_argument("--bench-n", type=int, default=4000)
    a = ap.parse_args(argv)

    build = a.build or os.path.join(a.work, "build")
    os.makedirs(build, exist_ok=True)
    env = wb.hy_env_mix(a.pagesize, a.ncpu, a.cls)

    # round-0 input bijection and mask seed, straight from what the generator wrote
    in_h = open(os.path.join(a.work, "hy_in.h")).read()
    m = PY_IN_H.search(in_h)
    if not m:
        raise SystemExit("no HY_P0 block in %s/hy_in.h" % a.work)
    vals = [int(x) for x in re.findall(r"\d+", m.group(1))]
    if len(vals) != 16 * 256:
        raise SystemExit("HY_P0 block has %d values" % len(vals))
    with open(os.path.join(build, "p0.bin"), "wb") as f:
        f.write(bytes(vals))
    seal = open(os.path.join(a.work, "hy_seal.h")).read()
    words = [int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]+)", PY_SEAL.search(seal).group(1))]
    seed = words[0] ^ words[1] ^ words[2] ^ words[3]
    print("p0      : %s/hy_in.h -> %s/p0.bin" % (a.work, build))
    print("seed    : 0x%08x (XOR of the four hy_seal.h words)" % seed)

    hdr = os.path.join(HERE, "wbaes_hybrid_dl6.h")
    with open(os.path.join(build, "hy_trace.h"), "w") as f:
        f.write(patch_header(open(hdr).read(), env))
    print("header  : %s -> %s/hy_trace.h (5 hooks)" % (hdr, build))

    for src, exe in (("dl6_harness.cpp", "dl6_harness"), ("dl6_bench.cpp", "dl6_bench")):
        subprocess.run([a.cxx, "-std=c++17", "-O2", "-I", build, "-o",
                        os.path.join(build, exe), os.path.join(HERE, src)], check=True)
    masked = os.path.join(a.work, os.path.basename(a.table))
    run = [os.path.join(build, "dl6_harness"), masked, os.path.join(build, "p0.bin"),
           hex(seed), str(a.n), os.path.join(build, "dl6")]
    out = subprocess.run(run, check=True, capture_output=True, text=True).stdout
    print(out.strip())
    bench = [os.path.join(build, "dl6_bench"), masked, os.path.join(build, "p0.bin"),
             hex(seed), str(a.bench_n)]
    print(subprocess.run(bench, check=True, capture_output=True, text=True).stdout.strip())
    print("traces  : %s/dl6_traces.bin (+ dl6_pts.bin, dl6_table_plain.bin)" % build)
    return 0


if __name__ == "__main__":
    sys.exit(main())
