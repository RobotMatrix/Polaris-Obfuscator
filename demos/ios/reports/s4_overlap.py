"""s4_overlap.py -- how much of the split's observable signature transfers
between two builds of the same source (different -obf-seed).

The observable signature of a split function, once the names are gone, is the
sequence of chunk boundaries inside it: the chunk count and the offsets of the
chunk starts relative to the function's first chunk.  This compares that
sequence between two builds:

  * chunk counts per function (from the -split-symbols sidecar)
  * Jaccard overlap of the *boundary offset sets* per function
  * whether the sequence of chunk sizes is identical

Usage:
  python3 s4_overlap.py A.bin A.tsv B.bin B.tsv
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "wbaes", "attacks", "residual"))
sys.path.insert(0, HERE)
import macho_symbols as MS            # noqa: E402
from s4_measure import read_split_sidecar, resolve  # noqa: E402


def boundaries(bin_path, side_path):
    """{fn: [offset of each chunk start relative to the function's first]}, and
    the sorted size sequence per function."""
    b = MS.parse(bin_path)
    _fns, chunks, _seed = read_split_sidecar(side_path)
    got = resolve(b, chunks)
    out = {}
    for c in got:
        out.setdefault(c["fn"], []).append(c["addr"])
    res = {}
    for fn, addrs in out.items():
        addrs.sort()
        base = addrs[0]
        offs = [a - base for a in addrs]
        sizes = [offs[i + 1] - offs[i] for i in range(len(offs) - 1)]
        res[fn] = dict(offsets=offs, sizes=sizes)
    return res


def jaccard(a, b):
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def main():
    a_bin, a_side, b_bin, b_side = sys.argv[1:5]
    A = boundaries(a_bin, a_side)
    B = boundaries(b_bin, b_side)
    all_fns = sorted(set(A) | set(B))
    print(f"{'function':42s} {'chunks A':>8s} {'chunks B':>8s} "
          f"{'offset Jaccard':>14s} {'same size seq':>13s}")
    tot_a = tot_b = 0
    jac = []
    for fn in all_fns:
        a = A.get(fn, dict(offsets=[], sizes=[]))
        b = B.get(fn, dict(offsets=[], sizes=[]))
        tot_a += len(a["offsets"])
        tot_b += len(b["offsets"])
        j = jaccard(a["offsets"], b["offsets"])
        jac.append(j)
        same = "yes" if a["sizes"] == b["sizes"] else "no"
        print(f"{fn:42s} {len(a['offsets']):8d} {len(b['offsets']):8d} "
              f"{j:14.3f} {same:>13s}")
    print(f"{'total':42s} {tot_a:8d} {tot_b:8d} "
          f"{sum(jac) / len(jac) if jac else 0:14.3f}")


if __name__ == "__main__":
    main()
