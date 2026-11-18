"""Per-process timing for the S2 computed-branch measurement.

Runs each variant N times per round (default 40) for R rounds (default 3),
alternating the variants inside a round so drift hits all of them, and reports
the median of the per-process "ns per call" line that demo6_bench.cpp prints.

  python3 s2_bench.py --iters 20000 B_base B_cb B_all
"""
import argparse
import statistics
import subprocess
import time


def run(exe, iters):
    t0 = time.perf_counter()
    out = subprocess.run([exe, str(iters)], capture_output=True, text=True)
    wall = (time.perf_counter() - t0) * 1e3
    ns, chk = out.stdout.split()
    return float(ns), wall, chk, out.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bins", nargs="+")
    ap.add_argument("--iters", type=int, default=20000)
    ap.add_argument("--procs", type=int, default=40)
    ap.add_argument("--rounds", type=int, default=3)
    a = ap.parse_args()

    data = {b: {"ns": [], "wall": [], "chk": set(), "rc": set()} for b in a.bins}
    for r in range(a.rounds):
        for _ in range(a.procs):
            for b in a.bins:
                ns, wall, chk, rc = run(b, a.iters)
                data[b]["ns"].append(ns)
                data[b]["wall"].append(wall)
                data[b]["chk"].add(chk)
                data[b]["rc"].add(rc)
        print("round %d: " % (r + 1) + "  ".join(
            "%s=%.1f ns" % (b.split("/")[-1], statistics.median(data[b]["ns"]))
            for b in a.bins))

    base = statistics.median(data[a.bins[0]]["ns"])
    print()
    print("%-28s %10s %10s %10s %8s" %
          ("variant", "ns/call", "proc ms", "checksum", "delta"))
    for b in a.bins:
        med = statistics.median(data[b]["ns"])
        print("%-28s %10.1f %10.2f %10s %+7.1f%%" %
              (b.split("/")[-1], med, statistics.median(data[b]["wall"]),
               ",".join(sorted(data[b]["chk"])), (med / base - 1) * 100))


if __name__ == "__main__":
    main()
