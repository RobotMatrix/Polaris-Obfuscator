#!/usr/bin/env python3
# 汇总 bench 3 次运行 → 每指标中位数 + OBF/PLAIN 开销倍率
import sys, statistics, re

def parse(path):
    runs = []
    cur = {}
    for line in open(path):
        line = line.strip()
        m = re.match(r"^(\w+) ([\d.]+)( acc [\d.]+)?$", line)
        if m:
            key, val = m.group(1), float(m.group(2))
            cur[key] = val
            if key.startswith("risk_infer") or "bench done" in line:
                runs.append(cur)
                cur = {}
        if line == "bench done" and cur:
            runs.append(cur)
            cur = {}
    if not runs:
        return {}
    keys = runs[-1].keys() if runs else []
    return {k: statistics.median([r.get(k, float("nan")) for r in runs]) for k in keys}

plain = parse(sys.argv[1])
obf = parse(sys.argv[2])
print("bench_median_ms plain obf overhead_x")
total_p = total_o = 0.0
for k in plain:
    p, o = plain[k], obf.get(k, float("nan"))
    if o != o:
        print(f"{k} {p:.3f} MISSING FAIL")
        continue
    ratio = o / p if p > 0 else float("nan")
    print(f"bench_{k} {p:.3f} {o:.3f} {ratio:.2f}")
    total_p += p
    total_o += o
if total_p > 0:
    print(f"bench_TOTAL {total_p:.3f} {total_o:.3f} {total_o/total_p:.2f}")
