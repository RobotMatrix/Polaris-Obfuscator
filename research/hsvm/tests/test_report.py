#!/usr/bin/env python3
"""Tests for tools/report.py: every rule gets a negative case."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(HERE, "..", "tools", "report.py")

ok = True


def check(cond, name):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    ok = ok and bool(cond)


BASE = {
    "run_id": "2026-11-17T07:00:00Z-g0",
    "gate": "G0",
    "created_at": "2026-11-17T07:00:00Z",
    "git_commit": "10394237732a666f0a097611b90c7e193ca1e478",
    "params_hash": "c5724bc3cf403a42",
    "protocol_sha256": "f964755dcd2587ee0772d210fd1597024f40bbba20c7c194c02c991983515c1f",
    "attacker_model": "A2",
    "seeds": [1001, 1002],
    "metrics": {"a1_seconds": 12.5, "coverage": 1.0},
    "queries_used": 4096,
    "censored": False,
    "raw_log": "raw.jsonl",
    "evidence": ["attacks/a1_trace_diff.py"],
}


def run_case(doc, name, expect_ok, needle=None, make_raw=True):
    with tempfile.TemporaryDirectory() as td:
        if make_raw:
            with open(os.path.join(td, "raw.jsonl"), "w", encoding="utf-8") as fh:
                fh.write('{"t":0}\n')
        path = os.path.join(td, "run.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        res = subprocess.run([sys.executable, REPORT, "validate", path],
                             capture_output=True, text=True)
    good = res.returncode == 0
    check(good == expect_ok, name)
    if needle and not expect_ok and res.returncode != 0:
        check(needle in res.stderr, name + " -> right reason")


def main():
    run_case(BASE, "valid report accepted", True)

    d = dict(BASE)
    d["raw_log"] = "missing.jsonl"
    run_case(d, "missing raw log rejected", False, "does not exist")

    d = dict(BASE)
    d["metrics"] = {"interpolation_success_rate": 0.004}
    d["queries_used"] = 0
    run_case(d, "success metric with zero queries rejected", False,
             "queries_used == 0")

    d = dict(BASE)
    d["metrics"] = {"interpolation_success_rate": 0.02}
    d["censored"] = True
    run_case(d, "censored run with positive success rate rejected", False,
             "may not report")

    d = dict(BASE)
    d["metrics"] = {"interpolation_success_rate": 0.0}
    d["censored"] = True
    run_case(d, "censored run with zero success rate accepted", True)

    d = dict(BASE)
    d["budget"] = 8192
    d["queries_used"] = 4096
    d["censored"] = False
    run_case(d, "unexhausted budget without censoring rejected", False,
             "censored must be true")

    d = dict(BASE)
    d["budget"] = 8192
    d["queries_used"] = 4096
    d["censored"] = True
    run_case(d, "unexhausted budget with censoring accepted", True)

    d = dict(BASE)
    d["queries_used"] = 9000
    d["budget"] = 8192
    run_case(d, "queries above budget rejected", False, "must not exceed")

    d = dict(BASE)
    d["params_hash"] = "nothex"
    run_case(d, "bad params hash rejected", False, "params_hash")

    d = dict(BASE)
    d["evidence"] = []
    run_case(d, "empty evidence rejected", False, "evidence")

    d = dict(BASE)
    d["gate"] = "G9"
    run_case(d, "unknown gate rejected", False, "gate must look like")

    d = dict(BASE)
    d["metrics"] = {"r_plain": 2.4}
    d["queries_used"] = 0
    run_case(d, "non-attack metric needs no queries", True)

    # --- statistics ---
    res = subprocess.run([sys.executable, REPORT, "stats", "--values",
                          "1,2,3,4"], capture_output=True, text=True)
    st = json.loads(res.stdout)
    check(res.returncode == 0, "stats runs")
    check(st["median"] == 2.5, "median of 1,2,3,4 is 2.5")
    check(abs(st["p5"] - 1.15) < 1e-9, "p5 uses linear interpolation (1.15)")
    check(st["mean"] == 2.5, "mean of 1,2,3,4 is 2.5")
    check(st["min"] == 1.0 and st["max"] == 4.0, "min/max are correct")

    res = subprocess.run([sys.executable, REPORT, "wilson", "--successes", "0",
                          "--trials", "16"], capture_output=True, text=True)
    ci = json.loads(res.stdout)
    check(ci["lo"] == 0.0, "Wilson lower bound clamps to 0")
    check(0.18 < ci["hi"] < 0.21, "Wilson upper bound ~0.194 for 0/16")

    res = subprocess.run([sys.executable, REPORT, "wilson", "--successes", "16",
                          "--trials", "16"], capture_output=True, text=True)
    ci = json.loads(res.stdout)
    check(ci["hi"] == 1.0 and 0.75 < ci["lo"] < 0.82,
          "Wilson bounds for 16/16 are sane")

    print("== report: %s ==" % ("all pass" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
