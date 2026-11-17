#!/usr/bin/env python3
"""Mutation tests for tools/check_protocol.py.

A checker that only accepts the real protocol proves nothing. Each case below
breaks exactly one pre-registration rule and expects a non-zero exit.
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROTOCOL = os.path.join(HERE, "..", "protocol.json")
CHECKER = os.path.join(HERE, "..", "tools", "check_protocol.py")
PARAMS_TOOL = sys.argv[1] if len(sys.argv) > 1 else None

ok = True


def check(cond, name):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    ok = ok and bool(cond)


def run_with(doc, extra=()):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(doc, fh)
        path = fh.name
    try:
        return subprocess.run([sys.executable, CHECKER, path, *extra],
                              capture_output=True, text=True)
    finally:
        os.unlink(path)


def main():
    with open(PROTOCOL, "r", encoding="utf-8") as fh:
        base = json.load(fh)

    good = run_with(base)
    check(good.returncode == 0, "real protocol is accepted")
    m = re.search(r"protocol_sha256=([0-9a-f]{64})", good.stdout)
    check(m is not None, "checker prints a 64-hex protocol hash")
    h1 = m.group(1) if m else ""

    good2 = run_with(base)
    m3 = re.search(r"protocol_sha256=([0-9a-f]{64})", good2.stdout)
    check(bool(h1) and m3 is not None and m3.group(1) == h1,
          "hash is deterministic")

    # Reformatting the file must not change the hash (canonical form only).
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(base, fh, indent=4, sort_keys=True)
        reformatted = fh.name
    try:
        r = subprocess.run([sys.executable, CHECKER, reformatted],
                           capture_output=True, text=True)
        check(r.returncode == 0 and h1 in r.stdout,
              "hash is independent of file formatting")
    finally:
        os.unlink(reformatted)

    def expect_fail(mutate, name, needle=None):
        doc = copy.deepcopy(base)
        mutate(doc)
        res = run_with(doc)
        good_exit = res.returncode != 0
        check(good_exit, name + " is rejected")
        if needle and good_exit:
            check(needle in res.stderr,
                  name + " reports the right reason")

    expect_fail(lambda d: d.pop("hypothesis"), "missing hypothesis",
                "missing top-level key")
    expect_fail(lambda d: d["hypothesis"].update(query_budget=2 ** 40 + 1),
                "non-power-of-two budget", "power of two")
    expect_fail(lambda d: d["stage1"].update(query_budget=2 ** 41),
                "stage1 budget above hypothesis budget", "must not exceed")
    expect_fail(lambda d: d["workload"][0].update(weight=0.1),
                "workload weights not summing to 1", "sum to 1")
    expect_fail(lambda d: d["seeds"].append(d["seeds"][0]),
                "duplicate seed", "unique")
    expect_fail(lambda d: d["seeds"].__setitem__(0, 0),
                "zero seed", "nonzero")
    expect_fail(lambda d: d["seeds"].clear(), "empty seeds", "non-empty")
    expect_fail(lambda d: d["stop_rules"].pop(), "missing stop rule",
                "stop_rules must include")
    expect_fail(lambda d: d["reporting"]["required_fields"].remove("raw_log"),
                "missing required report field", "required_fields is missing")
    expect_fail(lambda d: d["params_grid"].update(w=[24]),
                "illegal grid (spn w not multiple of 8)", "no legal")
    expect_fail(
        lambda d: d.update(chosen_point={"n": 512, "m": 512, "w": 8, "c": 8,
                                         "r_bar": 2, "rounds": 0,
                                         "psi": "table"}),
        "illegal chosen_point", "violates the parameter rules")
    expect_fail(
        lambda d: d.update(chosen_point={"n": 512, "m": 256, "w": 24, "c": 8,
                                         "r_bar": 2, "rounds": 2,
                                         "psi": "spn"}),
        "chosen_point outside the grid", "not one of the registered")

    # A legal chosen point must be accepted, and must change the hash.
    doc = copy.deepcopy(base)
    doc["chosen_point"] = {"n": 512, "m": 256, "w": 64, "c": 16, "r_bar": 4,
                           "rounds": 4, "psi": "spn"}
    res = run_with(doc)
    check(res.returncode == 0, "legal chosen_point is accepted")
    m2 = re.search(r"protocol_sha256=([0-9a-f]{64})", res.stdout)
    check(m2 is not None and m2.group(1) != h1,
          "setting chosen_point changes the protocol hash")

    if PARAMS_TOOL:
        res = run_with(doc, ("--params-tool", PARAMS_TOOL))
        check(res.returncode == 0, "C++ params tool accepts chosen_point")
        bad = copy.deepcopy(doc)
        bad["chosen_point"]["rounds"] = 0  # spn needs rounds >= 1
        res = run_with(bad, ("--params-tool", PARAMS_TOOL))
        check(res.returncode != 0, "C++ params tool rejects an illegal point")

    print("== protocol: %s ==" % ("all pass" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
