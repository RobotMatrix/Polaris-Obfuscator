#!/usr/bin/env python3
"""Validate hsvm_params output as JSON (stdlib only).

The C++ test already checks validation rules. This test checks the interface
the reports depend on: one parseable JSON object, stable bytes for the same
point, and non-zero exits for bad input.
"""
import json
import subprocess
import sys

TOOL = sys.argv[1] if len(sys.argv) > 1 else "./build/hsvm_params"

ok = True


def check(cond, name):
    global ok
    print(("  [PASS] " if cond else "  [FAIL] ") + name)
    ok = ok and bool(cond)


def run(*args):
    return subprocess.run([TOOL, *args], capture_output=True, text=True)


TABLE = ["--n", "512", "--m", "256", "--w", "8", "--c", "8", "--rbar", "2",
         "--rounds", "0", "--psi", "table", "--workload", "crc32",
         "--seed", "12345"]


def main():
    r = run(*TABLE)
    check(r.returncode == 0, "valid point exits 0")
    if r.returncode != 0:
        print(r.stderr)
        return 1

    doc = json.loads(r.stdout)  # raises if the tool emits invalid JSON
    check(doc["params"]["n"] == 512, "params.n round-trips")
    check(doc["params"]["workload"] == "crc32", "workload round-trips")
    h = doc["params_hash"]
    check(len(h) == 16, "params_hash is 16 chars")
    check(all(c in "0123456789abcdef" for c in h), "params_hash is lowercase hex")

    prov = doc["provenance"]
    check(prov["git_commit"] != "unknown", "provenance has a real commit")
    check(len(prov["git_commit"]) >= 7, "commit looks like a SHA")
    check("kernel_version" in prov, "provenance has kernel_version")

    r2 = run(*TABLE)
    check(r2.stdout == r.stdout, "same point -> byte-identical JSON")
    d2 = json.loads(r2.stdout)
    check(d2["params_hash"] == h, "same point -> same params_hash")

    spn = ["--n", "512", "--m", "256", "--w", "48", "--c", "16", "--rbar",
           "4", "--rounds", "4", "--psi", "spn", "--workload", "bignum",
           "--seed", "987654321"]
    rs = run(*spn)
    check(rs.returncode == 0, "spn point exits 0")
    if rs.returncode == 0:
        ds = json.loads(rs.stdout)
        check(ds["params"]["psi"] == "spn", "psi mode round-trips")
        check(ds["params_hash"] != h, "different point -> different hash")

    bad = run("--n", "512", "--m", "512", "--w", "8", "--c", "8", "--rbar",
              "2", "--rounds", "0", "--psi", "table", "--workload", "crc32",
              "--seed", "1")
    check(bad.returncode == 2, "invalid point exits 2")
    check("invalid parameter point" in bad.stderr, "invalid point explains why")

    usage = run("--n", "512")
    check(usage.returncode == 3, "missing arguments exits 3")

    print("== params_json: %s ==" % ("all pass" if ok else "FAILURES"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
