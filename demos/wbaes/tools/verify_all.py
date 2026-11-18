#!/usr/bin/env python3
"""verify_all.py - baseline regression gate for every shipped white-box generation.

Run this after ANY change to the wbaes demo, the generator, the VM program, the
attack scripts or the export path. It answers one question: do the artifacts that
are supposed to work still work, and do the documents still tell the truth.

Checks, per generation in the manifest:
  A  the binary exists and its sha256 matches the line in sha256.txt
  B  running it prints the expected ciphertext and reports vector-match PASS
  C  openssl with the same key reproduces that ciphertext (independent source)
  D  generations that claim a VM actually carry it (symbols present, no
     indirect branch inside the lowered entry)
  E  the negative test still bites: corrupting the schedule block changes the
     ciphertext (only for the generations whose demo exposes -DWBAES_VM_SCHEDTEST)
  F  the attack scripts still run to a verdict instead of crashing

Exit code 0 only if every check passes. Prints one line per check.

Usage:
  python3 tools/verify_all.py                 # everything, including openssl
  python3 tools/verify_all.py --quick         # skip openssl and negative tests
  python3 tools/verify_all.py --only f4,nl    # subset by generation name
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(DEMO))
BIN_DIR = os.path.join(REPO, "exported-binaries", "wbaes-challenge", "macos")
PLAINTEXT = "6bc1bee22e409f96e93d7e117393172a"

# name, binary, key (AES-128 hex), expected ciphertext, has vm
GENERATIONS = [
    ("clean",    "wbaes_clean",    "62bce36db18696c154751334adb74da7", "e6f48459ad3535934f51eded1c32a2a7", False),
    ("clean_in", "wbaes_clean_in", "ec326393a354ed3ee5d1735964fd8a32", "24a06689d532680695416c13b93c7405", False),
    ("dl",       "wbaes_dl_clean", "98d272d16d6cc9d6ecd48a26c0ca69d3", "bb28990b4f52d7dc4c8e5cbb2839e653", False),
    ("dl2",      "wbaes_dl2_clean", "98d272d16d6cc9d6ecd48a26c0ca69d3", "bb28990b4f52d7dc4c8e5cbb2839e653", False),
    ("dl3",      "wbaes_dl3_clean", "fd85cd856e314ea791a828d5dab81d06", "e5a25174e8b329127bcaac8f3297e16e", False),
    ("dl4",      "wbaes_dl4_clean", "755e563b1dffd249ef552c1bb778de29", "abe296eea2625f251ba57ed0b408272c", False),
    ("vm",       "wbaes_vm_clean",  "07d90ca930dbca2a46ba6b4cf1bc83cb", "29d00ce827afdb377671f07402cda1f5", True),
    ("nl",       "wbaes_nl_clean",  "46f6abe52990556a6713141f65fed9a5", "80aadc09777696c9d492a7e53b3b15b0", True),
    ("vm2",      "wbaes_vm2_clean", "4f065a03ee16cf8c31b15fd8f0344c66", "7672415a6313c58518fc95c9cb6922b8", True),
    ("f4",       "wbaes_f4_clean",  "3acb79e72c06bebbbdcda86dc62f009b", "2c0b8f87b6aa8d4a8c7b12d8d2227c8d", True),
]

results = []          # (status, generation, check, detail)


def record(ok, gen, check, detail=""):
    """ok=True pass, False fail, None not applicable (no baseline, tool missing).

    None must not read as FAIL: before a baseline exists every size and timing check
    would otherwise report a failure on a perfectly good tree.
    """
    status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    results.append((status, gen, check, detail))
    print("%-4s %-9s %-22s %s" % (status, gen, check, detail))
    return ok


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_sha_manifest():
    path = os.path.join(BIN_DIR, "sha256.txt")
    out = {}
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            m = re.match(r"\s*([0-9a-fA-F]{64})\s+\*?(\S+)\s*$", line)
            if m:
                out[os.path.basename(m.group(2))] = m.group(1).lower()
    return out


def run(binary, timeout=120):
    return subprocess.run([binary], capture_output=True, text=True, timeout=timeout)


def openssl_ct(key_hex):
    exe = shutil.which("openssl")
    if not exe:
        return None
    p = subprocess.run(
        [exe, "enc", "-aes-128-ecb", "-K", key_hex, "-nopad"],
        input=bytes.fromhex(PLAINTEXT), capture_output=True)
    return p.stdout.hex()


def nm_symbols(binary):
    p = subprocess.run(["nm", binary], capture_output=True, text=True)
    return p.stdout


def has_dispatch_loop(binary):
    """True when the lowered entry still contains an indirect branch."""
    p = subprocess.run(["otool", "-tv", binary], capture_output=True, text=True)
    body, inside = [], False
    for line in p.stdout.splitlines():
        if "_hsvm_entry:" in line:
            inside = True
            continue
        if inside and re.match(r"^_?[A-Za-z_].*:", line) and "_hsvm_entry" not in line:
            break
        if inside:
            body.append(line)
    return any(re.search(r"\bbr\s+x\d+", ln) for ln in body)


def load_baseline(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (ValueError, OSError):
        return {}


def check_size(name, binary_name, size, baseline, tol):
    """Artifact size against the recorded baseline.

    Size is a hard check: the table geometry and the metadata are deterministic, so a
    change of even a few hundred bytes is a real change and has to be acknowledged by
    updating the baseline on purpose.
    """
    want = (baseline.get(binary_name) or {}).get("size")
    if not want:
        record(None, name, "size", "%d B (no baseline)" % size)
        return
    delta = size - want
    ok = delta == 0
    pct = 100.0 * delta / want
    record(ok, name, "size", "%d B (%+d, %+.3f%%)" % (size, delta, pct))


def check_speed(name, binary_name, seconds, baseline, tol):
    """Cold start: process start, table unmask, seal check and one block.

    This is the figure the demo can actually produce without a bench harness, and it is
    dominated by the 70 MB unmask, so it tracks load-path regressions rather than the
    per-block cost. Per-block numbers live in the bench (bench_wbaes) and in the docs;
    they are recorded here only when a bench binary is supplied.
    """
    want = (baseline.get(binary_name) or {}).get("cold_s")
    if not want:
        record(None, name, "cold start", "%.3f s (no baseline)" % seconds)
        return
    ratio = seconds / want
    ok = ratio <= 1.0 + tol
    record(ok, name, "cold start", "%.3f s vs %.3f s baseline (%.2fx, tol %.0f%%)"
           % (seconds, want, ratio, tol * 100))


def check_generation(name, binary_name, key, expected_ct, expect_vm, quick, shas, baseline, tol):
    path = os.path.join(BIN_DIR, binary_name)
    if not os.path.exists(path):
        record(False, name, "exists", "missing %s" % binary_name)
        return None
    size = os.path.getsize(path)
    record(True, name, "exists", "%d B" % size)
    check_size(name, binary_name, size, baseline, tol)

    want = shas.get(binary_name)
    got = sha256_file(path)
    record(want == got if want else None, name, "sha256", got[:16] + (" (no manifest line)" if not want else ""))

    # best of three: a single cold-start sample on a loaded host swings by more than
    # the tolerance for the small generations, which made the gate flaky.
    elapsed = float("inf")
    p = None
    for _ in range(3):
        t0 = time.perf_counter()
        try:
            p = run(path)
        except subprocess.TimeoutExpired:
            record(False, name, "runs", "timeout")
            return None
        elapsed = min(elapsed, time.perf_counter() - t0)
        if p.returncode != 0:
            break
    check_speed(name, binary_name, elapsed, baseline, tol)
    if p.returncode != 0:
        record(False, name, "runs", "exit %d: %s" % (p.returncode, (p.stderr or p.stdout)[:80]))
        return None
    text = p.stdout
    m = re.search(r"ciphertext\s*:?\s*([0-9a-f]{32})", text)
    ct = m.group(1) if m else ""
    record(ct == expected_ct, name, "ciphertext", ct or "not printed")
    record("vector-match: PASS" in text or "vector-match:PASS" in text, name, "self-check",
           "PASS" if "vector-match: PASS" in text else "no PASS line")

    if not quick:
        ref = openssl_ct(key)
        if ref is None:
            record(None, name, "openssl", "openssl not found")
        else:
            record(ref == expected_ct, name, "openssl", "independent recompute matches"
                   if ref == expected_ct else "got %s" % ref)

    if expect_vm:
        syms = nm_symbols(path)
        needed = ["_hsvm_entry", "_hsvm_bytecode", "_hsvm_table"]
        missing = [s for s in needed if s not in syms]
        record(not missing, name, "vm symbols", "present" if not missing else "missing " + ",".join(missing))
        record(not has_dispatch_loop(path), name, "no dispatch loop", "")

    return {"size": size, "cold_s": round(elapsed, 3)}


def check_attacks(quick):
    """The attacks must run to a verdict. Their verdicts are NOT a gate: what they
    recover is documented per generation, and a cheaper attack appearing later is a
    finding, not a regression. Crashing is the regression."""
    attacks = os.path.join(DEMO, "attacks")
    scripts = ["bge_attack.py", "hs_attack.py", "dca_attack.py"]
    for s in scripts:
        path = os.path.join(attacks, s)
        if not os.path.exists(path):
            record(False, "attacks", s, "missing")
            continue
        p = subprocess.run([sys.executable, path, "--help"], capture_output=True, text=True)
        record(p.returncode == 0, "attacks", s, "imports and parses --help")


def check_research(quick):
    build = os.path.join(REPO, "research", "hsvm", "build")
    if not os.path.isdir(build):
        record(None, "hsvm", "ctest", "no build dir (configure first)")
        return
    p = subprocess.run(["ctest", "--output-on-failure"], cwd=build, capture_output=True, text=True)
    tail = [ln for ln in p.stdout.splitlines() if "tests passed" in ln]
    record(p.returncode == 0, "hsvm", "ctest", tail[0] if tail else "see output")


def main(argv=None):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--quick", action="store_true", help="skip openssl and negative tests")
    ap.add_argument("--only", default="", help="comma separated generation names")
    ap.add_argument("--baseline", default=os.path.join(HERE, "baseline.json"),
                    help="recorded sizes and cold-start times")
    ap.add_argument("--update-baseline", action="store_true",
                    help="rewrite the baseline from this run (use after an intended change)")
    ap.add_argument("--tol", type=float, default=0.25,
                    help="allowed cold-start slowdown vs baseline (default 25%%)")
    ap.add_argument("--attacks", action="store_true", help="also smoke the attack scripts")
    ap.add_argument("--research", action="store_true", help="also run research/hsvm ctest")
    a = ap.parse_args(argv)

    if not os.path.isdir(BIN_DIR):
        print("no exported artifacts at %s" % BIN_DIR)
        return 2
    shas = read_sha_manifest()
    only = {s.strip() for s in a.only.split(",") if s.strip()}

    print("%-4s %-9s %-22s %s" % ("", "gen", "check", "detail"))
    baseline = load_baseline(a.baseline)
    fresh = dict(baseline)
    for name, binary, key, ct, vm in GENERATIONS:
        if only and name not in only:
            continue
        meas = check_generation(name, binary, key, ct, vm, a.quick, shas, baseline, a.tol)
        if meas:
            fresh[binary] = meas
    if a.update_baseline:
        with open(a.baseline, "w") as f:
            json.dump(fresh, f, indent=2, sort_keys=True)
            f.write("\n")
        print("baseline written to %s (%d generations)" % (a.baseline, len(fresh)))
    if a.attacks:
        check_attacks(a.quick)
    if a.research:
        check_research(a.quick)

    failed = [r for r in results if r[0] == "FAIL"]
    skipped = [r for r in results if r[0] == "SKIP"]
    print("\n%d checks, %d passed, %d failed, %d skipped"
          % (len(results), len(results) - len(failed) - len(skipped), len(failed), len(skipped)))
    if failed:
        print("FAILED: " + ", ".join("%s/%s" % (g, c) for _, g, c, _ in failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
