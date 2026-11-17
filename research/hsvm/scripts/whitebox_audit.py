#!/usr/bin/env python3
"""White-box audit of the hsvm evidence chain.

Answers three questions that `ctest` cannot:
  1. do the published protocol hashes reproduce from the files on disk?
  2. does every report's binding (protocol hash, raw log, evidence, commit)
     actually resolve, and do the aggregate numbers equal the raw per-point
     JSON rather than being retyped?
  3. can the judges be fooled by a degenerate or self-reported field?

Exit code 1 on any hard failure. Findings that are weaknesses rather than
failures are printed as FINDING and do not fail the run (they are fixed by
changing the judge, not the data).

    python3 scripts/whitebox_audit.py
"""

import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILS = []
FINDINGS = []


def ok(cond, msg):
    if not cond:
        FAILS.append(msg)


def finding(msg):
    FINDINGS.append(msg)


def canonical(doc):
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def check_hashes():
    p1 = load(os.path.join(ROOT, "protocol.json"))
    p2 = load(os.path.join(ROOT, "protocol-v2.json"))
    h1, h2 = canonical(p1), canonical(p2)

    # The hash must be reproducible by the shipped checker, not just by us.
    for name, expect in (("protocol.json", h1), ("protocol-v2.json", h2)):
        res = subprocess.run([sys.executable, os.path.join(ROOT, "tools",
                                                           "check_protocol.py"),
                              os.path.join(ROOT, name)],
                             capture_output=True, text=True)
        ok(res.returncode == 0, "check_protocol rejects %s: %s"
           % (name, res.stderr.strip() or res.stdout.strip()))
        printed = [ln for ln in res.stdout.splitlines()
                   if ln.startswith("protocol_sha256=")]
        ok(printed and printed[0].split("=", 1)[1] == expect,
           "%s: checker hash %r != recomputed %s" % (name, printed, expect))

    # Every report that cites a protocol hash must cite a live one.
    live = {h1, h2}
    cited = set()
    for base, _, files in os.walk(os.path.join(ROOT, "reports")):
        for f in files:
            if f != "run.json":
                continue
            doc = load(os.path.join(base, f))
            cited.add(doc.get("protocol_sha256"))
    for h in cited:
        ok(h in live, "report cites unknown protocol hash %r" % h)
    ok(len(cited) >= 2, "expected reports citing both protocol versions, got %r"
       % cited)
    return h1, h2


def check_reports(h1, h2):
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    reports = []
    for base, _, files in os.walk(os.path.join(ROOT, "reports")):
        if "run.json" in files:
            reports.append(os.path.join(base, "run.json"))
    ok(len(reports) >= 4, "expected >= 4 gate reports, found %d" % len(reports))

    for path in sorted(reports):
        doc = load(path)
        tag = os.path.relpath(path, ROOT)
        for key in ("run_id", "gate", "git_commit", "params_hash",
                    "protocol_sha256", "metrics", "queries_used", "censored",
                    "raw_log", "evidence"):
            ok(key in doc, "%s: missing %s" % (tag, key))
        ph = doc.get("params_hash")
        ok(isinstance(ph, str) and len(ph) == 16 and
           all(c in "0123456789abcdef" for c in ph),
           "%s: params_hash is not 16 lowercase hex: %r" % (tag, ph))
        gc = doc.get("git_commit", "")
        ok(len(gc) == 40 and all(c in "0123456789abcdef" for c in gc),
           "%s: git_commit is not a full sha: %r" % (tag, gc))
        if gc and head:
            anc = subprocess.run(["git", "merge-base", "--is-ancestor", gc, head],
                                 cwd=ROOT, capture_output=True).returncode == 0
            ok(anc, "%s: git_commit %s is not an ancestor of HEAD" % (tag, gc[:8]))
        # raw_log and evidence must resolve relative to the report dir
        rl = doc.get("raw_log")
        ok(rl and os.path.exists(os.path.join(os.path.dirname(path), rl)),
           "%s: raw_log %r does not resolve" % (tag, rl))
        for ev in doc.get("evidence", []):
            cand = [os.path.join(os.path.dirname(path), ev),
                    os.path.join(ROOT, ev)]
            ok(any(os.path.exists(c) for c in cand),
               "%s: evidence %r does not resolve" % (tag, ev))


def check_grid_trace():
    """Aggregate grid values must equal the per-point raw files exactly."""
    for name in ("G1-model", "G1-model-addendum"):
        grid = load(os.path.join(ROOT, "reports", name, "grid.json"))
        for p in grid["points"]:
            raw = os.path.join(ROOT, "reports", name, "raw", p["point"] + ".json")
            ok(os.path.exists(raw), "%s: missing raw file for %s" % (name,
                                                                     p["point"]))
            if not os.path.exists(raw):
                continue
            r = load(raw)
            for key in ("gamma_p5", "gamma_min", "affine_nonaffine",
                        "step_cost_ratio", "bench_model_ns", "bench_plain_ns"):
                ok(r.get(key) == p.get(key),
                   "%s/%s: %s grid=%r raw=%r (aggregate was edited by hand?)"
                   % (name, p["point"], key, p.get(key), r.get(key)))


def check_judge_robustness():
    """Do the judges accept a degenerate point that reports no work?"""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    degenerate = {
        "points": [{
            "point": "degenerate", "params_hash": "0" * 16,
            "w": 64, "c": 8, "r_bar": 1, "rounds": 2, "psi": "spn",
            "gamma_p5": 1.0, "gamma_min": 1.0,
            "affine_nonaffine": 0, "instructions": 0,
            "step_cost_ratio": 0.0, "bench_model_ns": 0.0,
            "bench_plain_ns": 1.0, "enumerable_below_48": False,
        }]
    }
    tmp = os.path.join(ROOT, "reports", ".audit_degenerate.json")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(degenerate, fh)
    out = tmp + ".verdict"
    res = subprocess.run([sys.executable, os.path.join(ROOT, "tools",
                                                       "judge_g1_model.py"),
                          "--grid", tmp, "--out", out],
                         capture_output=True, text=True)
    verdict = load(out)
    os.remove(tmp)
    os.remove(out)
    if verdict["pass"]:
        finding("judge_g1_model passes a point with instructions=0 and "
                "bench_plain_ns=1.0: coverage/non-affine are satisfiable by an "
                "empty instruction set, and enumerability is taken from the "
                "sweep script instead of being derived from (psi, w)")

    # enumerated trust: a w=8 table point that lies about non-enumerability
    # must be rejected by the judge, which derives the flag itself.
    lying = degenerate["points"][0].copy()
    lying.update({"instructions": 16, "affine_nonaffine": 16, "w": 8,
                  "psi": "table", "step_cost_ratio": 2.0,
                  "enumerable_below_48": False, "bench_plain_ns": 4.2})
    tmp = os.path.join(ROOT, "reports", ".audit_lying.json")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"points": [lying]}, fh)
    out = tmp + ".verdict"
    subprocess.run([sys.executable, os.path.join(ROOT, "tools",
                                                 "judge_g1_model.py"),
                    "--grid", tmp, "--out", out], capture_output=True, text=True)
    verdict = load(out)
    os.remove(tmp)
    os.remove(out)
    if verdict["pass"]:
        finding("a w=8 table point claiming enumerable_below_48=false is "
                "accepted: the judge trusts the sweep instead of deriving "
                "enumerability from (psi, w)")


def check_report_censoring():
    """ADR-004: a censored report may not carry success metrics."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import report as report_mod  # noqa: E402

    bad = {
        "run_id": "audit-censored", "gate": "G1", "created_at": "2026-11-17T00:00:00Z",
        "git_commit": "0" * 40, "params_hash": "0" * 16,
        "protocol_sha256": "0" * 64, "attacker_model": "A2", "seeds": [1],
        "metrics": {"recover_success_rate": 0.42},
        "queries_used": 10, "censored": True,
        "raw_log": "nope.jsonl", "evidence": [],
    }
    tmp = os.path.join(ROOT, "reports", ".audit_censored.json")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(bad, fh)
    errs = report_mod.validate_report(tmp)
    os.remove(tmp)
    ok(any("censored" in e.lower() for e in errs),
       "report.py accepts a censored report with a success metric (ADR-004 "
       "not enforced): %r" % (errs,))


def main():
    h1, h2 = check_hashes()
    check_reports(h1, h2)
    check_grid_trace()
    check_judge_robustness()
    check_report_censoring()

    print("protocol v1 hash: %s" % h1)
    print("protocol v2 hash: %s" % h2)
    for f in FINDINGS:
        print("FINDING: %s" % f)
    if FAILS:
        for f in FAILS:
            print("FAIL: %s" % f)
        print("\naudit: %d failure(s), %d finding(s)" % (len(FAILS), len(FINDINGS)))
        return 1
    print("\naudit: 0 failures, %d finding(s)" % len(FINDINGS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
