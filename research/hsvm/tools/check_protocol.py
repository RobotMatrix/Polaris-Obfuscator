#!/usr/bin/env python3
"""Validate the HSV experiment pre-registration (protocol.json).

Why this exists: the plan's gate rules are only meaningful if the parameters,
budgets, distributions and seeds were frozen BEFORE the experiments ran. This
checker makes that mechanical: it rejects an incomplete protocol, rejects
values that contradict the C++ parameter rules, and prints a canonical hash
that every report must carry.

Stdlib only, so it runs on a bare machine.

Usage:
    check_protocol.py protocol.json [--params-tool ./build/hsvm_params]
"""

import argparse
import hashlib
import itertools
import json
import re
import subprocess
import sys

REQUIRED_TOP = [
    "protocol_version",
    "created",
    "source_document",
    "hypothesis",
    "stage1",
    "params_grid",
    "chosen_point",
    "seeds",
    "workload",
    "query_counting",
    "a2_memory_scope",
    "stop_rules",
    "reporting",
]

REQUIRED_REPORT_FIELDS = [
    "run_id",
    "gate",
    "created_at",
    "git_commit",
    "params_hash",
    "protocol_sha256",
    "attacker_model",
    "seeds",
    "metrics",
    "queries_used",
    "censored",
    "raw_log",
    "evidence",
]

STOP_RULE_IDS = {
    "stage1_no_feasible_point_under_r_plain_3",
    "stage2_whitebox_recovers_psi_or_compact_model",
    "core_hypothesis_success_rate_at_least_0_10",
}

GRID_KEYS = ["n", "m", "w", "c", "r_bar", "rounds", "psi"]


def is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def is_pow2(n):
    return is_int(n) and n > 0 and (n & (n - 1)) == 0


def point_legal(n, m, w, c, r_bar, rounds, psi):
    """Mirror of validate() in include/hsvm/params.h."""
    if not all(is_int(v) for v in (n, m, w, c, r_bar, rounds)):
        return False
    if n < 8 or m < 1 or m >= n or w < 1 or w > n or c < 1 or c > n:
        return False
    if r_bar < 1 or c * r_bar > n:
        return False
    if psi == "table":
        return w <= 16 and rounds == 0
    if psi == "spn":
        return w % 8 == 0 and 1 <= rounds <= 16
    if psi == "arx":
        return w % 8 == 0 and 16 <= w <= 64 and 1 <= rounds <= 16
    return False


def grid_points(grid):
    values = [grid.get(k) for k in GRID_KEYS]
    if not all(isinstance(v, list) and v for v in values):
        return []
    return [dict(zip(GRID_KEYS, combo)) for combo in itertools.product(*values)]


def validate(doc, params_tool=None):
    problems = []
    is_v2 = str(doc.get("protocol_version", "")).startswith("2")

    def need(cond, msg):
        if not cond:
            problems.append(msg)

    for key in REQUIRED_TOP:
        need(key in doc, "missing top-level key: %s" % key)
    if problems:
        return problems

    need(isinstance(doc["protocol_version"], str) and doc["protocol_version"],
         "protocol_version must be a non-empty string")
    need(isinstance(doc["created"], str) and
         re.match(r"^\d{4}-\d{2}-\d{2}$", doc["created"]) is not None,
         "created must be YYYY-MM-DD")
    need(isinstance(doc["source_document"], str) and doc["source_document"],
         "source_document must be a non-empty string")
    need(isinstance(doc["query_counting"], str) and doc["query_counting"],
         "query_counting must describe the counting rule")
    need(isinstance(doc["a2_memory_scope"], str) and doc["a2_memory_scope"],
         "a2_memory_scope must describe what the attacker may touch")

    # ---- hypothesis ----
    hyp = doc.get("hypothesis")
    need(isinstance(hyp, dict), "hypothesis must be an object")
    if isinstance(hyp, dict):
        need(hyp.get("attacker_model") in ("A2", "A2-static", "A2-dynamic"),
             "hypothesis.attacker_model must be A2 or a declared A2 variant "
             "(plan §1.3)")
        budget = hyp.get("query_budget")
        if not isinstance(budget, int) or isinstance(budget, bool):
            budget = 0
        need(is_pow2(budget),
             "hypothesis.query_budget must be a power of two")
        if is_pow2(budget):
            need(budget >= 2 ** 32,
                 "hypothesis.query_budget must be at least 2^32")
        instances = hyp.get("instances")
        if not isinstance(instances, int) or isinstance(instances, bool):
            instances = 0
        need(instances > 0, "hypothesis.instances must be >= 1")
        conf = hyp.get("confidence")
        need(isinstance(conf, (int, float)) and 0.5 < conf < 1,
             "hypothesis.confidence must be in (0.5, 1)")
        rate = hyp.get("success_rate_threshold")
        need(isinstance(rate, (int, float)) and 0 < rate < 1,
             "hypothesis.success_rate_threshold must be in (0, 1)")
        sem = hyp.get("semantic_threshold")
        need(isinstance(sem, (int, float)) and 0.5 <= sem < 1,
             "hypothesis.semantic_threshold must be in [0.5, 1)")
        bound = hyp.get("model_size_bound_bytes")
        need(is_int(bound) and bound > 0,
             "hypothesis.model_size_bound_bytes must be positive")
        dist = hyp.get("test_distribution")
        need(isinstance(dist, dict), "hypothesis.test_distribution must be an object")
        if isinstance(dist, dict):
            for k in ("normal", "boundary", "adaptive"):
                need(isinstance(dist.get(k), (int, float)) and dist[k] >= 0,
                     "test_distribution.%s must be a non-negative number" % k)
            total = sum(dist.get(k, 0) for k in ("normal", "boundary", "adaptive")
                        if isinstance(dist.get(k), (int, float)))
            need(abs(total - 1.0) <= 1e-9,
                 "test_distribution weights must sum to 1 (got %.6f)" % total)

    # ---- stage1 ----
    st = doc.get("stage1")
    need(isinstance(st, dict), "stage1 must be an object")
    if isinstance(st, dict):
        s1 = st.get("query_budget")
        need(is_pow2(s1), "stage1.query_budget must be a power of two")
        if is_pow2(s1) and isinstance(hyp, dict) and is_pow2(hyp.get("query_budget")):
            need(s1 <= hyp["query_budget"],
                 "stage1.query_budget must not exceed the hypothesis budget")
        interp = st.get("interpolation_success_threshold")
        need(isinstance(interp, (int, float)) and 0 < interp <= 0.5,
             "stage1.interpolation_success_threshold must be in (0, 0.5]")
        g = st.get("gamma_p5_threshold")
        need(isinstance(g, (int, float)) and 0 <= g <= 1,
             "stage1.gamma_p5_threshold must be in [0, 1]")
        need(is_int(st.get("gamma_states_per_instance")) and
             st["gamma_states_per_instance"] > 0,
             "stage1.gamma_states_per_instance must be positive")
        need(is_int(st.get("gamma_kernel_dirs")) and st["gamma_kernel_dirs"] > 0,
             "stage1.gamma_kernel_dirs must be positive")
        need(isinstance(st.get("affine_test"), str) and st["affine_test"],
             "stage1.affine_test must describe the test")
        perf = st.get("performance")
        need(isinstance(perf, dict), "stage1.performance must be an object")
        if isinstance(perf, dict):
            need(isinstance(perf.get("r_plain_max"), (int, float)) and
                 perf["r_plain_max"] >= 1,
                 "performance.r_plain_max must be >= 1")
            need(perf.get("commercial_baseline") is not None,
                 "performance.commercial_baseline must be set (or 'undecided')")
            need(is_int(perf.get("runs_per_measurement")) and
                 perf["runs_per_measurement"] >= 3,
                 "performance.runs_per_measurement must be >= 3")

    # ---- grid ----
    grid = doc.get("params_grid")
    need(isinstance(grid, dict), "params_grid must be an object")
    points = []
    if isinstance(grid, dict):
        for k in GRID_KEYS:
            vals = grid.get(k)
            need(isinstance(vals, list) and vals,
                 "params_grid.%s must be a non-empty list" % k)
            if isinstance(vals, list):
                if k == "psi":
                    need(all(v in ("table", "spn", "arx") for v in vals),
                         "params_grid.psi may only contain table, spn or arx")
                elif k == "rounds":
                    # 0 is the table-mode value; spn legality is checked per
                    # point below.
                    need(all(is_int(v) and v >= 0 for v in vals),
                         "params_grid.rounds must contain non-negative integers")
                else:
                    need(all(is_int(v) and v > 0 for v in vals),
                         "params_grid.%s must contain positive integers" % k)
        points = grid_points(grid)
        legal = [p for p in points if point_legal(**p)]
        need(bool(legal), "params_grid has no legal point")
        need(any(p["psi"] == "table" for p in legal),
             "params_grid has no legal table-mode point")
        need(any(p["psi"] == "spn" for p in legal),
             "params_grid has no legal spn-mode point")

    # ---- chosen point ----
    cp = doc.get("chosen_point")
    if cp is not None:
        need(isinstance(cp, dict), "chosen_point must be null or an object")
        if isinstance(cp, dict):
            missing = [k for k in GRID_KEYS if k not in cp]
            need(not missing, "chosen_point is missing: %s" % ", ".join(missing))
            if not missing:
                need(point_legal(**cp), "chosen_point violates the parameter rules")
                need(any(all(p.get(k) == cp.get(k) for k in GRID_KEYS)
                         for p in points),
                     "chosen_point is not one of the registered grid points")

    # ---- seeds ----
    seeds = doc.get("seeds")
    need(isinstance(seeds, list) and seeds, "seeds must be a non-empty list")
    if isinstance(seeds, list):
        need(all(is_int(s) for s in seeds), "seeds must all be integers")
        need(all(is_int(s) and s != 0 for s in seeds),
             "seeds must be nonzero (0 would make a clock-derived seed legal)")
        need(len(set(seeds)) == len(seeds), "seeds must be unique")
        if isinstance(hyp, dict) and is_int(hyp.get("instances")):
            need(len(seeds) >= hyp["instances"],
                 "need at least one seed per hypothesis instance")

    # ---- workload ----
    wl = doc.get("workload")
    need(isinstance(wl, list) and wl, "workload must be a non-empty list")
    if isinstance(wl, list):
        names = []
        total = 0.0
        for i, entry in enumerate(wl):
            good = isinstance(entry, dict)
            need(good, "workload[%d] must be an object" % i)
            if not good:
                continue
            need(isinstance(entry.get("name"), str) and entry["name"],
                 "workload[%d].name must be a string" % i)
            names.append(entry.get("name"))
            wgt = entry.get("weight")
            need(isinstance(wgt, (int, float)) and wgt > 0,
                 "workload[%d].weight must be positive" % i)
            if isinstance(wgt, (int, float)):
                total += wgt
        need(len(set(names)) == len(names), "workload names must be unique")
        need(abs(total - 1.0) <= 1e-9,
             "workload weights must sum to 1 (got %.6f)" % total)

    # ---- stop rules ----
    sr = doc.get("stop_rules")
    need(isinstance(sr, list) and sr, "stop_rules must be a non-empty list")
    if isinstance(sr, list) and not is_v2:
        need(STOP_RULE_IDS.issubset(set(sr)),
             "stop_rules must include all three §10.1 rules")

    # ---- reporting ----
    rep = doc.get("reporting")
    need(isinstance(rep, dict), "reporting must be an object")
    if isinstance(rep, dict):
        fields = rep.get("required_fields")
        need(isinstance(fields, list), "reporting.required_fields must be a list")
        if isinstance(fields, list):
            missing = [f for f in REQUIRED_REPORT_FIELDS if f not in fields]
            need(not missing, "reporting.required_fields is missing: %s"
                 % ", ".join(missing))
        need(isinstance(rep.get("censoring"), str) and rep["censoring"],
             "reporting.censoring must state the right-censoring rule")
        need(rep.get("separate_attacker_levels") is True,
             "reporting.separate_attacker_levels must be true")
        bases = rep.get("separate_baselines")
        need(isinstance(bases, list) and "r_plain" in bases and
             "r_commercial" in bases,
             "reporting.separate_baselines must list r_plain and r_commercial")

    # ---- v2 additions ----
    if str(doc.get("protocol_version", "")).startswith("2"):
        v2_required = ["supersedes", "rationale", "route",
                       "preregistered_expectation", "cost_gate",
                       "security_gate", "stage2_encoding"]
        for key in v2_required:
            need(key in doc, "v2: missing top-level key: %s" % key)

        cg = doc.get("cost_gate")
        need(isinstance(cg, dict), "v2: cost_gate must be an object")
        if isinstance(cg, dict):
            need(isinstance(cg.get("baseline"), str) and cg["baseline"],
                 "v2: cost_gate.baseline must name the baseline")
            cap = cg.get("cap_ratio")
            need(isinstance(cap, (int, float)) and 1 < cap <= 10,
                 "v2: cost_gate.cap_ratio must be in (1, 10]")
            need(cg.get("metric") == "step_cost_ratio",
                 "v2: cost_gate.metric must be 'step_cost_ratio'")
            need(cg.get("floor_derivation_required") is True,
                 "v2: cost_gate.floor_derivation_required must be true")
            comps = cg.get("floor_components")
            need(isinstance(comps, list) and len(comps) >= 4,
                 "v2: cost_gate.floor_components must list the cost terms")
            need(isinstance(cg.get("baseline_ns_per_instr"), (int, float)) and
                 cg["baseline_ns_per_instr"] > 0,
                 "v2: cost_gate.baseline_ns_per_instr must be positive")

        sg = doc.get("security_gate")
        need(isinstance(sg, dict), "v2: security_gate must be an object")
        if isinstance(sg, dict):
            need(sg.get("claimed_model") == "A2-static",
                 "v2: security_gate.claimed_model must be 'A2-static'")
            need(is_pow2(sg.get("max_probes")),
                 "v2: security_gate.max_probes must be a power of two")
            need(isinstance(sg.get("must_measure_on"), str) and
                 sg["must_measure_on"],
                 "v2: security_gate.must_measure_on must say where it is measured")
            need(isinstance(sg.get("a2_dynamic_note"), str) and
                 sg["a2_dynamic_note"],
                 "v2: security_gate must state the A2-dynamic boundary")

        enc = doc.get("stage2_encoding")
        need(isinstance(enc, dict), "v2: stage2_encoding must be an object")
        if isinstance(enc, dict):
            need(isinstance(enc.get("max_ns_per_step"), (int, float)) and
                 enc["max_ns_per_step"] > 0,
                 "v2: stage2_encoding.max_ns_per_step must be positive")
            need(isinstance(enc.get("attacks"), list) and enc["attacks"],
                 "v2: stage2_encoding.attacks must be non-empty")
            need(enc.get("positive_control_required") is True,
                 "v2: stage2_encoding.positive_control_required must be true")

        need(isinstance(doc.get("preregistered_expectation"), str) and
             len(doc["preregistered_expectation"]) > 40,
             "v2: preregistered_expectation must state the expected outcome")
        if isinstance(doc.get("stage1"), dict):
            need(isinstance(doc["stage1"].get("v2_scope"), str) and
                 doc["stage1"]["v2_scope"],
                 "v2: stage1.v2_scope must say what stage 1 now judges")
        v2_stop = {"g0v2_cost_floor_above_cap",
                   "stage2_whitebox_recovers_psi_or_compact_model",
                   "encoded_oracle_below_2pow40_probes",
                   "core_hypothesis_success_rate_at_least_0_10"}
        sr = doc.get("stop_rules")
        if isinstance(sr, list):
            need(v2_stop.issubset(set(sr)),
                 "v2: stop_rules must include all four v2 rules")

    # ---- cross-check with the C++ authority ----
    if params_tool and cp is not None and isinstance(cp, dict):
        args = [params_tool,
                "--n", str(cp.get("n")), "--m", str(cp.get("m")),
                "--w", str(cp.get("w")), "--c", str(cp.get("c")),
                "--rbar", str(cp.get("r_bar")), "--rounds", str(cp.get("rounds")),
                "--psi", str(cp.get("psi")), "--workload", "crc32",
                "--seed", "1"]
        try:
            res = subprocess.run(args, capture_output=True, text=True)
            need(res.returncode == 0,
                 "hsvm_params rejects chosen_point: %s" % res.stderr.strip())
        except OSError as exc:
            problems.append("cannot run --params-tool: %s" % exc)

    return problems


def canonical_hash(doc):
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("protocol")
    ap.add_argument("--params-tool", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    try:
        with open(args.protocol, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print("ERROR: cannot read protocol: %s" % exc, file=sys.stderr)
        return 2

    problems = validate(doc, args.params_tool)
    if problems:
        for p in problems:
            print("ERROR: %s" % p, file=sys.stderr)
        return 1

    cp = doc.get("chosen_point")
    print("protocol: ok (v%s, chosen_point=%s)" %
          (doc["protocol_version"], "unset" if cp is None else "set"))
    if not args.quiet:
        points = grid_points(doc["params_grid"])
        legal = [p for p in points if point_legal(**p)]
        print("  grid: %d points, %d legal (%d table, %d spn, %d arx)" %
              (len(points), len(legal),
               sum(1 for p in legal if p["psi"] == "table"),
               sum(1 for p in legal if p["psi"] == "spn"),
               sum(1 for p in legal if p["psi"] == "arx")))
        print("  seeds: %d | workload entries: %d | instances: %d" %
              (len(doc["seeds"]), len(doc["workload"]),
               doc["hypothesis"]["instances"]))
    print("protocol_sha256=%s" % canonical_hash(doc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
