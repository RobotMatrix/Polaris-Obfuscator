"""Measure the S1 split-chunk symbols against the compile-time sidecar.

Reports, for one linked Mach-O binary:
  * nlist / LC_FUNCTION_STARTS counts, and how many of the entries are chunk
    symbols declared in the sidecar (i.e. ground truth for "fake" functions)
  * ground truth real-function count (sidecar `fn` records, plus the symbols in
    the binary that are not chunk symbols)
  * the ratio observed / ground truth (the G1 proxy -- no IDA here)
  * chunk addresses, so the (function, chunk index -> address) map exists
  * a leak scan over symbol names, exports, dylibs and __cstring

Usage:
  python3 s1_measure.py <binary> --sidecar chunks.tsv [--json out.json]
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "wbaes", "attacks", "residual"))
import macho_symbols as MS  # noqa: E402

LEAK = re.compile(r"WBAES|hsvm|hy_vm|_ZN")


def read_sidecar(path):
    fns, chunks, seed = {}, [], None
    if not path:
        return fns, chunks, seed
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        if not f or f[0].startswith("#") or f[0] == "polaris-split-symbols":
            continue
        if f[0] == "seed":
            seed = f[1]
        elif f[0] == "fn":
            fns[f[1]] = int(f[2])
        elif f[0] == "chunk":
            chunks.append(dict(fn=f[1], idx=int(f[2]), sym=f[3], mbb=int(f[4])))
    return fns, chunks, seed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--sidecar")
    ap.add_argument("--baseline",
                    help="same build without -split-symbols: its function-start "
                         "count is the ground truth for the ratio")
    ap.add_argument("--json")
    a = ap.parse_args()

    b = MS.parse(a.binary)
    fns, chunks, seed = read_sidecar(a.sidecar)

    # ---- resolved (function, chunk) -> address map
    by_name = {}
    for s in b["symbols"]:
        if s["kind"] != "UNDEF":
            by_name.setdefault(s["name"], s["value"])
    resolved, missing = [], []
    for c in chunks:
        if c["sym"] in by_name:
            resolved.append(dict(c, addr=by_name[c["sym"]]))
        else:
            missing.append(c["sym"])

    chunk_names = {c["sym"] for c in chunks}
    defined = [s for s in b["symbols"] if s["kind"] != "UNDEF"]
    text = [s for s in defined if s["sect_name"].endswith("__text")]
    chunk_syms = [s for s in text if s["name"] in chunk_names]
    # __mh_execute_header is the Mach-O image header, not a function.
    real_syms = [s for s in text
                 if s["name"] not in chunk_names and s["name"] != "__mh_execute_header"]
    starts = b["function_starts"]
    real_starts = [x for x in starts if x in {s["value"] for s in real_syms}]
    fake_starts = [x for x in starts if x not in set(real_starts)]

    gt_fns = len(fns) if fns else len(real_syms)
    gt_total = gt_fns  # functions the MIR pass touched, from the sidecar
    base = MS.parse(a.baseline) if a.baseline else None
    gt_baseline = len(base["function_starts"]) if base else None

    # ---- leak scan
    hay = [s["name"] for s in b["symbols"]]
    hay += [e["name"] for e in b["exports"]]
    hay += b["dylibs"] + b["strings"]
    hay += [d for d in b["imports"]]
    leaks = [h for h in hay if LEAK.search(h)]

    out = dict(
        binary=a.binary,
        file_size=b["header"]["size"],
        text_size=[s["size"] for s in b["sections"] if s["sect"] == "__text"][0],
        nlist_total=len(b["symbols"]),
        nlist_defined=len(defined),
        nlist_text=len(text),
        nlist_chunk_symbols=len(chunk_syms),
        nlist_nonchunk_text=len(real_syms),
        function_starts=len(starts),
        function_starts_with_symbol=len([x for x in starts if x in by_name.values()]),
        real_function_starts=len(real_starts),
        fake_function_starts=len(fake_starts),
        sidecar_seed=seed,
        sidecar_functions={k: v for k, v in fns.items()},
        sidecar_chunks=len(chunks),
        sidecar_chunks_resolved=len(resolved),
        sidecar_chunks_missing=missing,
        ground_truth_functions=gt_total,
        ground_truth_function_starts=gt_baseline,
        ratio_starts_over_gt=(len(starts) / gt_total) if gt_total else None,
        ratio_starts_over_baseline=(len(starts) / gt_baseline) if gt_baseline else None,
        ratio_text_symbols_over_gt=(len(text) / gt_total) if gt_total else None,
        chunk_leaks=[c["sym"] for c in resolved if LEAK.search(c["sym"])],
        boundary_precision=(len(real_starts) / len(starts)) if starts else None,
        leak_matches=leaks,
        chunk_map=sorted([dict(fn=c["fn"], idx=c["idx"], sym=c["sym"], addr=hex(c["addr"]))
                          for c in resolved], key=lambda c: c["addr"]),
    )
    for k, v in out.items():
        if k in ("chunk_map", "sidecar_functions"):
            continue
        print(f"{k:32s} {v}")
    if out["chunk_map"]:
        print("chunk_map (first 3 of %d):" % len(out["chunk_map"]))
        for c in out["chunk_map"][:3]:
            print("  ", c)
    if a.json:
        open(a.json, "w").write(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
