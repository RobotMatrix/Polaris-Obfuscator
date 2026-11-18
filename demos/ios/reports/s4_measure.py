"""s4_measure.py -- measure S4 (merge-then-split + random chunk granularity).

Inputs (all optional except the binary):
  * the split sidecar (`-split-symbols-sidecar`): which blocks became chunks,
    which symbol names them, and -- when the build used -merge-then-split --
    the source-function scope index of each chunk;
  * the merge sidecar (`-merge-scope-sidecar`): scope index -> source function;
  * a baseline binary of the same source (no merge, no split): its function
    starts are the ground truth for "how many source functions are there".

Reported:
  attribution
    * visible symbol intervals and how many *source functions* sit inside each
    * chunks per source function
    * whether the chunk -> source-function map is recoverable from the binary
      (contiguous-run segmentation: assume one source function = one contiguous
      run of chunks, then score that assumption against the ground truth)
    * whether the chunk *names* or their order carry the mapping
  granularity
    * chunk counts and chunk byte sizes per function, compared with a second
      build (different seed): overlap of the observable signature

Usage:
  python3 s4_measure.py BIN --sidecar chunks.tsv [--merge-scope merged.tsv]
                           [--baseline BIN] [--json out.json]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "wbaes", "attacks", "residual"))
import macho_symbols as MS  # noqa: E402


def read_split_sidecar(path):
    fn_chunks, chunks, seed = {}, [], None
    if not path or not os.path.exists(path):
        return fn_chunks, chunks, seed
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        if not f or not f[0] or f[0].startswith("#"):
            continue
        if f[0] == "seed":
            seed = f[1]
        elif f[0] == "fn":
            fn_chunks[f[1]] = int(f[2])
        elif f[0] == "chunk":
            chunks.append(dict(fn=f[1], idx=int(f[2]), sym=f[3], mbb=int(f[4]),
                               scope=int(f[5]) if len(f) > 5 else None))
        elif f[0] == "entry":
            chunks.append(dict(fn=f[1], idx=-1, sym=f[2], mbb=-1, scope=None,
                               entry=True))
    return fn_chunks, chunks, seed


def read_merge_sidecar(path):
    src = {}
    if not path or not os.path.exists(path):
        return src
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        if f and f[0] == "src":
            src[int(f[2])] = dict(merged=f[1], name=f[3],
                                  switch=int(f[4]) if len(f) > 4 else None)
    return src


def resolve(binary, chunks):
    by_name = {}
    for s in binary["symbols"]:
        if s["kind"] != "UNDEF":
            by_name.setdefault(s["name"], s["value"])
    for c in chunks:
        c["addr"] = by_name.get(c["sym"])
    return [c for c in chunks if c.get("addr") is not None]


def text_section(binary):
    for s in binary["sections"]:
        if s["sect"] == "__text":
            return s
    return None


def visible_starts(binary, chunk_names):
    """Real function starts: nlist symbols in __text that are not chunk labels."""
    out = []
    for s in binary["symbols"]:
        if s["kind"] == "UNDEF" or not s["sect_name"].endswith("__text"):
            continue
        if s["name"] in chunk_names or s["name"] == "__mh_execute_header":
            continue
        out.append(dict(name=s["name"], addr=s["value"], size=s.get("size")))
    return sorted(out, key=lambda s: s["addr"])


def runs_by(seq, key):
    """Maximal runs of equal `key` in the given order."""
    out = []
    for item in seq:
        k = item.get(key)
        if out and out[-1][0] == k:
            out[-1][1].append(item)
        else:
            out.append((k, [item]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--sidecar")
    ap.add_argument("--merge-scope")
    ap.add_argument("--baseline")
    ap.add_argument("--json")
    a = ap.parse_args()

    b = MS.parse(a.binary)
    fn_chunks, chunks, seed = read_split_sidecar(a.sidecar)
    srcmap = read_merge_sidecar(a.merge_scope)
    resolved = resolve(b, chunks)
    chunk_names = {c["sym"] for c in chunks}
    base = MS.parse(a.baseline) if a.baseline else None
    txt = text_section(b)

    # ---- source functions per *visible* symbol interval -------------------
    starts = visible_starts(b, chunk_names)
    start_addrs = [s["addr"] for s in starts]
    tstart = txt["addr"] if txt else 0
    tend = tstart + txt["size"] if txt else 0

    def interval_of(addr):
        lo = None
        for s in starts:
            if s["addr"] <= addr:
                lo = s
            else:
                break
        return lo

    scoped = [c for c in resolved if c.get("scope") not in (None, -1)]
    per_interval = {}
    for c in resolved:
        lo = interval_of(c["addr"])
        key = lo["name"] if lo else "<before first symbol>"
        d = per_interval.setdefault(key, dict(chunks=0, scopes=set(), fns=set()))
        d["chunks"] += 1
        d["fns"].add(c["fn"])
        if c.get("scope") not in (None, -1):
            d["scopes"].add(c["scope"])

    # ---- chunks per source function --------------------------------------
    per_scope = {}
    for c in scoped:
        d = per_scope.setdefault(c["scope"], dict(name=srcmap.get(c["scope"], {}).get("name", "?"),
                                                  chunks=0, sizes=[], addrs=[]))
        d["chunks"] += 1
        d["addrs"].append(c["addr"])
    # chunk sizes: distance to the next chunk start / section end
    ordered = sorted(resolved, key=lambda c: c["addr"])
    for i, c in enumerate(ordered):
        nxt = ordered[i + 1]["addr"] if i + 1 < len(ordered) else (tend or c["addr"])
        c["size"] = nxt - c["addr"]
    for c in scoped:
        per_scope[c["scope"]]["sizes"].append(c["size"])

    # ---- attribution attack: contiguous runs of one source function ------
    # The strongest assumption an analyst can make without the scope field is
    # "one source function occupies one contiguous run of chunks".  Score it:
    # how many source functions does that assumption recover, and how many
    # chunks does it assign to the wrong function?
    scoped_by_addr = sorted(scoped, key=lambda c: c["addr"])
    runs = runs_by(scoped_by_addr, "scope")
    # best possible with the assumption: one contiguous segment per scope
    n_scopes = len(per_scope)
    n_runs = len(runs)
    # order-only attack: assume scopes appear in address order, one run each.
    # Correct classification requires r == number of scopes AND each scope in
    # exactly one run.
    scope_run_counts = {}
    for k, _items in runs:
        scope_run_counts[k] = scope_run_counts.get(k, 0) + 1
    fragmented = [s for s, n in scope_run_counts.items() if n > 1]

    # ---- leak checks ------------------------------------------------------
    leak_names = []
    for c in resolved:
        nm = c["sym"]
        # does a chunk name carry the source function name (or a prefix of it)?
        if c.get("scope") not in (None, -1):
            fname = srcmap.get(c["scope"], {}).get("name", "")
            stem = fname.split("(")[0]
            for frag in (fname, stem):
                if len(frag) > 3 and frag[:6] in nm:
                    leak_names.append(nm)
                    break

    out = dict(
        binary=a.binary,
        file_size=b["header"]["size"],
        text_size=txt["size"] if txt else None,
        seed=seed,
        chunks_total=len(resolved),
        chunks_missing=[c["sym"] for c in chunks if c.get("addr") is None],
        chunk_fns=fn_chunks,
        merged_scope_functions=len(srcmap),
        scoped_chunks=len(scoped),
        source_functions_with_chunks=n_scopes,
        visible_intervals=len(starts),
        function_starts=len(b["function_starts"]),
        per_interval={k: dict(chunks=v["chunks"], fns=sorted(v["fns"]),
                              source_functions=len(v["scopes"]))
                      for k, v in per_interval.items()},
        chunks_per_source_function={srcmap.get(k, {}).get("name", str(k)):
                                    v["chunks"] for k, v in per_scope.items()},
        chunk_sizes_per_source_function={srcmap.get(k, {}).get("name", str(k)):
                                         v["sizes"] for k, v in per_scope.items()},
        runs_in_address_order=n_runs,
        fragmented_scopes=len(fragmented),
        scope_runs={srcmap.get(k, {}).get("name", str(k)): n
                    for k, n in scope_run_counts.items()},
        name_leaks=leak_names,
        chunk_starts=sorted(c["addr"] for c in resolved),
        chunk_addr_by_scope={srcmap.get(k, {}).get("name", str(k)): sorted(v["addrs"])
                             for k, v in per_scope.items()},
    )
    if base is not None:
        out["baseline_file_size"] = base["header"]["size"]
        bt = text_section(base)
        out["baseline_text_size"] = bt["size"] if bt else None
        out["baseline_function_starts"] = len(base["function_starts"])
        out["baseline_text_symbols"] = [s["name"] for s in visible_starts(
            base, set())]

    for k, v in out.items():
        if k in ("chunk_starts", "chunk_addr_by_scope", "per_interval",
                 "chunks_per_source_function", "chunk_sizes_per_source_function",
                 "scope_runs", "chunk_fns", "baseline_text_symbols"):
            continue
        print(f"{k:34s} {v}")
    print("per_interval:")
    for k, v in out["per_interval"].items():
        print(f"  {k:32s} chunks={v['chunks']:3d} "
              f"source_functions={v['source_functions']} mfs={v['fns']}")
    print("chunks_per_source_function:")
    for k, v in out["chunks_per_source_function"].items():
        print(f"  {k:40s} {v:3d}  sizes={out['chunk_sizes_per_source_function'][k]}")
    print("scope_runs (contiguous runs per source function):")
    for k, v in out["scope_runs"].items():
        print(f"  {k:40s} runs={v}")
    if a.json:
        open(a.json, "w").write(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
