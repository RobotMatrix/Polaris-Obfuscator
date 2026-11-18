"""ab_measure.py -- measure the two shipped profiles of S1+S3 (see SPLIT-SYMBOLS-AB.md).

Profile A ("labels balanced"): the split chunk labels must be in the same
linkage class as the real function symbols, so that "this function start has a
name" carries no information about whether it is a real function.  Profile B
("flat"): no name table, no stale name bytes, no unwind table that still
enumerates the real starts.

For one Mach-O arm64 artifact this prints:

  * LC_FUNCTION_STARTS: count, 4-byte alignment, and how many carry a symbol;
  * those labelled starts split by the *class* of the label that reaches them
    (external / private-external / local) and by ground truth (real / forged,
    where "real" = a start of the same build without -split-symbols);
  * export-trie entries, string-table names, and every tell byte in the file;
  * printable strings that live in __LINKEDIT but are claimed by no load
    command (the dead-bytes leak: strip rewrites the trie root, the old node
    names stay readable);
  * __unwind_info entries and how many of them are real starts;
  * the run result (rc / stdout sha256 / line count), if --run.

Usage:
  python3 ab_measure.py BIN --baseline BIN [--sidecar chunks.tsv] [--run] [--json out]
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "wbaes", "tools"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "wbaes", "attacks", "residual"))
sys.path.insert(0, HERE)

import macho_scrub as MS          # noqa: E402
import macho_symbols as SYM       # noqa: E402
import s3_measure as S3           # noqa: E402

TELL = re.compile(rb"WBAES|hsvm|hy_vm|_ZN")
N_PEXT = 0x10
N_EXT = 0x01
N_TYPE = 0x0E


def raw_symbols(path):
    """[(name, n_type, n_desc, n_value)] straight from LC_SYMTAB."""
    m = MS.MachO(path)
    tab = m.symtab()
    if tab is None:
        return []
    _off, symoff, nsyms, stroff, strsize = tab
    strtab = bytes(m.data[stroff:stroff + strsize])
    out = []
    for i in range(nsyms):
        strx, ntype, _nsect, ndesc, nvalue = struct.unpack_from(
            "<IBBHQ", m.data, symoff + i * 16)
        end = strtab.find(b"\0", strx)
        name = strtab[strx:end if end >= 0 else len(strtab)].decode("utf-8", "replace")
        out.append((name, ntype, ndesc, nvalue))
    return out


def klass(ntype):
    if (ntype & N_TYPE) == 0:
        return "undef"
    if ntype & N_PEXT:
        return "private-external"
    if ntype & N_EXT:
        return "external"
    return "local"


def dead_trie_strings(path, minlen=4):
    """Printable runs inside an export trie that the trie walk cannot reach.

    This is the stale half of the trie after `strip` (or after any in-place
    rewrite): the load command still claims the bytes, no name resolves from
    them, and `strings` reads them anyway.
    """
    m = MS.MachO(path)
    out = []
    for _off, _cmd, doff, _dsz in m.export_ranges():
        start, size = struct.unpack_from("<II", m.data, doff)
        if not size or not start:
            continue
        spans = []
        MS.parse_export_trie(bytes(m.data[start:start + size]), spans)
        live = bytearray(size)
        for a, b in spans:
            live[a:b] = b"\x01" * (b - a)
        runs, cur = [], []
        for i in range(size):
            ch = m.data[start + i]
            if not live[i] and 0x20 <= ch < 0x7F:
                cur.append(ch)
            else:
                if len(cur) >= minlen:
                    runs.append(bytes(cur).decode("latin1"))
                cur = []
        if len(cur) >= minlen:
            runs.append(bytes(cur).decode("latin1"))
        out.extend(runs)
    return out


def unclaimed_strings(path, minlen=6):
    """Printable runs that sit in __LINKEDIT but outside every load command."""
    m = MS.MachO(path)
    seg = None
    for off, cmd, _sz in m.cmds:
        if cmd == MS.LC_SEGMENT_64 and m.data[off + 8:off + 24].split(b"\0")[0] == b"__LINKEDIT":
            fileoff, filesize = struct.unpack_from("<QQ", m.data, off + 40)
            seg = (fileoff, filesize)
    if not seg:
        return []
    lo, size = seg
    claimed = bytearray(size)
    for a, b, _what in MS.linkedit_claimed_ranges(m):
        a, b = max(a, lo), min(b, lo + size)
        if b > a:
            claimed[a - lo:b - lo] = b"\x01" * (b - a)
    runs, cur = [], []
    for i in range(size):
        ch = m.data[lo + i]
        if claimed[i]:
            if len(cur) >= minlen:
                runs.append(bytes(cur).decode("latin1"))
            cur = []
            continue
        if 0x20 <= ch < 0x7F:
            cur.append(ch)
        else:
            if len(cur) >= minlen:
                runs.append(bytes(cur).decode("latin1"))
            cur = []
    if len(cur) >= minlen:
        runs.append(bytes(cur).decode("latin1"))
    return runs


def measure(binary, baseline, sidecar=None, run=False):
    base = S3.measure(binary, baseline=baseline, sidecar=sidecar, run=run)
    b = SYM.parse(binary)
    data = open(binary, "rb").read()
    starts = set(b["function_starts"])
    named = {}
    for name, ntype, _desc, value in raw_symbols(binary):
        if (ntype & N_TYPE) != 0:
            named.setdefault(value, []).append((name, klass(ntype)))
    real = set(SYM.parse(baseline)["function_starts"])

    classes = {}
    for a in sorted(starts):
        # one start may carry several names (real symbol + seeded entry alias);
        # count the start once per class so the numbers are "starts", not names.
        seen = {k for _n, k in named.get(a, [])}
        for k in seen:
            key = "real" if a in real else "forged"
            classes.setdefault(k, {}).setdefault(key, 0)
            classes[k][key] += 1
    base["labelled_by_class"] = classes

    exp = [e["name"] for e in MS.MachO(binary).exports()]
    base["export_names"] = exp[:5]
    base["tells"] = {
        "nlist": len([1 for n, _t, _d, _v in raw_symbols(binary) if TELL.search(n.encode())]),
        "exports": len([n for n in exp if TELL.search(n.encode())]),
        "strtab": len([1 for n in base.get("leak_examples", {}).get("strtab", [])
                       if TELL.search(n.encode())]),
        "raw_file": len(TELL.findall(data)),
        "unclaimed_linkedit": len([s for s in unclaimed_strings(binary)
                                   if TELL.search(s.encode())]),
    }
    base["unclaimed_linkedit_strings"] = unclaimed_strings(binary)[:8]
    base["dead_trie_strings"] = dead_trie_strings(binary)[:8]
    base["dead_trie_strings_n"] = len(dead_trie_strings(binary))
    base["strings_tell"] = [ln for ln in subprocess.run(
        ["/usr/bin/strings", "-a", binary], capture_output=True, text=True
    ).stdout.splitlines() if TELL.search(ln.encode())][:8]
    if run:
        exe = binary if os.sep in binary else "./" + binary
        r = subprocess.run([exe], capture_output=True, text=True)
        base["run"] = dict(rc=r.returncode,
                           lines=len(r.stdout.strip().splitlines()),
                           stdout_sha256=hashlib.sha256(r.stdout.encode()).hexdigest()[:16])
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--sidecar")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    r = measure(a.binary, a.baseline, a.sidecar, a.run)
    for k in ("file_size", "text_size", "text_sha256", "nlist_total", "nlist_defined",
              "function_starts_in_text", "function_starts_4B_aligned",
              "starts_with_symbol", "real_starts_ground_truth", "forged_starts",
              "real_fraction", "labelled_real", "labelled_forged", "unnamed_starts",
              "exports", "unwind_entries", "unwind_real", "unwind_not_real",
              "leak_raw_file_bytes", "run", "labelled_by_class", "tells",
              "unclaimed_linkedit_strings", "dead_trie_strings_n",
              "dead_trie_strings", "strings_tell", "export_names"):
        if k in r:
            print("%-30s %s" % (k, r[k]))
    if a.json:
        open(a.json, "w").write(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
