"""S3 measurement: do symbol treatment and stripping still leave structure behind?

Answers, for one linked Mach-O arm64 artifact, the questions S1 raised:

  * does LC_FUNCTION_STARTS survive the treatment?  (count, payload sha256, and
    a byte-for-byte compare against --same-fnstarts-as other-build)
  * how many of those starts carry a symbol, and how many are *real* function
    starts (intersection with a baseline build's starts = ground truth)?
    -> a labelled_real / labelled_forged pair; if either is 0 the two kinds of
       candidate are still separable, whatever the names say.
  * do any original names survive in the symbol table, the export trie, the
    string table, __cstring, or anywhere in the file bytes?

Every number printed here comes from the file; nothing is inferred.

Usage:
  python3 s3_measure.py BIN [--baseline BIN] [--sidecar chunks.tsv]
                            [--same-fnstarts-as BIN] [--run] [--json out.json]

  --baseline BIN        same build without -split-symbols: its function starts
                        are the ground truth for "real" vs "forged".
  --sidecar chunks.tsv  S1 sidecar; lets a chunk symbol be recognised by name.
  --same-fnstarts-as    fail loudly if the LC_FUNCTION_STARTS payload differs.

  python3 s3_measure.py --reuuid BIN --out COPY
                        copy BIN with a randomised LC_UUID and an ad-hoc
                        signature. Needed before a crash probe: the OS
                        symbolication cache is keyed by UUID, so a stripped
                        build that shares its UUID with the unstripped build
                        still resolves names that are no longer in the file.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "wbaes", "attacks", "residual"))
import macho_symbols as MS  # noqa: E402

LEAK = re.compile(rb"WBAES|hsvm|hy_vm|_ZN")

LC_SYMTAB = 0x2
LC_FUNCTION_STARTS = 0x26
LC_UUID = 0x1B


def load_commands(data):
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off, out = 32, []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        out.append((off, cmd, cmdsize))
        off += cmdsize
    return out


def function_starts(data, cmds):
    for off, cmd, _sz in cmds:
        if cmd == LC_FUNCTION_STARTS:
            o, s = struct.unpack_from("<II", data, off + 8)
            return data[o:o + s], o, s
    return b"", None, 0


def string_table(data, cmds):
    for off, cmd, _sz in cmds:
        if cmd == LC_SYMTAB:
            _so, _ns, stro, strs = struct.unpack_from("<IIII", data, off + 8)
            return data[stro:stro + strs], stro, strs
    return b"", None, 0


def unwind_entries(data, sections, base_vmaddr=0):
    """Function addresses the compact __unwind_info table enumerates.

    Apple format: a section header, a first-level index of pages (12 B entries,
    the last one a sentinel), and per page a second-level header. kind==3 is
    the compressed form: 32-bit entries, low 24 bits = offset from the page's
    index entry, high 8 bits = encoding index. kind==2 is the regular form:
    8-byte {uint32 offset, uint32 encoding}.
    """
    sec = [s for s in sections if s["sect"] == "__unwind_info"]
    if not sec:
        return []
    o, size = sec[0]["offset"], sec[0]["size"]
    if size < 28:
        return []
    ver, _ceo, _cec, _pao, _pac, io, ic = struct.unpack_from("<7I", data, o)
    if ver != 1 or ic == 0 or io + ic * 12 > size:
        return []
    out = []
    for i in range(ic):
        func_off, page_off, _lsda = struct.unpack_from("<III", data, o + io + i * 12)
        if page_off == 0 or page_off + 12 > size:
            continue
        kind = struct.unpack_from("<I", data, o + page_off)[0]
        ep, ec = struct.unpack_from("<HH", data, o + page_off + 4)
        for k in range(ec):
            if kind == 3:
                if page_off + ep + k * 4 + 4 > size:
                    break
                w = struct.unpack_from("<I", data, o + page_off + ep + k * 4)[0]
                off = w & 0xFFFFFF
            elif kind == 2:
                if page_off + ep + k * 8 + 4 > size:
                    break
                off = struct.unpack_from("<I", data, o + page_off + ep + k * 8)[0]
            else:
                break
            out.append(base_vmaddr + func_off + off)
    return out


def read_sidecar(path):
    chunks, fns = [], {}
    if not path:
        return chunks, fns
    for line in open(path):
        f = line.rstrip("\n").split("\t")
        if not f or f[0].startswith("#"):
            continue
        if f[0] == "fn":
            fns[f[1]] = int(f[2])
        elif f[0] == "chunk":
            chunks.append(dict(fn=f[1], idx=int(f[2]), sym=f[3]))
    return chunks, fns


def measure(binary, baseline=None, sidecar=None, same_fnstarts_as=None, run=False):
    b = MS.parse(binary)
    data = open(binary, "rb").read()
    cmds = load_commands(data)
    payload, foff, fsize = function_starts(data, cmds)
    strtab, _so, ssize = string_table(data, cmds)

    text = [s for s in b["sections"] if s["sect"] == "__text"][0]
    tlo, thi = text["addr"], text["addr"] + text["size"]
    starts = b["function_starts"]
    named = {s["value"]: s["name"] for s in b["symbols"] if s["kind"] != "UNDEF"}
    chunks, fns = read_sidecar(sidecar)
    chunk_names = {c["sym"] for c in chunks}

    base = MS.parse(baseline) if baseline else None
    real = set(base["function_starts"]) if base else set()
    real_in_text = {a for a in real if tlo <= a < thi}

    in_text = [a for a in starts if tlo <= a < thi]
    labelled = [a for a in in_text if a in named]
    labelled_real = [a for a in labelled if a in real]
    labelled_forged = [a for a in labelled if base and a not in real]
    real_here = [a for a in in_text if a in real]
    forged = len(in_text) - len(real_here)
    chunk_labelled = [a for a in labelled if named[a] in chunk_names]

    # ---- leaks: three name tables plus every byte in the file
    sym_names = [s["name"] for s in b["symbols"]]
    exp_names = [e["name"] for e in b["exports"]]
    str_names = [x.decode("latin1") for x in strtab.split(b"\0") if x]
    leaks = dict(
        symbols=sorted({n for n in sym_names if LEAK.search(n.encode())}),
        exports=sorted({n for n in exp_names if LEAK.search(n.encode())}),
        strtab=sorted({n for n in str_names if LEAK.search(n.encode())}),
        cstring=sorted({s for s in b["strings"] if LEAK.search(s.encode())}),
    )
    raw_file_bytes = len(LEAK.findall(data))

    base_vmaddr = [s for s in b["segments"] if s["name"] == "__TEXT"][0]["vmaddr"]
    unw = unwind_entries(data, b["sections"], base_vmaddr)
    unw_in_text = [a for a in unw if tlo <= a < thi]

    out = dict(
        binary=os.path.basename(binary),
        file_size=len(data),
        text_size=text["size"],
        text_sha256=hashlib.sha256(data[text["offset"]:text["offset"] + text["size"]]).hexdigest(),
        nlist_total=len(b["symbols"]),
        nlist_defined=len([s for s in b["symbols"] if s["kind"] != "UNDEF"]),
        unwind_entries=len(unw_in_text),
        unwind_real=len([a for a in unw_in_text if a in real_in_text]),
        unwind_not_real=len([a for a in unw_in_text if a not in real_in_text]),
        unwind_matching_starts=len([a for a in unw_in_text if a in set(in_text)]),
        exports=len(exp_names),
        function_starts=len(starts),
        function_starts_in_text=len(in_text),
        function_starts_4B_aligned=len([a for a in in_text if a % 4 == 0]),
        fnstarts_dataoff=foff, fnstarts_datasize=fsize,
        fnstarts_payload_sha256=hashlib.sha256(payload).hexdigest()[:16],
        starts_with_symbol=len(labelled),
        starts_with_chunk_symbol=len(chunk_labelled),
        starts_with_other_symbol=len(labelled) - len(chunk_labelled),
        real_starts_ground_truth=len(real_here),
        forged_starts=forged,
        real_fraction=(len(real_here) / len(in_text)) if in_text else None,
        labelled_real=len(labelled_real),
        labelled_forged=len(labelled_forged),
        unnamed_starts=len(in_text) - len(labelled),
        leak_counts={k: len(v) for k, v in leaks.items()},
        leak_examples={k: v[:6] for k, v in leaks.items()},
        leak_raw_file_bytes=raw_file_bytes,
        sidecar_chunk_symbols=len(chunks),
    )

    if same_fnstarts_as:
        other = function_starts(open(same_fnstarts_as, "rb").read(),
                                load_commands(open(same_fnstarts_as, "rb").read()))[0]
        out["fnstarts_payload_identical_to"] = os.path.basename(same_fnstarts_as)
        out["fnstarts_payload_identical"] = (other == payload)

    if run:
        exe = binary if os.sep in binary or "/" in binary else os.path.join(".", binary)
        r = subprocess.run([exe], capture_output=True, text=True)
        out["run"] = dict(rc=r.returncode, lines=len(r.stdout.strip().splitlines()),
                          stdout_sha256=hashlib.sha256(r.stdout.encode()).hexdigest()[:16],
                          stderr=r.stderr.strip()[:200])
    return out


def reuuid(src, dst):
    """Copy + randomise LC_UUID + re-sign. For crash probes, see the module doc."""
    data = bytearray(open(src, "rb").read())
    for off, cmd, _sz in load_commands(bytes(data)):
        if cmd == LC_UUID:
            data[off + 8:off + 24] = os.urandom(16)
            break
    else:
        raise SystemExit("%s has no LC_UUID" % src)
    shutil.copy2(src, dst)
    open(dst, "wb").write(data)
    os.chmod(dst, 0o755)
    subprocess.run(["codesign", "--force", "--sign", "-", "--timestamp=none", dst],
                   check=True, capture_output=True)
    return dst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--baseline")
    ap.add_argument("--sidecar")
    ap.add_argument("--same-fnstarts-as")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--reuuid", action="store_true", help="BIN is the source, --out the copy")
    ap.add_argument("--out")
    a = ap.parse_args()

    if a.reuuid:
        if not a.out:
            raise SystemExit("--reuuid needs --out")
        print(reuuid(a.binary, a.out))
        return

    r = measure(a.binary, a.baseline, a.sidecar, a.same_fnstarts_as, a.run)
    for k, v in r.items():
        if isinstance(v, dict):
            print(f"{k:34s} " + " ".join(f"{kk}={vv}" for kk, vv in v.items()))
        else:
            print(f"{k:34s} {v}")
    if a.json:
        open(a.json, "w").write(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
