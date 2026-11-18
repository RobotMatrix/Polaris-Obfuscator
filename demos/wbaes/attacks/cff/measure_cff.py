#!/usr/bin/env python3
"""Static shape of a white-box build: text size, instructions, blocks, branches,
__hytab cross-references, and the shortest static path from main() to the first
instruction that materialises the 70 MB table base address.

This is a measurement tool, not an attack. It reads only the Mach-O (otool -tv /
otool -l, both invoked as subprocesses) and reports what a reverse engineer has to
walk through. The "instructions before the table base" number is a *proxy*:

  * path     = fewest CALL edges from main() to a function that computes &kHyTab
  * cost     = total instruction count of the distinct functions on that path
  * xrefs    = number of instructions that materialise an address inside __hytab

It says nothing about how long a human needs; it is reproducible and it moves in
the direction a reader's work moves.

usage: python3 measure_cff.py --binary BIN [--json OUT.json] [--label V0]
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

COND_RX = re.compile(r"^(b\.[a-z]{2}|cbz|cbnz|tbz|tbnz)$")
UNCOND = ("b",)
INDIRECT = ("br", "braa", "braaz", "brab", "brabz", "blr", "braa", "ret")


def run(*cmd):
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("%s failed: %s" % (" ".join(cmd), out.stderr[:400]))
    return out.stdout


def text_size(binary):
    sect = None
    for line in run("otool", "-l", binary).splitlines():
        line = line.strip()
        if line.startswith("sectname"):
            sect = line.split()[1]
            continue
        if sect == "__text" and line.startswith("size"):
            return int(line.split()[1], 16)
    raise SystemExit("no __text section")


def symbols(binary):
    """addr -> name for every __text symbol, from nm -nm."""
    syms = {}
    for line in run("nm", "-nm", binary).splitlines():
        parts = line.split()
        if len(parts) < 4 or "(__TEXT,__text)" not in line:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[-1]
        syms.setdefault(addr, name)
    return syms


def section(binary, seg, sect):
    addr = size = None
    cur = None
    pend = None
    for line in run("otool", "-l", binary).splitlines():
        line = line.strip()
        if line.startswith("sectname"):
            pend = line.split()[1]
        elif line.startswith("segname"):
            cur = (line.split()[1], pend)
        elif cur == (seg, sect) and line.startswith("addr"):
            addr = int(line.split()[1], 16)
        elif cur == (seg, sect) and line.startswith("size"):
            size = int(line.split()[1], 16)
    return addr, size


INS_RX = re.compile(r"^([0-9a-f]{16})\t(\S+)\t?(.*)$")


def disasm(binary):
    """[(func_name, [(addr, mnemonic, operands)])] in file order."""
    funcs = []
    cur = None
    ins = []
    for line in run("otool", "-tv", binary).splitlines():
        if line.rstrip().endswith(":") and not line.startswith("(") \
                and " " not in line.strip() and not line.startswith("\t"):
            name = line.strip()[:-1]
            if cur is not None and ins:
                funcs.append((cur, ins))
            cur, ins = name, []
            continue
        m = INS_RX.match(line)
        if m and cur is not None:
            ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
    if cur is not None and ins:
        funcs.append((cur, ins))
    return funcs


def branch_target(operands):
    m = re.match(r"\s*(0x[0-9a-f]+)\b", operands)
    return int(m.group(1), 16) if m else None


def call_target(operands):
    return branch_target(operands)


def ins_addr(operands):
    m = re.match(r"\s*(0x[0-9a-f]+)\b", operands)
    return int(m.group(1), 16) if m else None


def mnemonic_hash(ins):
    """Hash of the mnemonic sequence of one function.

    Addresses and immediates are dropped on purpose: they move when the image
    layout moves (__text grows, __bss follows). Two builds with the same
    mnemonic sequence and the same instruction / block / branch counts compile
    that function to the same instruction schedule; only relocated operands
    differ. Non-annotated code keeps the same hash across builds, annotated
    code does not.
    """
    return hashlib.sha256("\n".join(mn for _, mn, _ in ins).encode()).hexdigest()[:16]


def analyse(binary):
    tsize = text_size(binary)
    syms = symbols(binary)
    tab_addr, tab_size = section(binary, "__DATA", "__hytab")
    # A 16-byte pointer cell (__ZL10hy_tab_ptr) sits immediately before the
    # section and holds &kHyTab after dyld rebasing, so a reference to it is a
    # reference to the table base.
    tab_lo = tab_addr - 0x10
    funcs = disasm(binary)

    fdata = []          # per function record
    total_ins = 0
    cond = uncond = indir = calls = rets = 0
    xref_ins = []       # (func, addr, kind)
    for name, ins in funcs:
        addrs = {a for a, _, _ in ins}
        leaders = {ins[0][0]}
        ncond = nuncond = nindir = nret = 0
        ncmp = nmovk = 0
        for i, (a, mn, ops) in enumerate(ins):
            if mn == "cmp":
                ncmp += 1
            elif mn == "movk":
                nmovk += 1
            is_br = False
            if COND_RX.match(mn):
                ncond += 1
                is_br = True
            elif mn in UNCOND:
                nuncond += 1
                is_br = True
            elif mn in ("br", "braa", "braaz", "brab", "brabz", "blr"):
                nindir += 1
                is_br = True
            elif mn == "ret":
                nret += 1
                is_br = True
            elif mn == "bl":
                calls += 1
            if is_br:
                t = branch_target(ops)
                if t is not None and t in addrs:
                    leaders.add(t)
                if i + 1 < len(ins):
                    leaders.add(ins[i + 1][0])
        # __hytab xrefs: adrp page + (add #imm | load/store #imm)
        pages = {}
        for a, mn, ops in ins:
            if mn == "adrp":
                mm = re.search(r"^(x\d+|w\d+),\s*(\d+)\s*;\s*(0x[0-9a-f]+)", ops)
                if mm:
                    pages[mm.group(1)] = int(mm.group(3), 16)
                continue
            base = None
            mm = re.match(r"^(x\d+),\s*x\d+,\s*#(0x[0-9a-f]+|0)$", ops)
            if mm and mn in ("add",):
                if mm.group(1) in pages:
                    base = pages[mm.group(1)] + int(mm.group(2), 16)
            mm2 = re.match(r"^\w+,\s*\[(x\d+)(?:,\s*#(0x[0-9a-f]+|\d+))?\]", ops)
            if mm2 and mm2.group(1) in pages:
                off = int(mm2.group(2), 0) if mm2.group(2) else 0
                base = pages[mm2.group(1)] + off
            if base is not None and tab_lo <= base < tab_addr + tab_size:
                xref_ins.append((name, a, mn))
        fdata.append({
            "name": name, "ins": len(ins),
            "blocks": len(leaders), "cond": ncond, "uncond": nuncond,
            "indirect": nindir, "ret": nret, "cmp": ncmp, "movk": nmovk,
            "start": ins[0][0], "end": ins[-1][0] + 4,
            "shape": mnemonic_hash(ins),
        })
        total_ins += len(ins)
        cond += ncond
        uncond += nuncond
        indir += nindir
        rets += nret

    # call graph on direct bl edges that land on a known function start
    by_start = {f["start"]: f["name"] for f in fdata}
    name_of = {f["name"]: f for f in fdata}
    edges = {}
    for name, ins in funcs:
        tgt = []
        for a, mn, ops in ins:
            if mn == "bl":
                t = call_target(ops)
                if t in by_start:
                    tgt.append(by_start[t])
                    continue
                # "0x... ; symbol stub for: _name" or a plain symbol operand
                s = ops.strip()
                stub = re.search(r"symbol stub for:\s*(\S+)", s)
                if stub and stub.group(1) in name_of:
                    tgt.append(stub.group(1))
                elif s in name_of:
                    tgt.append(s)
        edges[name] = tgt

    main = next((n for n in name_of if n == "_main"), None)
    has_xref = {n for n, _, _ in xref_ins}

    def bfs(targets):
        """Fewest-call-edge path from main to any of `targets`."""
        if not main:
            return None
        prev = {main: None}
        q = [main]
        hit = None
        while q:
            n = q.pop(0)
            if n in targets:
                hit = n
                break
            for c in edges.get(n, []):
                if c not in prev:
                    prev[c] = n
                    q.append(c)
        if not hit:
            return None
        path_ = []
        n = hit
        while n is not None:
            path_.append(n)
            n = prev[n]
        path_.reverse()
        return path_

    path = bfs(has_xref)

    # Anchors on the crypto hot path. Cost = instruction count of the distinct
    # functions on the shortest call chain from main(), i.e. how many lines of
    # disassembly a reader has to account for before arriving at that anchor.
    ANCHORS = {
        "vm_offsets": "__ZL10hy_vm_planiPA16_j",
        "encrypt": "__ZNK5WBAES7encryptEPKhPh",
        "encrypt_once": "__ZL15hy_encrypt_oncePKhPhjiPA16_Kj",
        "mc_round": "__Z11hy_mc_roundPKhjiiiS0_PhjPKj",
        "pair_map": "__Z11hy_pair_mapPKhjS0_Phjiii",
        "spn_inv": "__Z10hy_spn_invPKhjiiiPhj",
        "hsvm_entry": "_hsvm_entry",
    }
    anchors = {}
    for label, fn in ANCHORS.items():
        p = bfs({fn})
        if p:
            anchors[label] = {
                "path": p,
                "functions": len(p),
                "instructions": sum(name_of[n]["ins"] for n in p),
                "blocks": sum(name_of[n]["blocks"] for n in p),
            }

    path_cost = sum(name_of[n]["ins"] for n in path) if path else None
    return {
        "binary": os.path.basename(binary),
        "text_bytes": tsize,
        "total_instructions": total_ins,
        "total_blocks": sum(f["blocks"] for f in fdata),
        "functions": len(fdata),
        "cond_branches": cond,
        "uncond_branches": uncond,
        "indirect_branches": indir,
        "rets": rets,
        "calls": calls,
        "hytab": {"addr": hex(tab_addr), "size": tab_size},
        "hytab_xref_instructions": len(xref_ins),
        "hytab_xref_sites": len({a for _, a, _ in xref_ins}),
        "hytab_xref_funcs": sorted({n for n, _, _ in xref_ins}),
        "path_main_to_hytab": path,
        "path_functions": len(path) if path else None,
        "path_instructions": path_cost,
        "anchors": anchors,
        "hot": [f for f in fdata if f["name"] in (
            "_main", "__ZNK5WBAES7encryptEPKhPh", "__ZNK5WBAES7decryptEPKhPh",
            "__Z11hy_mc_roundPKhjiiiS0_PhjPKj", "_hsvm_entry",
            "__ZL10hy_protectPKhPhi", "__Z10hy_spn_invPKhjiiiPhj")],
        "largest": sorted(fdata, key=lambda f: -f["ins"])[:8],
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--json")
    ap.add_argument("--label", default="")
    a = ap.parse_args(argv)
    r = analyse(a.binary)
    r["label"] = a.label
    txt = json.dumps(r, indent=1)
    if a.json:
        with open(a.json, "w") as f:
            f.write(txt)
    print(txt)


if __name__ == "__main__":
    main()
