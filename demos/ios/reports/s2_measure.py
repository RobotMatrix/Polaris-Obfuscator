"""Static control-flow census for the S2 computed-branch work.

For one linked Mach-O arm64 binary it reports:

  * branch census in __text (direct b / b.cond / cbz / cbnz / tbz / tbnz,
    indirect br / blr, calls, ret)
  * every direct-branch successor that lands on a *split chunk head*, using the
    chunk symbols the same build emits with -split-symbols (that flag does not
    change the code, so the addresses are comparable -- verified by __text
    size/bytes in the report)
  * how many `br` are table-driven (adrp/add/ldrsw/sub #key/add/br), i.e. how
    many successors a linear or recursive disassembler cannot resolve
  * the target table itself: its base (from the adrp/add of the first
    table-driven edge), its raw words, the key it is XORed with, and the
    decoded successor addresses -- i.e. a demonstration that the table is
    readable once the key has been read out of the sub immediate

Usage:
  python3 s2_measure.py BIN [--json out.json] [--chunks-symbols]
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "..", "wbaes", "attacks", "residual"))
import macho_symbols as MS  # noqa: E402

CHUNK_SYM = re.compile(r"^_k[0-9a-f]{12}$")

DIRECT_B = {"b"}
DIRECT_COND = {"b.eq", "b.ne", "b.hs", "b.lo", "b.mi", "b.pl", "b.vs", "b.vc",
               "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al"}
DIRECT_TEST = {"cbz", "cbnz", "tbz", "tbnz"}
INDIRECT = {"br", "blr", "braa", "blraa", "braaz", "blraaz", "ret", "retaa",
            "retab"}

LINE = re.compile(r"^\s*([0-9a-f]{16})\t(\S+)\t?(.*)$")
TARGET = re.compile(r"(0x[0-9a-f]+)")


def disasm(binary):
    out = subprocess.run(["otool", "-tv", binary], capture_output=True,
                         text=True).stdout
    insns = []
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        addr, op, args = m.group(1), m.group(2), m.group(3).strip()
        if op.startswith(".long") or op.startswith(".byte"):
            insns.append((int(addr, 16), op, args, None))
            continue
        tgt = None
        if op in DIRECT_B | DIRECT_COND | DIRECT_TEST:
            found = TARGET.findall(args)
            if found:
                tgt = int(found[-1], 16)
        insns.append((int(addr, 16), op, args, tgt))
    return insns


def section(binary_parsed, seg, sect):
    for s in binary_parsed["sections"]:
        if s["seg"] == seg and s["sect"] == sect:
            return s
    return None


def read_words(binary, sect, addr, count):
    """Read `count` 32-bit words at virtual address addr out of the file."""
    off = sect["offset"] + (addr - sect["addr"])
    with open(binary, "rb") as f:
        f.seek(off)
        data = f.read(4 * count)
    return [int.from_bytes(data[i:i + 4], "little", signed=True)
            for i in range(0, len(data), 4)]


def measure(binary, verbose=False):
    b = MS.parse(binary)
    text = section(b, "__TEXT", "__text")
    const = section(b, "__TEXT", "__const")
    insns = disasm(binary)

    # Chunk heads: seeded symbols in __text (only present with -split-symbols).
    chunks = {}
    for s in b["symbols"]:
        if s.get("name") and CHUNK_SYM.match(s["name"]):
            chunks[s["value"]] = s["name"]

    census = {}
    for _, op, _, _ in insns:
        if op.startswith(".long") or op.startswith(".byte"):
            continue
        key = ("direct-b" if op in DIRECT_B else
               "direct-cond" if op in DIRECT_COND else
               "direct-test" if op in DIRECT_TEST else
               "indirect" if op in INDIRECT else
               "call" if op in ("bl", "blraa") else "other")
        census[key] = census.get(key, 0) + 1

    direct = [(a, op, args, t) for a, op, args, t in insns
              if t is not None and a is not None]
    lo, hi = (text["addr"], text["addr"] + text["size"]) if text else (0, 0)
    # A branch that lands inside __text is one a disassembler can follow back
    # into real code; the rest are decodes of the .byte filler.
    direct_in_text = [(a, op, t) for a, op, _, t in direct if lo <= t < hi]
    direct_into_chunk = [(a, op, t) for a, op, t in direct_in_text if t in chunks]

    # br that follow adrp/add of a block symbol (the pre-S2 form) vs table.
    plain_br = 0
    plain_targets = []
    for i in range(2, len(insns)):
        if insns[i][1] == "br" and insns[i - 1][1] == "add" \
                and insns[i - 2][1] == "adrp":
            plain_br += 1
            m = TARGET.search(insns[i - 2][2])
            off = re.search(r"#(0x[0-9a-f]+)", insns[i - 1][2])
            if m and off:
                plain_targets.append(int(m.group(1), 16) + int(off.group(1), 16))

    # Table-driven br: the six-instruction form
    #   adrp xB,page / add xB,xB,#off / ldrsw xT,[xB,#i] / sub xT,xT,#key /
    #   add xB,xT,xB / br xB
    # and the conditional form, which loads two arms and csel's them
    #   adrp/add / ldrsw / ldrsw / sub / sub / csel / add / br
    # Both are detected by walking back from every `br` for an `ldrsw` plus a
    # `sub #key` with the one per-build key.
    keys = {}
    table_edges = []
    tables = {}
    for i, (a, op, ar, _) in enumerate(insns):
        if op != "br":
            continue
        lo_i = max(0, i - 12)
        win = insns[lo_i:i]
        ldrsw = [j for j, x in enumerate(win) if x[1] == "ldrsw"]
        subk = [j for j, x in enumerate(win)
                if x[1] == "sub" and re.search(r"#0x[0-9a-f]+", x[2])]
        if not ldrsw or not subk:
            continue
        kv = None
        for j in subk:
            m = re.search(r"#(0x[0-9a-f]+)", win[j][2])
            if m:
                kv = int(m.group(1), 16)
        base = None
        for j, x in enumerate(win):
            if x[1] == "adrp":
                mp = TARGET.search(x[2])
                off = None
                for y in win[j + 1:j + 4]:
                    if y[1] == "add":
                        off = re.search(r"#(0x[0-9a-f]+)", y[2])
                        break
                if mp and off:
                    base = int(mp.group(1), 16) + int(off.group(1), 16)
                    break
        if kv is None or base is None:
            continue
        table_edges.append(dict(br=a, base=base, key=kv, reg=ar))
        tables[base] = tables.get(base, 0) + 1
        keys[kv] = keys.get(kv, 0) + 1

    # Decode one table: every entry, raw and keyed.
    decoded = []
    all_targets = []
    if const and tables:
        for base, n in tables.items():
            keyv = next(iter(keys))
            raw = read_words(binary, const, base, n)
            for j, w in enumerate(raw):
                delta = w - keyv
                tgt = (base + delta) & 0xffffffffffffffff
                all_targets.append(tgt)
                decoded.append(dict(idx=j, raw=w & 0xffffffff, delta=delta,
                                    target=tgt))
        if verbose:
            print("table %#x, %d entries, key %#x" % (base, len(decoded), keyv))
            for d in decoded[:8]:
                print("  [%2d] raw=%#010x delta=%+7d -> %#x" %
                      (d["idx"], d["raw"], d["delta"], d["target"]))

    return dict(
        binary=os.path.basename(binary),
        file_size=os.path.getsize(binary),
        text_size=text["size"] if text else None,
        const_size=const["size"] if const else None,
        instructions=sum(1 for _, op, _, _ in insns
                         if not op.startswith(".")),
        census=census,
        direct_branch_targets=len(direct),
        direct_in_text=len(direct_in_text),
        direct_in_text_list=[dict(addr=hex(a), op=op, target=hex(t))
                             for a, op, t in direct_in_text],
        direct_branch_edges=len(direct_in_text),
        plain_adrp_add_br=plain_br,
        plain_targets_into_chunk=sum(1 for t in plain_targets if t in chunks),
        table_targets_into_chunk=sum(1 for t in all_targets if t in chunks),
        table_targets_in_text=sum(1 for t in all_targets if lo <= t < hi),
        chunk_symbols=len(chunks),
        direct_into_chunk=len(direct_into_chunk),
        direct_into_chunk_list=[dict(addr=hex(a), op=op, target=hex(t))
                                for a, op, t in sorted(direct_into_chunk)],
        table_driven_br=len(table_edges),
        table_entries=sum(tables.values()),
        table_bases={hex(k): v for k, v in tables.items()},
        table_keys=[hex(k) if k is not None else None for k in keys],
        table_decoded=decoded[:16],
        nlist=len(b["symbols"]),
        function_starts=len(b.get("function_starts", []) or []),
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--json")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    r = measure(a.binary, a.verbose)
    if a.json:
        json.dump(r, open(a.json, "w"), indent=1)
    print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
