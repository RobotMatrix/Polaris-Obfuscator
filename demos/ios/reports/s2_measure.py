"""Static control-flow census + target-table attacks for S1/S2/S2b.

For one linked Mach-O arm64 binary it reports:

  * branch census in __text (direct b / b.cond / cbz / cbnz / tbz / tbnz,
    indirect br / blr, calls, ret)
  * every direct-branch successor that lands on a *split chunk head*, using the
    chunk symbols the same build emits with -split-symbols (that flag does not
    change the code, so the addresses are comparable)
  * how many `br` sites are table-driven, split into the S2 shape
    (adrp/add + ldrsw + sub #key + add + br) and the S2b shape
    (adrp/add + ldrsw + eor #c + sub + add + br, with the key folded out of a
    ring in another section)
  * three attacks on the target table, i.e. how many successors each one
    resolves back into __text:

      legacy  the S2 decoder: read the `sub #imm` of the consuming sequence,
              delta = entry - key, target = table + delta.  This is the 20-line
              script that got 42/42 out of S2 (SPLIT-COMPUTED-BRANCHES.md 6).
      naive   follow the S2b data flow (adrp/add/ldr of the ring) but treat the
              ring words as the key: try each of W0, W1, W0^W1, W0*W1, ~W0 and
              decode with both sub and xor.  This is what "I found the key"
              buys without knowing the encoding.
      scheme  the full scheme: K from the ring fold, per-entry mask from the
              cumulative xor of the `eor #imm` operands.  This is the floor of
              the measurement and it is reported on purpose: the scheme lives in
              the compiler, so a reader who reimplements it wins.  The point of
              the flag is that the table and the sequence alone do not say how.

Usage:
  python3 s2_measure.py BIN [--json out.json] [-v]
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
IMMHEX = re.compile(r"#(0x[0-9a-f]+)")
REG = re.compile(r"^([wx][0-9]+)")

WINDOW = 22          # instructions to look back from a `br`
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


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


def section_of(binary_parsed, addr):
    for s in binary_parsed["sections"]:
        if s["addr"] and s["addr"] <= addr < s["addr"] + s["size"]:
            return s
    return None


def read_bytes(binary, addr, count):
    b = section_of(BP, addr)
    if not b:
        return None
    off = b["offset"] + (addr - b["addr"])
    with open(binary, "rb") as f:
        f.seek(off)
        return f.read(count)


def read_word(binary, addr):
    d = read_bytes(binary, addr, 4)
    if d is None or len(d) < 4:
        return None
    return int.from_bytes(d[:4], "little", signed=False)


def read_qword(binary, addr):
    d = read_bytes(binary, addr, 8)
    if d is None or len(d) < 8:
        return None
    return int.from_bytes(d[:8], "little", signed=False)


def sx32(v):
    v &= MASK32
    return v - (1 << 32) if v & (1 << 31) else v


def reg_of(args):
    m = REG.match(args.strip())
    return m.group(1) if m else None


def page_of(args):
    m = TARGET.search(args)
    return int(m.group(1), 16) if m else None


def imm_of(args):
    m = IMMHEX.search(args)
    return int(m.group(1), 16) if m else None


def adrp_addresses(win, i):
    """For an adrp at win[i], the pages it can be paired with."""
    return page_of(win[i][2])


def base_before(win, upto, reg):
    """Value of `reg` set by an adrp (+ optional add) before index `upto`."""
    for j in range(upto - 1, -1, -1):
        op, ar = win[j][1], win[j][2]
        if op == "add" and reg_of(ar) and reg_of(ar) == reg:
            parts = ar.split(",")
            off = imm_of(parts[-1]) if len(parts) > 1 else None
            src = reg_of(parts[1]) if len(parts) > 1 else None
            if off is not None and src:
                p = base_before(win, j, src)
                if p is not None:
                    return p + off
        elif op == "adrp" and reg and reg_of(ar) == reg:
            return page_of(ar)
        elif op == "adrp" and reg and ar.strip().startswith(reg + ","):
            return page_of(ar)
    return None


def load_base(win, i):
    """Base address of a load `ldr/ldrsw Rt, [Rn, #imm]` at win[i]."""
    ar = win[i][2]
    m = re.match(r"^([wx][0-9]+), \[([wx][0-9]+)(?:, #(0x[0-9a-f]+))?\]", ar)
    if not m:
        return None, None
    rn = m.group(2)
    # otool prints the *byte* offset for scaled addressing modes.
    off = int(m.group(3), 16) if m.group(3) else 0
    b = base_before(win, i, rn)
    # Returns the *table* base (what adrp/add produced) and the byte offset the
    # load used; the entry lives at base + off.
    return b, off


def ring_word(binary, win, upto):
    """Last `adrp/add/ldr` in win[:upto] that loads a 64-bit word."""
    for j in range(upto - 1, -1, -1):
        if win[j][1] != "ldr":
            continue
        ar = win[j][2]
        m = re.match(r"^(x[0-9]+), \[([wx][0-9]+)(?:, #(0x[0-9a-f]+))?\]", ar)
        if not m:
            continue
        b, off = load_base(win, j)
        if b is None:
            continue
        return read_qword(binary, b + off)
    return None


def analyse(binary, verbose=False):
    b = MS.parse(binary)
    text = section(b, "__TEXT", "__text")
    const = section(b, "__TEXT", "__const")
    insns = disasm(binary)

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

    direct = [(a, op, args, t) for a, op, args, t in insns if t is not None]
    lo, hi = (text["addr"], text["addr"] + text["size"]) if text else (0, 0)
    direct_in_text = [(a, op, t) for a, op, _, t in direct if lo <= t < hi]
    direct_into_chunk = [(a, op, t) for a, op, t in direct_in_text if t in chunks]

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

    # --- table-driven `br`, both shapes ------------------------------------
    sites = []          # one record per table-driven br
    prev_term = -1
    for i, (a, op, ar, _) in enumerate(insns):
        if op in INDIRECT or op in DIRECT_B:
            prev_term, start_term = i, prev_term
        if op != "br":
            continue
        # One window per edge: stop at the previous branch, so a neighbouring
        # edge's `eor`/`ldrsw` cannot be mistaken for this one's.
        win = insns[max(start_term + 1, i - WINDOW):i]
        ldrsw = [j for j, x in enumerate(win) if x[1] == "ldrsw"]
        if not ldrsw:
            continue
        subs = [j for j, x in enumerate(win)
                if x[1] == "sub" and imm_of(x[2]) is not None]
        eors = [j for j, x in enumerate(win)
                if x[1] == "eor" and imm_of(x[2]) is not None
                and reg_of(x[2]).startswith("w")]
        entries = []
        for j in ldrsw:
            base, _ = load_base(win, j)
            if base is None:
                continue
            boff = imm_of(win[j][2]) or 0
            raw = read_word(binary, base + boff)
            if raw is None:
                continue
            entries.append(dict(base=base, idx=boff // 4, raw=raw))
        if not entries:
            continue
        rec = dict(br=a, entries=entries, kind=None, key=None, eors=[],
                   ring=None, dirty=sum(1 for x in win
                                        if x[1].startswith(".")))
        loaded = set()
        for j in ldrsw:
            r = reg_of(win[j][2])
            if r:
                loaded.add(r)
        # S2: `sub wT, wT, #key` whose destination is a register an ldrsw just
        # defined -- a `sub sp, sp, #0x80` in the same block is not the key.
        subs = [j for j in subs
                if reg_of(win[j][2]) and reg_of(win[j][2]) in loaded
                and win[j][2].split(",")[1].strip() == reg_of(win[j][2])]
        if subs:
            kv = None
            for j in subs:
                v = imm_of(win[j][2])
                if v is not None:
                    kv = v
            rec["kind"] = "plain"
            rec["key"] = kv
        elif eors:
            rec["kind"] = "encoded"
            rec["eors"] = [imm_of(win[j][2]) for j in eors]
            rec["ring"] = ring_word(binary, win, len(win))
        else:
            continue
        sites.append(rec)

    tables = {}
    for r in sites:
        for e in r["entries"]:
            tables[e["base"]] = tables.get(e["base"], 0) + 1

    # --- attacks -----------------------------------------------------------
    def resolve(target_list, label):
        in_text = [t for t in target_list if lo <= t < hi]
        return dict(label=label, resolved=len(in_text), of=len(target_list),
                    into_chunk=sum(1 for t in in_text if t in chunks),
                    in_text=in_text)

    # legacy: entry - key
    legacy_targets = []
    for r in sites:
        if r["key"] is None:
            continue
        for e in r["entries"]:
            legacy_targets.append((e["base"] + sx32(e["raw"] - r["key"]))
                                  & MASK64)
    legacy = resolve(legacy_targets, "legacy sub #imm")

    # naive: the ring words used directly as the key, sub and xor.  This is
    # what following the S2b data flow buys without knowing the encoding.
    naive_variants = []
    enc_sites = [r for r in sites if r["kind"] == "encoded" and r["ring"]]
    for variant in ("W0", "W1", "W0^W1", "W0*W1", "~W0"):
        for mode in ("sub", "xor"):
            tg = []
            for r in enc_sites:
                w0 = r["ring"] & MASK32
                w1 = (r["ring"] >> 32) & MASK32
                k = {"W0": w0, "W1": w1, "W0^W1": w0 ^ w1,
                     "W0*W1": (w0 * w1) & MASK32, "~W0": ~w0 & MASK32}[variant]
                for e in r["entries"]:
                    d = (e["raw"] - k) if mode == "sub" else (e["raw"] ^ k)
                    tg.append((e["base"] + sx32(d)) & MASK64)
            naive_variants.append(resolve(tg, "naive %s %s" % (variant, mode)))
    naive_best = dict(label="naive ring key", resolved=0, of=0, into_chunk=0)
    if naive_variants:
        best = max(naive_variants, key=lambda v: v["resolved"])
        naive_best = dict(best)
        naive_best["of"] = max(v["of"] for v in naive_variants)
        naive_best["best"] = best["label"]
        naive_best["all_variants"] = [
            dict(label=v["label"], resolved=v["resolved"],
                 into_chunk=v["into_chunk"]) for v in naive_variants]

    # scheme-aware: ring fold + cumulative `eor #imm` masks
    scheme_targets = []
    scheme_sites = 0
    for r in sites:
        if r["kind"] != "encoded" or r["ring"] is None:
            continue
        k = ((r["ring"] & MASK32) ^ ((r["ring"] >> 32) & MASK32)) & MASK32
        mask = k
        scheme_sites += 1
        for n, e in enumerate(r["entries"]):
            if n < len(r["eors"]):
                mask ^= r["eors"][n]
            scheme_targets.append((e["base"] + sx32(e["raw"] - mask)) & MASK64)
    scheme = resolve(scheme_targets, "scheme-aware")

    all_plain = [r for r in sites if r["kind"] == "plain"]
    all_enc = [r for r in sites if r["kind"] == "encoded"]

    if verbose:
        for r in sites[:6]:
            print("site %#x kind=%s key=%s ring=%s eors=%s" %
                  (r["br"], r["kind"],
                   hex(r["key"]) if r["key"] is not None else "-",
                   hex(r["ring"]) if r["ring"] is not None else "-",
                   [hex(x) for x in r["eors"]]))
            for e in r["entries"]:
                print("   idx=%d raw=%#010x base=%#x" %
                      (e["idx"], e["raw"], e["base"]))

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
        chunk_symbols=len(chunks),
        direct_into_chunk=len(direct_into_chunk),
        direct_into_chunk_list=[dict(addr=hex(a), op=op, target=hex(t))
                                for a, op, t in sorted(direct_into_chunk)],
        table_driven_br=len(sites),
        table_plain_br=len(all_plain),
        table_enc_br=len(all_enc),
        table_entries=sum(len(r["entries"]) for r in sites),
        table_bases={hex(k): v for k, v in tables.items()},
        table_keys=sorted({hex(r["key"]) for r in all_plain
                           if r["key"] is not None}),
        enc_windows_with_dirty=sum(1 for r in all_enc if r["dirty"]),
        attacks=dict(legacy=dict(legacy, in_text=[hex(t) for t in
                                                  legacy["in_text"][:8]]),
                     naive=naive_best, scheme=scheme),
        nlist=len(b["symbols"]),
        function_starts=len(b.get("function_starts", []) or []),
    )


BP = None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--json")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    global BP
    BP = MS.parse(a.binary)
    r = analyse(a.binary, a.verbose)
    if a.json:
        json.dump(r, open(a.json, "w"), indent=1)
    print(json.dumps(r, indent=1))


if __name__ == "__main__":
    main()
