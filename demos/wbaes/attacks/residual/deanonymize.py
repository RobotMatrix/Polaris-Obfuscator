"""De-anonymise a stripped Polaris export: seeded symbol names -> real names.

Reads two Mach-O files: the stripped target and a reference build of the same
source that still carries its symbols. The mapping is derived only from facts in
the target, in this order:

  1. the export trie (LC_DYLD_EXPORTS_TRIE) still carries the *original* names and
     their addresses, so each nlist entry is matched by address;
  2. renamed sections are matched to the reference by size (and by the size of the
     object they hold), not by guesswork;
  3. functions the stripper left without any name are matched by address order
     against the reference build's local symbols, and reported as an inference.

Usage: python3 deanonymize.py <stripped> <reference>
"""
import argparse
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("ms", os.path.join(HERE, "macho_symbols.py"))
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)

BASE = 0x100000000


def demangle(n):
    """Tiny readback for the names this binary actually exports."""
    n = n.lstrip("_")
    if n.startswith("ZNK5WBAES"):
        return "WBAES::" + n[9:] + "  (const)"
    if n.startswith("ZN5WBAES"):
        return "WBAES::" + n[8:]
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stripped")
    ap.add_argument("reference")
    a = ap.parse_args()
    S = ms.parse(a.stripped)
    R = ms.parse(a.reference)

    exp = {e["address"]: e["name"] for e in S["exports"]}
    sdef = {s["value"] - BASE: s for s in S["symbols"] if s["kind"] != "UNDEF" and s["value"] >= BASE}

    print("== symbol map (address -> seeded name -> name from the export trie)")
    exact = 0
    for off in sorted(exp):
        s = sdef.get(off)
        if not s:
            continue
        exact += 1
        print(f"  {off:#08x}  {s['name']:<14s} -> {exp[off]:<45s} {demangle(exp[off])}")
    print(f"  {exact}/{len(sdef)} defined symbols resolved by address\n")

    print("== sections")
    rsec = {s["size"]: s for s in R["sections"]}
    for sec in S["sections"]:
        ref = rsec.get(sec["size"])
        tag = ""
        if ref:
            tag = f"  == {ref['seg']},{ref['sect']}"
        print(f"  {sec['seg']},{sec['sect']:<14s} size {sec['size']:>10}{tag}")

    print("\n== functions without any remaining name (inferred order vs reference locals)")
    named = set(sdef)
    starts = [a_ for a_ in S["function_starts"] if (a_ - BASE) not in named]
    # only file-static functions were dropped by the stripper; the public WBAES
    # methods are still named in the target, so compare against the statics
    rlocals = sorted([s for s in R["symbols"]
                      if s["kind"] != "UNDEF" and s["name"].startswith("__ZL")
                      and s["sect_name"].endswith("__text") and s.get("size")],
                     key=lambda s: s["value"])
    print(f"  stripped: {len(starts)} unnamed starts; reference locals: {len(rlocals)}")
    for i, st in enumerate(starts):
        hint = ""
        if i < len(rlocals):
            hint = f"  ~ {rlocals[i]['name']} (order only)"
        print(f"  sub_{st:x}{hint}")


if __name__ == "__main__":
    main()
