#!/usr/bin/env python3
"""G4 information bound: can a table-shaped model ever fit 4 KiB?

G4 asks whether the attacker's recovered model fits `model_size_bound_bytes`.
For an arbitrary function F2^w -> F2^c presented as a table, the number of bits
is exactly c * 2^w (no compression is possible without assuming structure), so
the bound can be settled analytically instead of measured. This script computes
it, records the packed floor next to the naive uint64 size used by hsvm_games,
and states which window widths are excluded outright.

    g4_info_bound.py --out reports/S4-g3g4/info_bound.json
"""

import argparse
import json
import os
import sys

BOUND = 4096  # protocol.json hypothesis.model_size_bound_bytes


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--bound", type=int, default=BOUND)
    args = ap.parse_args()

    rows = []
    for w in (8, 16, 24, 32, 48, 64):
        c = w
        bits = c * (1 << w)
        packed = bits // 8
        naive = (1 << w) * 8
        rows.append({
            "w": w,
            "c": c,
            "table_bits": bits,
            "packed_bytes": packed,
            "naive_u64_bytes": naive,
            "packed_fits_bound": packed <= args.bound,
            "naive_fits_bound": naive <= args.bound,
            # For table-shaped models the packed size is a lower bound, so a
            # width whose packed size exceeds the bound cannot pass G4 at all.
            "table_g4_possible": packed <= args.bound,
        })

    first_impossible = min((r["w"] for r in rows if not r["table_g4_possible"]),
                           default=None)
    doc = {
        "bound_bytes": args.bound,
        "rows": rows,
        "conclusion": {
            "table_g4_possible_up_to_w": (first_impossible - 8)
            if first_impossible else None,
            "note": "packed size c*2^w bits is a lower bound for any table-shaped "
                    "model; family-aware models (e.g. recovering ARX keys) are a "
                    "different game and are not measured here",
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")

    for r in rows:
        print("w=%2d packed=%9d naive=%9d packed<=4K=%s"
              % (r["w"], r["packed_bytes"], r["naive_u64_bytes"],
                 r["packed_fits_bound"]))
    print("table-shaped G4 possible up to w=%s (bound %d bytes)"
          % (doc["conclusion"]["table_g4_possible_up_to_w"], args.bound))
    return 0


if __name__ == "__main__":
    sys.exit(main())
