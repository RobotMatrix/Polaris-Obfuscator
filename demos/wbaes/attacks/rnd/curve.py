#!/usr/bin/env python3
"""Traces-to-converge curve for the consistency attack, per randomisation level.

The attack is not reimplemented: this imports collision_pairs() and solve_half()
from attacks/residual/consistency_attack.py and boundary_halves logic from
attacks/residual/reslib.py, and evaluates the same 8 halves at each trace count.
The two modes differ only in which traces a half may use:

  naive   every trace; the observation is the first address that falls inside the
          64K boundary table. That is exactly what reslib.logical_index does, so
          this mode *is* the shipped attack on a trace file with dummy reads.
  filter  drop the traces where that table is hit more than once in the block. A
          real block touches each 64K boundary table exactly once, so the extra
          hit is noise, and the multiplicity is visible without any key.

usage:
  python3 rnd/curve.py --traces /tmp/wbaes-rnd/k16/rnd_k16_s1_traces.bin --mode filter
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
ATK = os.path.join(REPO, "demos", "wbaes", "attacks")
sys.path.insert(0, ATK)
sys.path.insert(0, os.path.join(ATK, "residual"))
import wblib as wb
import reslib as R
from consistency_attack import collision_pairs, solve_half

TS = (32, 64, 128, 256, 512, 1024, 4096)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--mode", default="naive", choices=("naive", "filter"))
    ap.add_argument("--cap", type=int, default=2000)
    ap.add_argument("--row", type=int, default=0)
    ap.add_argument("--offset", type=int, default=0, help="skip this many usable traces")
    ap.add_argument("--key", default=R.CHALLENGE_KEY)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)

    env = wb.hy_env_mix(*wb.DEFAULT_ENV)
    traces, pts = wb.read_traces(a.traces)
    atr = [[x[0] for x in t] for t in traces]
    key = bytes.fromhex(a.key)
    m = wb.MC[a.row]

    # the 8 halves all come from the (col, row) boundary table of round 0
    cand = {}
    for col in range(4):
        base = wb.enc_col(0, col) + wb.BDY_OFF + a.row * wb.N
        tag = wb.hy_tag(0, 0, col, wb.K_BDY_T32 + a.row)
        for half in (0, 1):
            cand[(col, half)] = [
                [wb.hy_scatter_inv(x - base, env, tag) >> (8 * half) & 0xFF
                 for x in tr if base <= x < base + wb.N]
                for tr in atr
            ]

    out = {"traces": a.traces, "mode": a.mode, "cap": a.cap, "offset": a.offset, "curve": {}}
    for T in TS:
        if T > len(pts):
            continue
        counts, pairs_n, kept, rec = [], [], [], {}
        for col in range(4):
            srcs = [wb.sr_src(k + 4 * col) for k in range(4)]
            for half in (0, 1):
                obs_all = cand[(col, half)]
                if a.mode == "filter":
                    idx = [i for i, o in enumerate(obs_all) if len(o) == 1]
                else:
                    idx = [i for i, o in enumerate(obs_all) if o]
                idx = idx[a.offset:a.offset + T]
                kept.append(len(idx))
                obs = [obs_all[i][0] for i in idx]
                p = [pts[i] for i in idx]
                pairs = collision_pairs(obs, a.cap) if obs else []
                hits = (solve_half(p, pairs, srcs[2 * half], srcs[2 * half + 1],
                                   m[2 * half], m[2 * half + 1]) if pairs else [])
                counts.append(len(hits))
                pairs_n.append(len(pairs))
                if len(hits) == 1:
                    rec[srcs[2 * half]] = hits[0][0]
                    rec[srcs[2 * half + 1]] = hits[0][1]
        if len(rec) == 16:
            rk = bytes(rec[i] for i in range(16))
            got = {"key": rk.hex(), "equals_published": rk.hex() == a.key,
                   "reproduces_ct": wb.aes_encrypt(bytes.fromhex(R.CHALLENGE_PT), rk).hex()
                   == R.CHALLENGE_CT}
        else:
            got = {"key": None, "bytes": len(rec)}
        out["curve"][T] = {"unique": sum(1 for c in counts if c == 1),
                           "empty": sum(1 for c in counts if c == 0),
                           "widest": max(counts), "per_half": counts,
                           "pairs": [min(pairs_n), max(pairs_n)],
                           "traces_used": [min(kept), max(kept)], "key": got}
        print("%5d traces: unique %d/8  empty %d  widest %d  pairs %d..%d  key %s"
              % (T, out["curve"][T]["unique"], out["curve"][T]["empty"],
                 out["curve"][T]["widest"], min(pairs_n), max(pairs_n),
                 (got["key"] or "-") + (" OK" if got.get("reproduces_ct") else "")))
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
