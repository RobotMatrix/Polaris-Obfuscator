#!/usr/bin/env python3
"""What the recorded traces say without any key guessing.

  * identity: every level must reproduce the K=0 reference block for block, and
    the K=0 reference is anchored to the artifact by its published ciphertext and
    by re-deriving blocks with wblib.encrypt;
  * what one dummy does to a 64K boundary table: how often a trace has two
    candidates for the table the consistency attack reads, and how often the first
    candidate in program order is the wrong one. Those two numbers are the only
    reason any trace-count difference can exist;
  * whether the obvious realignment (sort by address, take the lowest) works.

usage: python3 rnd/measure.py --work /tmp/wbaes-rnd > rnd/measure.json
"""
import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
ATK = os.path.join(REPO, "demos", "wbaes", "attacks")
sys.path.insert(0, ATK)
sys.path.insert(0, os.path.join(ATK, "residual"))
import wblib as wb
import reslib as R

SEED = 0xB8AB764E
LEVELS = [("K0", "k0_s0"), ("K0shuf", "k0_s1"), ("K4", "k4_s1"), ("K16", "k16_s1"), ("K64", "k64_s1")]


def recs(path):
    raw = open(path, "rb").read()
    off, out = 0, []
    while off < len(raw):
        n = struct.unpack_from("<I", raw, off)[0]
        off += 4
        out.append([struct.unpack_from("<III", raw, off + 12 * i) for i in range(n)])
        off += 12 * n
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True, help="directory holding k0_s0/, k4_s1/, ...")
    ap.add_argument("--binary", default=None)
    ap.add_argument("--blocks", type=int, default=64, help="K=0 blocks re-derived with wblib")
    a = ap.parse_args(argv)
    binary = a.binary or os.path.join(REPO, "exported-binaries", "wbaes-challenge",
                                      "macos", "wbaes_vm2_clean")

    res = {"identity": {}, "levels": {}, "dummy_stats": {}}
    base = None
    for name, tag in LEVELS:
        pre = os.path.join(a.work, tag, "rnd_" + tag)
        ct = open(pre + "_ct.bin", "rb").read()
        seeds = open(pre + "_seeds.bin", "rb").read()
        tr = recs(pre + "_traces.bin")
        if base is None:
            base = ct
        res["identity"][name] = {
            "blocks": len(ct) // 16,
            "blocks_equal_to_k0": sum(1 for i in range(0, len(ct), 16) if ct[i:i + 16] == base[i:i + 16]),
            "distinct_seeds": len(set(struct.unpack("<%dI" % (len(seeds) // 4), seeds))),
            "accesses_per_block": sorted(set(len(t) for t in tr)),
            "traces": len(tr),
        }
        res["levels"][name] = tr

    # anchor the K=0 reference to the artifact, not to itself
    art, _ = R.load_shipped(binary, seed=SEED, cache=os.path.join(a.work, "table_plain.bin"))
    pts = open(os.path.join(a.work, "k0_s0", "rnd_k0_s0_pts.bin"), "rb").read()
    ct0 = open(os.path.join(a.work, "k0_s0", "rnd_k0_s0_ct.bin"), "rb").read()
    ok = sum(1 for i in range(a.blocks)
             if wb.encrypt(art.tab_obj, art.p0, pts[16 * i:16 * i + 16], art.env).hex()
             == ct0[16 * i:16 * i + 16].hex())
    res["identity"]["k0_vs_wblib"] = {"blocks": a.blocks, "equal": ok}
    # the recorded blocks are the PRNG plaintexts, so the challenge vector is
    # checked separately: the artifact must produce the published ciphertext, and
    # the harness prints the same value for its own challenge-vector block
    res["identity"]["challenge_vector"] = {
        "plaintext": R.CHALLENGE_PT,
        "published": R.CHALLENGE_CT,
        "wblib_over_artifact": wb.encrypt(art.tab_obj, art.p0,
                                          bytes.fromhex(R.CHALLENGE_PT), art.env).hex(),
    }

    for name in ("K4", "K16", "K64"):
        st = {"multi": 0, "first_wrong": 0, "total": 0, "sorted_wrong": 0, "clean_all16": 0}
        for i, tr in enumerate(res["levels"][name]):
            real = set(x for x, l, w in res["levels"]["K0"][i])
            okall = True
            for col in range(4):
                for row in range(4):
                    b = wb.enc_col(0, col) + wb.BDY_OFF + row * wb.N
                    hits = [x for x, l, w in tr if b <= x < b + wb.N]
                    st["total"] += 1
                    if len(hits) > 1:
                        st["multi"] += 1
                        okall = False
                        if hits[0] not in real:
                            st["first_wrong"] += 1
                        if min(hits) not in real:
                            st["sorted_wrong"] += 1
            if okall:
                st["clean_all16"] += 1
        st["traces"] = len(res["levels"][name])
        st["multi_frac"] = st["multi"] / st["total"]
        st["first_wrong_frac_of_multi"] = st["first_wrong"] / max(st["multi"], 1)
        st["clean_all16_frac"] = st["clean_all16"] / st["traces"]
        res["dummy_stats"][name] = st
    json.dump({"identity": res["identity"], "dummy_stats": res["dummy_stats"]}, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
