# White-box challenge — 2026-11 (independent red team)

Three self-contained macOS arm64 binaries. Each is a white-box AES-128-ECB
implementation: it takes a 16-byte block, runs it through a 70 MB table program
(the table is inside the binary), and prints the ciphertext.

**Goal: recover the 128-bit AES key of each binary, and describe how you did it.**

## Files

| file | bytes | sha256 |
|---|---|---|
| `wbaes_f4_max` | 70,707,184 | `4d72a95a48d6ce99b3ac4bf0a088b98b87dee8700ed17611ea2c27d1db35dba3` |
| `wbaes_vm2_max` | 70,707,184 | `a68e3c7c713fd1f1f59935df1f84a18ee85e857d04072b8abbf2e8b9455cd9b3` |
| `wbaes_f4_hard` | 70,296,208 | `84117df40bd992dc7cff13b2d03bedf0dc018756d3789626709381fdd3151a1f` |

`sha256.txt` repeats the hashes for checking the copies survived transfer.

`wbaes_f4_hard` is the same F4 generation as `wbaes_f4_max` — same key, same
ciphertext, byte-identical table — built with the de-symbolisation pass described
below. It is a third target, not a harder one; read that section before choosing
what to attack.

## What is given

- The three binaries, runnable as-is (`./wbaes_f4_max` prints a known-answer check,
  `./wbaes_f4_hard` prints `check: ok`).
- One known-answer pair per binary, which is enough to verify a recovered key:

```
wbaes_f4_max
  plaintext  6bc1bee22e409f96e93d7e117393172a
  ciphertext 2c0b8f87b6aa8d4a8c7b12d8d2227c8d

wbaes_vm2_max
  plaintext  6bc1bee22e409f96e93d7e117393172a
  ciphertext 7672415a6313c58518fc95c9cb6922b8

wbaes_f4_hard   (same key and ciphertext as wbaes_f4_max)
  plaintext  6bc1bee22e409f96e93d7e117393172a
  ciphertext 2c0b8f87b6aa8d4a8c7b12d8d2227c8d
```

`wbaes_f4_hard` prints only `check: ok` when run. It carries no known-answer
vector — the self-check derives a plaintext from a build seed and compares a hash
of the answer — so the pair above is the only block you get from it without
instrumenting it.

- The fact that the block cipher is AES-128-ECB. Hiding that was never claimed to
  work: the block size, the nine rounds and the algebra identify it within minutes.

## What is deliberately not given

- The keys. If a procedure prints a key, check it against the known-answer pair
  above plus `openssl enc -aes-128-ecb -K <key> -nopad` on the same plaintext.
- Any hint about the table layout beyond "70 MB, one section".

## `wbaes_f4_hard`: what was removed, and what it did not buy

Same sources as `wbaes_f4_max`, rebuilt through the de-symbolisation pass
(`tools/harden_export.py`, seed `polaris-f4-export-2026-11-18`). Three things were
changed, all of them metadata or test vectors; no code and no table byte moved:

- **Section names.** `__DATA,__hytab` (the 70 MB table) and `__DATA,__hsvm` (the
  bytecode) are now `__DATA,__rpw3sxyhfp` and `__DATA,__r77nbreolp`.
- **Symbols.** All 16 defined symbols are per-build seeded names
  (`__hsvm_entry` → `_mrtisyvda7`, `_hsvm_table` → `_r2wqkkzdie`), local and debug
  symbols are dropped, and the string table that named them is rewritten. `nm -a`
  matches nothing for `aes|wbaes|hsvm|hytab|sbox|mixcol|rcon|test_pt|test_ct`.
- **The known-answer vector.** The NIST plaintext/ciphertext pair is gone from
  `__const`, along with the `plaintext :` / `vector-match` printf strings. The
  self-check now derives a plaintext from a 32-bit build seed and compares an
  FNV-1a-64 of the answer, so the binary prints `check: ok` and nothing else.

**Measured cost to our own extractor: none worth counting.** It stops at the loader
(`no __hytab section`) in 0.04 s; one line — take the 70 MB section by size instead
of by name — puts it back on the same key in the same time:

| | unhardened `wbaes_f4_max` | `wbaes_f4_hard` |
|---|---|---|
| extractor as committed | key in 15.6 s cold, 0.2 s warm | **fails at the loader, 0.04 s** |
| one-line loader change (section by size) | n/a (not needed) | key in 15.3 s cold, 0.2 s warm |
| of which: read + find input bijection | 0.02 s | 0.02 s |
| of which: locate the mask seed | 0.07 s | 0.02 s |
| of which: unmask 70 MB in Python | 15.0 s | 15.5 s |
| of which: the algebra itself | 0.19 s | 0.20 s |

Detectability score (`tools/m1_detect.py`, what `nm`/`otool`/`strings` give you):
**100 → 0** against `wbaes_f4_max`, and 155 → 0 against the debug build that still
carries the vector and the printf strings.

The honest reading: this build removes the name tag, the section hint and the free
known-answer block. It does not change what the algebra costs, and the table is
byte-identical, so anyone who finds the 70 MB section and unmasks it is exactly
where they were with `wbaes_f4_max`. If you want the target that punishes a lazy
first pass, take this one; if you want the one whose shape is genuinely different,
take `wbaes_vm2_max`. The F4 pair differs only in metadata.

## Ground rules

- Local, offline analysis of the files as delivered. Debuggers, tracing and
  instrumentation are fair game — one generation was measured to fall to an
  address-trace attack, so if you want the harder of the three, start with `wbaes_vm2_max`.
- Independent methods are more useful than reproducing ours. Our own scripts and their
  measured costs are in the source repository; if you read them, say so, because the
  interesting number is the cost of an attack that was written without them.
- Report: key, wall-clock cost, what tooling you used, and which step was the real
  obstacle. A negative result (you could not get it in N hours) is just as useful.

## Reference point, stated up front

These are not hardened against key extraction, and the numbers are known:

- `wbaes_f4_max`: the column combine is 16 bits wide but the encoding it can carry is
  forced to be affine, which makes the 2^16 pair tables exactly XOR-separable. Our
  script needs 8,192 consistency tests, 0.19 s of algebra and 15.6 s end to end cold
  on the packaging host (0.2 s once the unmasked table is cached) — of that, 15.0 s is
  the Python unmask of the 70 MB section and 0.02 s is finding the input bijection.
- `wbaes_f4_hard`: the same key and the same table behind seeded names. The script
  above does not start on it at all (`no __hytab section`, 0.04 s); change the loader
  to pick the 70 MB section by size and it recovers the same key in 15.3 s cold /
  0.2 s warm. Add a few minutes of human time for that one line, not a new attack.
- `wbaes_vm2_max`: per-lane encodings with a 32-bit recoding. Our static attack needs
  16,384 tests and ~18 s; an address-trace attack needs 64 traces and about a second.

So the point of this exercise is not whether it falls, but how far an independent
attacker gets without the repository, and where they spend their time. If you get the
key in minutes, that matches our measurements; if you get stuck, that is a finding
worth more to us than the key.

## What these builds do contain (so you know it is not a stub)

- The AES key schedule is not in the binary in any standard form; keys live inside the
  encoded tables.
- A bytecode VM (`hsvm`) computes the per-round table offsets at load time; the
  lowered code has no dispatch loop.
- A double-computation check for fault attacks (a single injected fault yields junk
  output), and table seals that fail closed if the table or schedule block is modified.
