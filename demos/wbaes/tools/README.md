# tools/ — export hardening for the white-box artifact

Four programs and a driver. The driver is the only thing you normally run:

```bash
python3 demos/wbaes/tools/harden_export.py \
        --src demos/wbaes --out /tmp/wbaes-hard \
        --seed "$(date +%Y%m%d-%H%M%S)" --probe --bench --vmtest --m1
```

`--src` must be the tree that holds `hy_table.bin`, `hy_seal.h`, `hy_in.h` and
`hy_tab.S` (they are written by `gen_hybrid`, so generate the table first). The
driver writes everything into `--out` and never edits `--src`.

## What each file does

| file | stage | why it exists |
|---|---|---|
| `harden_export.py` | driver | table scrub → KAT replacement → build → Mach-O scrub → self-check, plus the optional probe/bench/VM/vm-negative builds |
| `hy_scrub.cpp` | 1. table | pre-composes every 256-entry S-box-shaped table with a per-build affine map and absorbs the inverse into the 64K decode tables it feeds. 0 bytes / 0 ops at run time |
| `macho_scrub.py` | 3. metadata | post-link rename of every custom section and every defined symbol from the build seed, drops local/debug symbols, rebuilds `LC_SYMTAB`/`LC_DYSYMTAB`, re-signs ad hoc |
| `m1_detect.py` | measure | the attacker's first ten minutes as a score: `nm`, `otool -l`, `__cstring`, S-box byte search, NIST vector search, 256-entry table classifier, build-metadata scan |
| `m1scan.c` | measure | the byte half of M1: counts 256-byte windows that are permutations and 4-uniform (an S-box row up to invertible maps on both sides). Compiled on demand by `m1_detect.py` |
| `hy_selftest.cpp` | diagnose | compares every round of a rewritten table against the original, one line per `(dir, round)`. This is what caught the index-permutation dead end — see the header of `hy_scrub.cpp` |
| `vm_negative_test.cpp` | prove | V2 of `VM-REQUIREMENT.md` on the hardened tree: flip one schedule byte the code never reads directly, and the ciphertext must move because the VM recomputes the offsets from the renamed section |

## Why the rename happens after the link

`-mllvm -passes=hsvm` reads `@hsvm_bytecode`, `@hsvm_entry`, `@hsvm_table` and
`@hsvm_table_len` **by name** while lowering, so the names have to exist during
the build. Once the executable is linked, every reference is an address inside
one image, so the names are metadata: deleting or renaming them cannot change
behaviour. `macho_scrub.py` rewrites the symbol table in place (the new string
table is padded to the old size, so no load command moves) and fixes the
`LC_DYSYMTAB` ranges plus the stub indirection table, then re-signs ad hoc —
an arm64 macOS binary with a stale embedded signature is killed on exec.

For a device build the last step must sign with the real identity and
entitlements instead; `codesign -s -` is enough only because this artifact is a
`macos` challenge binary.

## Verifying by hand

```bash
nm -a /tmp/wbaes-hard/wbaes_hard          # 16 seeded names + libc imports
otool -l /tmp/wbaes-hard/wbaes_hard | grep sectname
strings -a /tmp/wbaes-hard/wbaes_hard | grep -Ei 'aes|wbaes|hytab|hsvm|sbox|mixcolumns|rcon'
python3 demos/wbaes/tools/m1_detect.py --bin /tmp/wbaes-hard/wbaes_hard --seal demos/wbaes
```
