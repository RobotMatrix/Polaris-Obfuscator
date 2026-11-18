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
| `hy_scrub.cpp` | 1. table | pre-composes every 256-entry S-box-shaped table with a per-build affine map and absorbs the inverse into the 64K decode tables it feeds. 0 bytes / 0 ops at run time. **No target in the F4 generation** (its front is 2^16-entry 16-bit pair tables, not S-box rows): it verifies the artifact, writes it back byte-for-byte and reports `tables_reenencoded: 0` — see its header and README §5.29 |
| `macho_scrub.py` | 3. metadata | post-link rename of every custom section and every defined symbol from the build seed, drops local/debug symbols, rebuilds `LC_SYMTAB`/`LC_DYSYMTAB`, empties `LC_DYLD_EXPORTS_TRIE` (the second name table), re-signs ad hoc |
| `m1_detect.py` | measure | the attacker's first ten minutes as a score: `nm`, `otool -l`, `__cstring`, the export trie and the string table, S-box byte search, NIST vector search, 256-entry table classifier, build-metadata scan |
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

The symbol table is **not** the only place those names live. ld64 also writes the
defined names into `LC_DYLD_EXPORTS_TRIE`, and the tool refuses to write an
artifact whose trie or string table still matched `WBAES|hsvm|hy_vm|wbaes|hytab|
_ZN` after the rewrite. Rewriting one name table and leaving the other is worse
than doing nothing: the artifact looks anonymous to `nm` while `dyld_info
-exports` still prints every original name at its address.

Two more places hold names, both handled now (`--no-zero-slack` opts out of the
first, `--unwind neutralise` enables the second):

* **dead bytes.** A table that is rewritten in place keeps the bytes it no
  longer points at. After `strip`, the export trie's old nodes are unreachable
  but still spell `decryptPK7AES_ctxPh`, `ECB_`, ... (measured: 1,608 printable
  fragments in a 34,176 B trie region of the wbaes artifact, SPLIT-SYMBOLS-AB.md).
  `zero_trie_slack` zeroes exactly the bytes the trie walk cannot reach, and
  `zero_linkedit_slack` zeroes every `__LINKEDIT` byte no load command claims.
* **`__unwind_info`.** It is a name-free table that still enumerates the real
  function starts (15 of 17 entries on wbaes: precision 0.88), and neither
  `strip` nor this tool used to touch it. `--unwind neutralise` rewrites it as
  a valid header with zero index entries, at the same offset and size.

Order matters: `strip` must run **before** this tool. Emptying the trie changes
its `datasize`, after which ld64's `strip` refuses the file ("function starts
data out of place"); `--exports keep` is the only mode `strip` still accepts
afterwards. Strip-then-scrub is the supported order and what the B profile uses.

The post-condition now tests two things, and both are about *original* names:
no name that was in the file before the rewrite may still be in the string
table, and no surviving name may **start** with a tell prefix. The old check
searched the whole string table for `_ZN` case-insensitively, which also matches
inside the tool's own base32 names (`_zns4zohl73`); with S1's chunk labels in
the table that rejected 151 of 200 seeds (75.5%), not the 2% measured when the
table held 17 names.

For a device build the last step must sign with the real identity and
entitlements instead; `codesign -s -` is enough only because this artifact is a
`macos` challenge binary.

## Verifying by hand

```bash
nm -a /tmp/wbaes-hard/wbaes_hard          # 16 seeded names + libc imports
dyld_info -exports /tmp/wbaes-hard/wbaes_hard   # no entries
otool -l /tmp/wbaes-hard/wbaes_hard | grep sectname
strings -a /tmp/wbaes-hard/wbaes_hard | grep -Ei 'aes|wbaes|hytab|hsvm|sbox|mixcolumns|rcon'
python3 demos/wbaes/tools/m1_detect.py --bin /tmp/wbaes-hard/wbaes_hard --seal demos/wbaes
```
