#!/usr/bin/env python3
"""macho_scrub.py — per-build renaming of Mach-O sections and symbols.

Why this exists
---------------
The white-box artifact used to announce its purpose in three places that cost an
attacker nothing to read:

  * section names  __DATA,__hytab / __DATA,__hsvm   ("hybrid table", "HSV VM")
  * symbol names   _kHyTab, _hsvm_entry, _hsvm_bytecode, _hsvm_table,
                   _hsvm_table_len, _hsvm_mem, _ZN5WBAES... , test_pt/test_ct
  * the string table that ties the two together

The HSV pass reads @hsvm_bytecode / @hsvm_entry / @hsvm_table / @hsvm_table_len
BY NAME at compile time, so the rename cannot happen in the source. After
lowering, every reference is already an absolute/PC-relative address inside one
executable, so after the link the names are pure metadata: renaming or deleting
them cannot change behaviour. That is why this runs post-link.

What it does
------------
  1. every section whose name is not a stock Mach-O section gets a name derived
     from the build seed  ("__q7f2hk3m" style) — no purpose, no two builds alike
  2. every defined external symbol is renamed from the same seed
  3. debug/local symbols (N_STAB, and every non-external entry) are dropped
  4. LC_SYMTAB is rewritten in place (the new string table is padded to the old
     size, so no other load command moves)
  5. the file is re-signed ad-hoc (arm64 refuses to exec an invalid signature)

Undefined imports (`_printf`, `_arc4random`, ...) keep their names: they are
libc, they name nothing about this program, and `nm -u` on any binary shows them.

Usage:
    python3 macho_scrub.py --in a.out --out b.out --seed build-2026-11-18
    python3 macho_scrub.py --in a.out --check --seed s     # report only
"""
import argparse
import hashlib
import struct
import subprocess
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_CODE_SIGNATURE = 0x1D
LC_DYSYMTAB = 0xB

N_STAB = 0xE0
N_TYPE = 0x0E
N_UNDF = 0x00
N_EXT = 0x01

# Stock section names. Everything else in a segment is a custom section and gets
# a seeded name. (Renaming __text/__cstring/... would confuse otool/ld, not the
# attacker, so the whitelist is about tooling, not secrecy.)
STOCK = {
    "__text", "__stubs", "__stub_helper", "__const", "__cstring", "__oslog",
    "__unwind_info", "__eh_frame", "__gcc_except_tab", "__data", "__bss",
    "__common", "__got", "__la_symbol_ptr", "__nl_symbol_ptr", "__mod_init_func",
    "__mod_term_func", "__thread_vars", "__thread_data", "__thread_bss",
    "__objc_classlist", "__objc_protolist", "__objc_imageinfo", "__objc_const",
    "__objc_selrefs", "__objc_classrefs", "__objc_superrefs", "__objc_catlist",
    "__objc_protorefs", "__objc_methname", "__objc_methtype", "__objc_ivar",
    "__data_const", "__typeref", "__swift5_types", "__swift5_proto",
    "__swift5_fieldmd", "__swift5_reflstr", "__swift5_builtin", "__swift5_assocty",
    "__swift5_capture", "__swift5_mpenum", "__swift5_protos", "__const_const",
    "__auth_ptr", "__init_offsets", "__chain_starts",
}


def seeded_name(seed: str, kind: str, orig: str, width: int = 10) -> str:
    """Deterministic, seed-dependent, purpose-free name."""
    digest = hashlib.sha256(("%s|%s|%s" % (seed, kind, orig)).encode()).digest()
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"  # exactly 32 symbols = 5 bits
    n = 0
    for byte in digest:
        n = (n << 8) | byte
    out = []
    for _ in range(width):
        out.append(alphabet[n & 31])
        n >>= 5
    return "".join(out)


class MachO:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = bytearray(f.read())
        magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, _res = \
            struct.unpack_from("<IiiIIIII", self.data, 0)
        if magic != MH_MAGIC_64:
            raise SystemExit("%s: not a thin 64-bit little-endian Mach-O" % path)
        self.cputype = cputype
        self.ncmds = ncmds
        self.cmds = []  # (offset_of_cmd, cmd, cmdsize)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            self.cmds.append((off, cmd, cmdsize))
            off += cmdsize

    def segments(self):
        for off, cmd, cmdsize in self.cmds:
            if cmd != LC_SEGMENT_64:
                continue
            segname = self.data[off + 8:off + 24].split(b"\0")[0].decode()
            nsects = struct.unpack_from("<I", self.data, off + 64)[0]
            for i in range(nsects):
                so = off + 72 + i * 80
                yield segname, so

    def sections(self):
        """(segname, sectname, section_header_offset)"""
        for segname, so in self.segments():
            sectname = self.data[so:so + 16].split(b"\0")[0].decode()
            yield segname, sectname, so

    def symtab(self):
        for off, cmd, cmdsize in self.cmds:
            if cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", self.data, off + 8)
                return off, symoff, nsyms, stroff, strsize
        return None

    def symbols(self):
        tab = self.symtab()
        if tab is None:
            return []
        _off, symoff, nsyms, stroff, strsize = tab
        strtab = self.data[stroff:stroff + strsize]
        out = []
        for i in range(nsyms):
            so = symoff + i * 16
            n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", self.data, so)
            end = strtab.find(b"\0", n_strx)
            name = strtab[n_strx:end if end >= 0 else len(strtab)].decode("utf-8", "replace")
            out.append(dict(off=so, strx=n_strx, type=n_type, sect=n_sect,
                            desc=n_desc, value=n_value, name=name))
        return out

    def write(self, path):
        with open(path, "wb") as f:
            f.write(self.data)


def harden(inp, out, seed, check=False, strip_locals=True, keep_undef=True, verbose=True):
    m = MachO(inp)
    renamed_sections = []
    for segname, sectname, so in m.sections():
        if sectname in STOCK or not sectname:
            continue
        new = "__" + seeded_name(seed, "sect", sectname)
        assert len(new) <= 16
        m.data[so:so + 16] = new.encode().ljust(16, b"\0")
        renamed_sections.append((segname, sectname, new))

    tab = m.symtab()
    renamed_syms, dropped = [], 0
    if tab is not None:
        sym_cmd_off, symoff, nsyms, stroff, strsize = tab
        syms = m.symbols()
        extdefs, undefs = [], []
        for idx, s in enumerate(syms):
            ntype = s["type"]
            is_stab = (ntype & N_STAB) != 0
            is_ext = (ntype & N_EXT) != 0
            kind = ntype & N_TYPE
            if is_stab or (not is_ext and strip_locals):
                dropped += 1
                continue
            (undefs if kind == N_UNDF else extdefs).append((idx, s))
        # New order: external definitions, then undefined imports. The indirect
        # symbol table (stubs -> imports) is remapped below, so it stays valid.
        order = extdefs + undefs
        remap = {old: new for new, (old, _s) in enumerate(order)}
        if not keep_undef:
            raise SystemExit("--drop-undefined is not supported: the stub helper "
                             "needs the import indices")

        # rebuild the string table
        strtab = bytearray()
        strtab += b"\0\0\0\0"  # keep offset 0 unused, like ld
        for _old, s in order:
            if (s["type"] & N_TYPE) == N_UNDF:
                newname = s["name"]  # libc import: names nothing about us
            else:
                newname = "_" + seeded_name(seed, "sym", s["name"])
                renamed_syms.append((s["name"], newname))
            s["strx"] = len(strtab)
            strtab += newname.encode() + b"\0"
        if len(strtab) > strsize:
            raise SystemExit("scrubbed string table (%d B) does not fit in the original "
                             "%d B; refusing to move __LINKEDIT" % (len(strtab), strsize))
        # write symbols in the new order
        for i, (_old, s) in enumerate(order):
            struct.pack_into("<IBBHQ", m.data, symoff + i * 16,
                             s["strx"], s["type"], s["sect"], s["desc"], s["value"])
        for i in range(len(order), nsyms):
            struct.pack_into("<16s", m.data, symoff + i * 16, b"")
        m.data[stroff:stroff + strsize] = bytes(strsize)
        m.data[stroff:stroff + len(strtab)] = strtab
        struct.pack_into("<I", m.data, sym_cmd_off + 12, len(order))  # nsyms

        # LC_DYSYMTAB: no locals left; definitions first, imports after.
        for off, cmd, cmdsize in m.cmds:
            if cmd != LC_DYSYMTAB:
                continue
            n_ext, n_und = len(extdefs), len(undefs)
            struct.pack_into("<IIIIII", m.data, off + 8,
                             0, 0, 0, n_ext, n_ext, n_und)
            indirect_off, n_indirect = struct.unpack_from("<II", m.data, off + 56)
            for i in range(n_indirect):
                eo = indirect_off + i * 4
                val = struct.unpack_from("<I", m.data, eo)[0]
                if val & 0xC0000000:  # INDIRECT_SYMBOL_LOCAL / ABS
                    continue
                if val not in remap:
                    raise SystemExit("indirect symbol %d -> %d vanished" % (i, val))
                struct.pack_into("<I", m.data, eo, remap[val])

    if verbose:
        print("sections renamed: %d" % len(renamed_sections))
        for seg, old, new in renamed_sections:
            print("  %-10s %-16s -> %s" % (seg, old, new))
        print("symbols renamed : %d" % len(renamed_syms))
        for old, new in renamed_syms:
            print("  %-48s -> %s" % (old, new))
        print("symbols dropped : %d" % dropped)

    if check:
        return m

    m.write(out)
    import os
    os.chmod(out, 0o755)
    # arm64 will not exec a binary whose embedded signature is stale
    subprocess.run(["codesign", "--force", "--sign", "-", "--timestamp=none", out],
                   check=True, capture_output=True)
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", dest="out")
    ap.add_argument("--seed", required=True)
    ap.add_argument("--check", action="store_true", help="report only, write nothing")
    ap.add_argument("--keep-locals", action="store_true")
    a = ap.parse_args()
    if not a.check and not a.out:
        raise SystemExit("--out is required unless --check")
    harden(a.inp, a.out, a.seed, check=a.check, strip_locals=not a.keep_locals)


if __name__ == "__main__":
    main()
