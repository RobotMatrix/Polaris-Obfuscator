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
  * LC_DYLD_EXPORTS_TRIE — a *second*, independent copy of the defined names
    that ld64 writes into __LINKEDIT.  This is the one that survived the first
    version of this tool: LC_SYMTAB was rewritten, the trie was not, so
    `nm -a` showed seeded names while dyld's export trie still spelled out
    __ZN5WBAES8enc_coreERK11WBAESTablesS2_PKhPh, _hsvm_entry, _hy_vm_plan ...
    Pairing the trie's addresses with the renamed sections put the reader back
    exactly where they started.  A main executable needs no exports at run
    time (LC_MAIN gives the entry point), so the trie is now rewritten as the
    minimal empty trie and the bytes it used to occupy are zeroed.

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
  5. LC_DYLD_EXPORTS_TRIE is rewritten as the minimal empty trie (2 bytes) and
     the region it used to occupy is zeroed; a main executable does not need
     exports, and dyld keeps loading it (see --exports for the alternative)
  6. the file is re-signed ad-hoc (arm64 refuses to exec an invalid signature)

Undefined imports (`_printf`, `_arc4random`, ...) keep their names: they are
libc, they name nothing about this program, and `nm -u` on any binary shows them.

Usage:
    python3 macho_scrub.py --in a.out --out b.out --seed build-2026-11-18
    python3 macho_scrub.py --in a.out --check --seed s     # report only
    python3 macho_scrub.py --in a.out --out b.out --seed s --exports zero
"""
import argparse
import hashlib
import re
import struct
import subprocess
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_CODE_SIGNATURE = 0x1D
LC_DYSYMTAB = 0xB
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033

MH_EXECUTE = 0x2

# An empty export trie is two zero bytes: root node, terminal_size=0,
# child_count=0. dyld walks it, finds no exports, and moves on.
EMPTY_TRIE = b"\x00\x00"

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


def uleb(buf, off):
    """Unsigned LEB128 -> (value, next_offset)."""
    result = shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, off


def parse_export_trie(buf):
    """Walk a dyld export trie; return [{name, flags, address}].

    Layout (dyld source, `MachOFile::forEachExportTrieEntry`): each node is a
    ULEB terminal_size, terminal_size bytes of terminal info, a ULEB child
    count, then per child a NUL-terminated label and a ULEB child node offset
    *relative to the start of the trie*.  A terminal's info is flags, then the
    address (ULEB) unless EXPORT_SYMBOL_FLAGS_REEXPORT / STUB_AND_RESOLVER.
    """
    out = []

    def walk(node_off, prefix, depth=0):
        if depth > 32 or node_off >= len(buf):
            return
        terminal_size, p = uleb(buf, node_off)
        info_end = p + terminal_size
        if terminal_size:
            flags, q = uleb(buf, p)
            address = 0
            if flags & 0x08:  # REEXPORT: no address, the name is all we want
                pass
            elif flags & 0x10:  # STUB_AND_RESOLVER: address, then resolver
                address, _ = uleb(buf, q)
            else:
                address, _ = uleb(buf, q)
            out.append({"name": prefix, "flags": flags, "address": address})
        p = info_end
        if p >= len(buf):
            return
        nchild, p = uleb(buf, p)
        for _ in range(nchild):
            z = buf.find(b"\0", p)
            if z < 0:
                return
            label = buf[p:z].decode("utf-8", "replace")
            p = z + 1
            child, p = uleb(buf, p)
            walk(child, prefix + label, depth + 1)

    try:
        walk(0, "")
    except (IndexError, ValueError):
        pass
    return out


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
        self.filetype = filetype
        self.ncmds = ncmds
        self.cmds = []  # (offset_of_cmd, cmd, cmdsize)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.data, off)
            self.cmds.append((off, cmd, cmdsize))
            off += cmdsize

    def export_ranges(self):
        """[(cmd_offset, cmd, dataoffset_field_offset, datasize_field_offset)]"""
        out = []
        for off, cmd, cmdsize in self.cmds:
            if cmd == LC_DYLD_EXPORTS_TRIE:
                out.append((off, cmd, off + 8, off + 12))
            elif cmd == LC_DYLD_INFO_ONLY and cmdsize >= 48:
                # export_off / export_size are fields 9 and 10 of the struct
                out.append((off, cmd, off + 40, off + 44))
        return out

    def exports(self):
        """Every name in every export trie in the file, with its address."""
        out = []
        for _off, _cmd, doff, dsz in self.export_ranges():
            start, size = struct.unpack_from("<II", self.data, doff)
            if not size or not start:
                continue
            for e in parse_export_trie(bytes(self.data[start:start + size])):
                e = dict(e)
                e["cmd"] = _cmd
                e["dataoffset"] = start
                e["datasize"] = size
                out.append(e)
        return out

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


def scrub_exports(m, seed, mode="empty", verbose=True):
    """Remove the original names from every dyld export trie.

    mode="empty"  rewrite the trie as the minimal empty trie (root node, no
                  terminal, no children) and zero the bytes it used to occupy.
                  The load command stays, so the file structure is unchanged
                  apart from the datasize field.  This is what an attacker
                  reads with `dyld_info -exports` / `otool -Iv`.
    mode="zero"   set dataoffset/datasize to 0 and zero the old region; dyld
                  treats a zero-size trie as "no exports".
    mode="keep"   leave the trie alone (only valid for something that really
                  needs its exports, i.e. a dylib).

    Nothing here can change behaviour of a main executable: the entry point is
    LC_MAIN, exports are not consulted at load time, and the code and the table
    bytes are untouched.
    """
    names = m.exports()
    info = {"mode": mode, "entries_before": len(names),
            "names_before": [e["name"] for e in names],
            "tries": [], "bytes_before": 0, "bytes_after": 0}

    if mode == "keep":
        return info
    if m.filetype != MH_EXECUTE:
        raise SystemExit("refusing to drop exports on a non-executable "
                         "(filetype %d): a dylib's exports are its ABI, use "
                         "--exports keep" % m.filetype)

    for off, cmd, doff, dsz in m.export_ranges():
        start, size = struct.unpack_from("<II", m.data, doff)
        if not size or not start:
            continue
        info["bytes_before"] += size
        if mode == "empty":
            assert size >= len(EMPTY_TRIE)
            m.data[start:start + size] = EMPTY_TRIE.ljust(size, b"\0")
            struct.pack_into("<I", m.data, dsz, len(EMPTY_TRIE))
            info["bytes_after"] += len(EMPTY_TRIE)
        elif mode == "zero":
            m.data[start:start + size] = bytes(size)
            struct.pack_into("<II", m.data, doff, 0, 0)
            info["bytes_after"] += 0
        else:
            raise SystemExit("unknown --exports mode %r" % mode)
        info["tries"].append({"cmd": hex(cmd), "dataoffset": start,
                              "datasize_before": size,
                              "datasize_after": len(EMPTY_TRIE) if mode == "empty" else 0})

    if verbose and info["entries_before"]:
        print("exports removed : %d name(s), %d B trie -> %d B"
              % (len(names), info["bytes_before"], info["bytes_after"]))
        for e in names:
            print("  %-56s flags %#x addr %#x" % (e["name"], e["flags"], e["address"]))
    return info


def harden(inp, out, seed, check=False, strip_locals=True, keep_undef=True, verbose=True,
           exports="empty"):
    m = MachO(inp)
    renamed_sections = []
    for segname, sectname, so in m.sections():
        if sectname in STOCK or not sectname:
            continue
        new = "__" + seeded_name(seed, "sect", sectname)
        assert len(new) <= 16
        m.data[so:so + 16] = new.encode().ljust(16, b"\0")
        renamed_sections.append((segname, sectname, new))

    trie = scrub_exports(m, seed, mode=exports, verbose=verbose)

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

    # Post-condition: no original name may survive in *either* name table. This
    # is the check the first version of this tool did not have, which is why a
    # renamed LC_SYMTAB and an untouched export trie both shipped.
    leftover = [e["name"] for e in m.exports()]
    if exports != "keep" and leftover:
        raise SystemExit("export trie still carries %d name(s): %s"
                         % (len(leftover), ", ".join(leftover[:8])))
    tells = re.compile(rb"WBAES|hsvm|hy_vm|wbaes|hytab|_ZN|_ZNK", re.I)
    tab = m.symtab()
    if tab is not None:
        _o, _symoff, _n, stroff, strsize = tab
        hit = tells.findall(bytes(m.data[stroff:stroff + strsize]))
        if hit:
            raise SystemExit("string table still carries %r" % hit[:8])

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
    ap.add_argument("--exports", choices=("empty", "zero", "keep"), default="empty",
                    help="what to do with LC_DYLD_EXPORTS_TRIE: empty trie (default), "
                         "zero-size command, or keep (dylibs)")
    a = ap.parse_args()
    if not a.check and not a.out:
        raise SystemExit("--out is required unless --check")
    harden(a.inp, a.out, a.seed, check=a.check, strip_locals=not a.keep_locals,
           exports=a.exports)


if __name__ == "__main__":
    main()
