"""Mach-O symbol / structure extractor for arm64 binaries (stdlib only).

Prints, for one binary:
  * header + segment/section table (name, vmaddr, size, fileoff)
  * the symbol table (LC_SYMTAB nlist_64 entries): type, section, value, size
  * function starts (LC_FUNCTION_STARTS, ULEB128 deltas) -> sub_<addr> names for
    every address that has no symbol
  * exported symbols (LC_DYLD_INFO_ONLY / LC_DYLD_EXPORTS_TRIE trie)
  * imported symbols (bind opcodes), and the dylibs they come from
  * cstring contents worth grepping (short, printable, non-seeded)

Usage: python3 symbols.py <binary> [--json out.json]
"""
import argparse
import json
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_INFO_ONLY = 0x80000022
LC_FUNCTION_STARTS = 0x26
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_LOAD_DYLIB = 0xC
N_STAB, N_TYPE, N_SECT, N_EXT = 0xE0, 0x0E, 0x0F, 0x01

SECT_NAMES = {}


def uleb(buf, off):
    r = s = 0
    while True:
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return r, off


def parse(path):
    data = open(path, "rb").read()
    magic, cputype, cpusub, ftype, ncmds, sizeofcmds, flags, _ = struct.unpack_from("<IiiIIIII", data, 0)
    if magic != MH_MAGIC_64:
        raise SystemExit("not a 64-bit little-endian Mach-O")
    hdr = dict(magic=hex(magic), cputype=cputype, cpusubtype=cpusub, filetype=ftype,
               ncmds=ncmds, sizeofcmds=sizeofcmds, flags=hex(flags), size=len(data))
    segs, sects = [], []
    symoff = nsyms = stroff = strsize = None
    fnstarts = None
    dyld_info = None
    exports_off = None
    dylibs = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].rstrip(b"\0").decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            segs.append(dict(name=name, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize))
            base = off + 72
            for i in range(nsects):
                s = data[base + i * 80: base + (i + 1) * 80]
                sn = s[:16].rstrip(b"\0").decode()
                segn = s[16:32].rstrip(b"\0").decode()
                addr, size = struct.unpack_from("<QQ", s, 32)
                offset = struct.unpack_from("<I", s, 48)[0]
                sects.append(dict(seg=segn, sect=sn, addr=addr, size=size, offset=offset))
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, off + 8)
        elif cmd == LC_FUNCTION_STARTS:
            fnstarts = struct.unpack_from("<II", data, off + 8)
        elif cmd == LC_DYLD_INFO_ONLY:
            (rebase_off, rebase_size, bind_off, bind_size, weak_off, weak_size,
             lazy_off, lazy_size, export_off, export_size) = struct.unpack_from("<10I", data, off + 8)
            dyld_info = dict(rebase=(rebase_off, rebase_size), bind=(bind_off, bind_size),
                             weak=(weak_off, weak_size), lazy=(lazy_off, lazy_size),
                             export=(export_off, export_size))
        elif cmd == LC_DYLD_EXPORTS_TRIE:
            exports_off = struct.unpack_from("<II", data, off + 8)
        elif cmd == LC_LOAD_DYLIB:
            noff = struct.unpack_from("<I", data, off + 8)[0]
            dylibs.append(data[off + noff:off + cmdsize].rstrip(b"\0").decode())
        off += cmdsize

    for i, s in enumerate(sects, 1):
        SECT_NAMES[i] = f"{s['seg']},{s['sect']}"

    # ---- symbols
    strtab = data[stroff:stroff + strsize]
    syms = []
    for i in range(nsyms):
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from("<IBBHQ", data, symoff + i * 16)
        name = strtab[n_strx:strtab.find(b"\0", n_strx)].decode(errors="replace")
        if n_type & N_STAB:
            kind = "STAB"
        elif n_type & N_TYPE == 0x0:
            kind = "UNDEF"
        elif n_type & N_TYPE == 0xE:
            kind = "SECT"
        else:
            kind = "TYPE%d" % (n_type & N_TYPE)
        syms.append(dict(name=name, kind=kind, ext=bool(n_type & N_EXT), sect=n_sect,
                         sect_name=SECT_NAMES.get(n_sect, "-"), value=n_value, desc=n_desc))

    # size = distance to the next symbol in the same section (last one: section end)
    by_sect = {}
    for s in syms:
        if s["kind"] == "SECT":
            by_sect.setdefault(s["sect"], []).append(s)
    for sec, lst in by_sect.items():
        lst.sort(key=lambda s: s["value"])
        end = None
        for s in sects:
            if SECT_NAMES.get(sec) == f"{s['seg']},{s['sect']}":
                end = s["addr"] + s["size"]
        for i, s in enumerate(lst):
            s["size"] = (lst[i + 1]["value"] if i + 1 < len(lst) else end) - s["value"]

    # ---- function starts
    starts = []
    if fnstarts:
        o, size = fnstarts
        base = None
        addr = 0
        p = o
        while p < o + size:
            d, p = uleb(data, p)
            if d == 0:
                break
            addr += d
            starts.append(addr)
        # the deltas are relative to the __TEXT segment, not to __text
        textseg = [s for s in segs if s["name"] == "__TEXT"]
        base = textseg[0]["vmaddr"] if textseg else 0
        starts = [base + a for a in starts]

    # ---- exports trie
    exports = []

    def walk(buf, node_off, prefix, depth=0):
        # This build's trie uses NUL-terminated labels (checked against the
        # observed byte layout, not assumed from the header docs).
        if depth > 24 or node_off >= len(buf):
            return
        p = node_off
        terminal_size, p = uleb(buf, p)
        info_end = p + terminal_size
        if terminal_size:
            q = p
            flags, q = uleb(buf, q)
            if flags & 0x08:
                exports.append(dict(name=prefix, flags=flags, address=0, reexport=True))
            else:
                addr, q = uleb(buf, q)
                exports.append(dict(name=prefix, flags=flags, address=addr))
        p = info_end
        if p >= len(buf):
            return
        nchild, p = uleb(buf, p)
        for _ in range(nchild):
            if p >= len(buf):
                return
            z = buf.find(b"\0", p)
            if z < 0:
                return
            label = buf[p:z].decode(errors="replace")
            p = z + 1
            child, p = uleb(buf, p)
            # child offsets in this trie are absolute (tested: they point backwards)
            walk(buf, child, prefix + label, depth + 1)

    if dyld_info and dyld_info["export"][1]:
        eo, es = dyld_info["export"]
        walk(data[eo:eo + es], 0, "")
    elif exports_off and exports_off[1]:
        eo, es = exports_off
        walk(data[eo:eo + es], 0, "")

    # ---- bind opcodes -> imported symbols
    imports = []

    def bind_scan(buf):
        p = 0
        seg_idx = 0
        while p < len(buf):
            op = buf[p] & 0xF0
            imm = buf[p] & 0x0F
            p += 1
            if op == 0x70:                        # BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
                continue
            elif op == 0x10:                      # SET_DYLIB_SPECIAL_IMM
                continue
            elif op == 0x40:                      # SET_SYMBOL_TRAILING_FLAGS_IMM
                s = bytes(buf[p:buf.find(b"\0", p)])
                p += len(s) + 1
                imports.append(s.decode(errors="replace"))
            elif op == 0x90:                      # DONE
                break
            elif op == 0xC0:                      # ADD_ADDR_IMM_SCALED
                continue
            elif op == 0x80:                      # SET_TYPE_IMM etc
                continue
            elif op == 0x30:                      # SET_TYPE_IMM
                continue
            elif op == 0x60:                      # SET_SEGMENT_AND_OFFSET_ULEB
                _, p = uleb(buf, p)
            elif op in (0x20, 0x50, 0xE0, 0xB0):
                _, p = uleb(buf, p)
            elif op == 0x00:                      # DONE
                break
            elif op == 0xD0:
                continue
            elif op == 0xA0:
                continue
            elif op == 0xF0:
                continue
            else:
                continue

    if dyld_info:
        for key in ("bind", "lazy", "weak"):
            o, s = dyld_info[key]
            if s:
                bind_scan(data[o:o + s])

    # ---- cstrings
    strings = []
    for s in sects:
        if s["sect"] in ("__cstring", "__const"):
            blob = data[s["offset"]:s["offset"] + s["size"]]
            cur = b""
            for b in blob:
                if 32 <= b < 127:
                    cur += bytes([b])
                else:
                    if len(cur) >= 4:
                        strings.append(cur.decode())
                    cur = b""
    return dict(header=hdr, segments=segs, sections=sects, symbols=syms,
                function_starts=starts, exports=exports, imports=imports,
                dylibs=dylibs, strings=strings)


def report(b, path):
    h = b["header"]
    print(f"file      {path}")
    print(f"size      {h['size']:,} bytes   filetype {h['filetype']}   flags {h['flags']}")
    print()
    print("segments")
    for s in b["segments"]:
        print(f"  {s['name']:12s} vmaddr {s['vmaddr']:#014x} vmsize {s['vmsize']:#012x} "
              f"fileoff {s['fileoff']:>8} filesize {s['filesize']:>9}")
    print()
    print("sections")
    for s in b["sections"]:
        print(f"  {s['seg']},{s['sect']:<16s} addr {s['addr']:#014x} size {s['size']:#012x} offset {s['offset']}")
    print()
    defined = [s for s in b["symbols"] if s["kind"] != "UNDEF"]
    undef = [s for s in b["symbols"] if s["kind"] == "UNDEF"]
    print(f"symbol table: {len(b['symbols'])} entries ({len(defined)} defined, {len(undef)} undefined)")
    for s in sorted(defined, key=lambda s: s["value"]):
        size = s.get("size")
        print(f"  {s['value']:#014x} {'T' if s['sect_name'].endswith('__text') else 'S'} "
              f"{s['name']:<40s} {s['sect_name']:<20s} size {size if size is not None else '?'}")
    print()
    print("imports (undefined nlist entries, dylib ordinal in n_desc>>8)")
    for s in sorted(undef, key=lambda s: s["name"]):
        print(f"  {s['name']:<28s} ordinal {s['desc'] >> 8}")
    print("dylibs")
    for d in b["dylibs"]:
        print(f"  {d}")
    print()
    named = {s["value"] for s in defined}
    extra = [a for a in b["function_starts"] if a not in named]
    print(f"function starts: {len(b['function_starts'])} total, {len(extra)} without a symbol")
    for a in extra:
        print(f"  sub_{a:x}")
    print()
    if b["exports"]:
        print("exports")
        for e in b["exports"]:
            print(f"  {e['name']} flags {e['flags']:#x} addr {e['address']:#x}")
        print()
    print("strings")
    for s in b["strings"][:40]:
        print(f"  {s!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--json")
    a = ap.parse_args()
    b = parse(a.binary)
    report(b, a.binary)
    if a.json:
        open(a.json, "w").write(json.dumps(b, indent=1))


if __name__ == "__main__":
    main()
