#!/usr/bin/env python3
"""
fake_symbols.py — 为 MIR 混淆后的 Mach-O 注入"伪函数符号"

背景: Polaris MIR 的函数切割把一个 C++ 函数拆成多个不连续代码块,
但 Mach-O 的函数边界由符号表决定, IDA 仍把它们折叠回原函数符号内
(函数数量不变)。本脚本扫描函数区间内的所有分支跳转目标 (切割块入口),
在符号表注入 `_<orig>_wbfakeNN` 伪符号, 使 IDA/otool/nm 看到的
函数数量显著增加 (切割块的静态可见性 ↑)。

布局重排: [exports_trie][func_starts][symtab(扩容)][strtab(扩容)][codesig(后移)]
__LINKEDIT segment 的 vmsize/filesize 相应扩容; 其余段内容零改动。
注入后需 ad-hoc 重签: codesign -f -s - <bin>

用法: python3 fake_symbols.py <macho> [--max N] [--prefix P]
  --max N    每个函数最多注入 N 个伪符号 (默认 128)
  --prefix P 伪符号名前缀 (默认 _wbfake)
"""
import struct
import subprocess
import re
import sys
import argparse

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_CODE_SIGNATURE = 0x1D
LC_DATA_IN_CODE = 0x29
LC_FUNCTION_STARTS = 0x26
N_SECT = 0x0E
N_EXT = 0x01


def parse_load_commands(data):
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = struct.unpack_from('<IIIIIIII', data, 0)
    cmds = []
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        c = {'off': off, 'cmd': cmd, 'cmdsize': cmdsize}
        if cmd == LC_SEGMENT_64:
            segname = data[off + 8:off + 24].rstrip(b'\0').decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, off + 24)
            c.update(segname=segname, vmaddr=vmaddr, vmsize=vmsize, fileoff=fileoff, filesize=filesize)
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from('<IIII', data, off + 8)
            c.update(symoff=symoff, nsyms=nsyms, stroff=stroff, strsize=strsize)
        elif cmd == LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from('<II', data, off + 8)
            c.update(dataoff=dataoff, datasize=datasize)
        elif cmd in (LC_FUNCTION_STARTS, LC_DATA_IN_CODE):
            dataoff, datasize = struct.unpack_from('<II', data, off + 8)
            c.update(dataoff=dataoff, datasize=datasize)
        cmds.append(c)
        off += cmdsize
    return cmds


def section_index_for_text(data, cmds):
    """返回 __TEXT,__text 的 section 序号 (1-based, 符号表 n_sect 用)"""
    idx = 0
    for c in cmds:
        if c['cmd'] != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from('<I', data, c['off'] + 64)[0]
        soff = c['off'] + 72
        for i in range(nsects):
            sect = data[soff + i * 80: soff + (i + 1) * 80]
            sectname = sect[0:16].rstrip(b'\0').decode()
            segname = sect[16:32].rstrip(b'\0').decode()
            idx += 1
            if segname == '__TEXT' and sectname == '__text':
                return idx
    return 1


def collect_branch_targets(data, funcs, max_addr, max_per_func):
    """反汇编函数区间, 收集所有块间跳转目标"""
    out = subprocess.run(['otool', '-tvV', '-l'], capture_output=True, text=True)
    return None  # placeholder (not used)


def collect_targets_via_otool(binary, symbol_ranges, max_per_func):
    """用 otool -tvV 反汇编, 按 symbol_ranges 收集跳转目标.
    symbol_ranges: list of (name, start_vmaddr, end_vmaddr)"""
    out = subprocess.run(['otool', '-tvV', binary], capture_output=True, text=True).stdout
    lines = out.splitlines()
    # 先把所有行解析为 (addr, text)
    parsed = []
    cur_label = None
    label_re = re.compile(r'^(_[A-Za-z0-9_$.]+):\s*$')
    hexline_re = re.compile(r'^([0-9a-f]{8,16})\t(.*)$')
    for ln in lines:
        m = label_re.match(ln.strip())
        if m:
            cur_label = m.group(1)
            continue
        m = hexline_re.match(ln)
        if m:
            parsed.append((int(m.group(1), 16), m.group(2)))

    results = []
    for (name, start, end) in symbol_ranges:
        targets = set()
        for addr, text in parsed:
            if addr < start or addr >= end:
                continue
            # 分支类指令的目标地址: 指令文本里最后一个 0x… 地址
            mnem = text.split('\t')[0].strip() if '\t' in text else text.strip()
            if not re.match(r'^(b|bl|br|cbz|cbnz|cbz|tbz|tbnz|ldr)\b', mnem) and 'b.' not in mnem:
                # arm64 分支助记词都含 b 开头或 b.cond
                if not re.match(r'^b', mnem):
                    continue
            m2 = re.findall(r'0x([0-9a-f]+)', text)
            for hx in m2:
                t = int(hx, 16)
                if start <= t < end and t != addr:
                    targets.add(t)
        results.append((name, start, end, sorted(targets)[:max_per_func]))
    return results


def uleb128(v):
    out = bytearray()
    while True:
        b = v & 0x7f
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def patch(binary, max_per_func=128, prefix='_wbfake', demote_originals=True):
    data = bytearray(open(binary, 'rb').read())
    cmds = parse_load_commands(bytes(data))

    symcmd = next(c for c in cmds if c['cmd'] == LC_SYMTAB)
    sigcmd = next(c for c in cmds if c['cmd'] == LC_CODE_SIGNATURE)
    fs_cmd = next((c for c in cmds if c['cmd'] == LC_FUNCTION_STARTS), None)
    linkedit = next(c for c in cmds if c['cmd'] == LC_SEGMENT_64 and c['segname'] == '__LINKEDIT')
    text_sect = section_index_for_text(bytes(data), cmds)

    symoff, nsyms, stroff, strsize = symcmd['symoff'], symcmd['nsyms'], symcmd['stroff'], symcmd['strsize']

    # --- 读符号表 ---
    syms = []
    for i in range(nsyms):
        n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', data, symoff + i * 16)
        s_end = stroff + n_strx
        name = data[s_end:data.index(b'\0', s_end)].decode()
        syms.append((name, n_type, n_sect, n_value))
    text_syms = [(n, v) for (n, t, s, v) in syms if (t & 0x0E) == N_SECT and n.startswith('_') and not n.startswith(prefix)]

    text_addr_sorted = sorted(set(v for (_, v) in text_syms))
    text_end = None
    for c in cmds:
        if c['cmd'] != LC_SEGMENT_64:
            continue
        nsects = struct.unpack_from('<I', data, c['off'] + 64)[0]
        soff = c['off'] + 72
        for i in range(nsects):
            sect = data[soff + i * 80: soff + (i + 1) * 80]
            if sect[16:32].rstrip(b'\0') == b'__TEXT' and sect[0:16].rstrip(b'\0') == b'__text':
                addr, size = struct.unpack_from('<QQ', sect, 32)
                text_end = addr + size
    assert text_end

    ranges = []
    for (name, v) in text_syms:
        nxt = min([a for a in text_addr_sorted if a > v] + [text_end])
        ranges.append((name, v, nxt))

    targets_per_func = collect_targets_via_otool(binary, ranges, max_per_func)
    total_new = sum(len(t) for (_, _, _, t) in targets_per_func)
    print(f'[+] 候选函数 {len(ranges)} 个, 伪符号总数 {total_new}')
    if total_new == 0:
        print('[!] 无可注入目标')
        return 1

    # ============ 新 linkedit 布局 ============
    # [linkedit_start .. fs_off) 原样 (exports trie 等)
    # [fs_off ..) 新 function_starts 数据
    # [new_symoff) symtab (旧 + 新)
    # [new_stroff) strtab (旧 + 新)
    # [new_sigoff) codesig
    fs_off = fs_cmd['dataoff'] if fs_cmd else symoff

    new_nsyms = nsyms + total_new
    new_symtab_size = new_nsyms * 16
    old_symtab_size = nsyms * 16

    # funcstarts 新数据: 原始函数地址 + 全部伪块地址, 升序, ULEB delta (基址 = __text addr? 
    # 实际上 function starts 的 base 是 __TEXT 段 vmaddr)
    text_vmaddr = None
    for c in cmds:
        if c['cmd'] == LC_SEGMENT_64 and c['segname'] == '__TEXT':
            text_vmaddr = c['vmaddr']
    all_starts = set()
    for (_, v) in text_syms:
        all_starts.add(v)
    for (_, _, _, ts) in targets_per_func:
        all_starts.update(ts)
    all_starts = sorted(all_starts)
    fs_data = bytearray()
    prev = text_vmaddr
    for a in all_starts:
        fs_data += uleb128(a - prev)
        prev = a
    fs_data += b'\0'
    # 4 字节对齐补齐
    while len(fs_data) % 4:
        fs_data += b'\0'
    print(f'[+] function_starts 重建: {len(all_starts)} 个函数地址, {len(fs_data)}B')

    # 符号条目
    new_entries = bytearray()
    new_strs = bytearray()
    off_in_str = strsize
    for (name, start, end, ts) in targets_per_func:
        for i, t in enumerate(ts):
            nm = f'{prefix}_{name.lstrip("_")}_{i}'
            new_entries += struct.pack('<IBBHQ', off_in_str, N_SECT | N_EXT, text_sect, 0, t)
            new_strs += nm.encode() + b'\0'
            off_in_str += len(nm) + 1
    new_strsize = strsize + len(new_strs)

    def align_up(x, a=4):
        return (x + a - 1) & ~(a - 1)

    new_fs_off = fs_off
    new_symoff = align_up(new_fs_off + len(fs_data), 8)
    new_stroff = align_up(new_symoff + new_symtab_size, 8)
    new_strtab_end = new_stroff + new_strsize
    new_sigoff = align_up(new_strtab_end, 16)

    old_end = sigcmd['dataoff'] + sigcmd['datasize']

    head = bytes(data[fs_cmd['off'] + 8: fs_cmd['off'] + 8 + 8])  # 保留 LC 头, 数据在 patch 里换

    new_blob = bytearray()
    new_blob += bytes(data[fs_off: new_fs_off])  # 空
    new_blob += fs_data
    pad1 = new_symoff - (new_fs_off + len(fs_data))
    new_blob += b'\0' * pad1
    new_blob += bytes(data[symoff: symoff + old_symtab_size])
    new_blob += new_entries
    pad2 = new_stroff - (new_symoff + new_symtab_size)
    new_blob += b'\0' * pad2
    new_blob += bytes(data[stroff: stroff + strsize])
    new_blob += new_strs
    pad3 = new_sigoff - new_strtab_end
    new_blob += b'\0' * pad3
    new_blob += bytes(data[sigcmd['dataoff']: sigcmd['dataoff'] + sigcmd['datasize']])
    new_blob += bytes(data[old_end:])  # codesig 之后的内容 (通常无)

    grow = (new_sigoff + sigcmd['datasize']) - old_end
    print(f'[+] linkedit 扩容 {grow:+d}B: fs@{hex(new_fs_off)} symtab@{hex(new_symoff)} strtab@{hex(new_stroff)} codesig@{hex(new_sigoff)}')

    data = bytearray(data[:fs_off]) + new_blob

    # 更新 LC
    # function starts
    struct.pack_into('<II', data, fs_cmd['off'] + 8, new_fs_off, len(fs_data))
    # symtab
    struct.pack_into('<IIII', data, symcmd['off'] + 8, new_symoff, new_nsyms, new_stroff, new_strsize)
    # codesig
    struct.pack_into('<II', data, sigcmd['off'] + 8, new_sigoff, sigcmd['datasize'])
    # data-in-code 指向旧 symtab 区域 → 已搬空, 置零
    for c in cmds:
        if c['cmd'] == LC_DATA_IN_CODE:
            struct.pack_into('<II', data, c['off'] + 8, new_fs_off, 0)
    # linkedit size
    le_off = linkedit['off']
    vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', data, le_off + 24)
    struct.pack_into('<QQQQ', data, le_off + 24, vmaddr, align_up(vmsize + grow, 0x4000), fileoff, filesize + grow)

    open(binary, 'wb').write(data)
    print(f'[+] 已写入: nsyms {nsyms} → {new_nsyms}, funcstarts {len(all_starts)} 项')
    return 0


def neutralize_function_boundaries(binary):
    """置零 __unwind_info + 清空 LC_FUNCTION_STARTS —
    IDA 优先用这两者划定函数边界, symtab 里的伪符号会被折叠进原函数.
    清空后 IDA 回退到 symtab 逐符号建函数 (无异常展开需求时运行时安全)."""
    import struct as _s
    data = bytearray(open(binary, 'rb').read())
    magic, ct, cs, ft, ncmds, soc, flags, res = _s.unpack_from('<IIIIIIII', data, 0)
    o = 32
    for _ in range(ncmds):
        cmd, cmdsize = _s.unpack_from('<II', data, o)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = _s.unpack_from('<I', data, o + 64)[0]
            s = o + 72
            for i in range(nsects):
                sect = data[s + i * 80: s + (i + 1) * 80]
                if sect[0:16].rstrip(b'\0') == b'__unwind_info':
                    addr, sz = _s.unpack_from('<QQ', sect, 32)
                    fo = _s.unpack_from('<I', sect, 48)[0]
                    data[fo:fo + sz] = b'\0' * sz
                    print(f'[+] __unwind_info zeroed ({sz}B)')
        o += cmdsize
    open(binary, 'wb').write(data)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binary')
    ap.add_argument('--max', type=int, default=128)
    ap.add_argument('--prefix', default='_wbfake')
    ap.add_argument('--keep-originals', action='store_true')
    args = ap.parse_args()
    rc = patch(args.binary, args.max, args.prefix, not args.keep_originals)
    if rc == 0:
        neutralize_function_boundaries(args.binary)
        print('[+] 完成. 请重签: codesign -f -s - ' + args.binary)
    sys.exit(rc)


if __name__ == '__main__':
    main()
