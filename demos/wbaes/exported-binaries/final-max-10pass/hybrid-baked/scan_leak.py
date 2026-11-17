#!/usr/bin/env python3
# scan_leak.py — 扫描 BAKED 二进制是否泄露密钥材料。只打印命中计数, 不打印密钥。
# 用法: python3 -I scan_leak.py <binary> <wbaes_key.h>
import re, sys

bin_path, key_path = sys.argv[1], sys.argv[2]
data = open(bin_path, 'rb').read()
src = open(key_path).read()

def blk(name):
    out = []
    for i in range(4):
        m = re.search(r'%s%d\[64\] = \{(.*?)\};' % (name, i), src, re.S)
        out.append([int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1))])
    return out

KBLK, CBLK = blk('KBLK'), blk('CBLK')
KOFF, COFF = [24, 6, 9, 25], [4, 51, 41, 58]
key = bytearray(16)
for s in range(4):
    for b in range(4):
        key[s*4 + b] = KBLK[s][KOFF[s] + b] ^ CBLK[s][COFF[s] + b]

# 轮密钥扩展 (FIPS-197)
xt = lambda x: ((x << 1) ^ 0x1b) & 0xff if x & 0x80 else (x << 1)
gm = lambda a, b: (lambda p: p)(__import__('functools').reduce(
    lambda p, _: (p[0] ^ (p[2] & 1 and p[1] or 0), xt(p[1]), p[2] >> 1), range(8), (0, a, b))[0])
SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bd'
    'be0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae'
    '08aa782528610cb5aae27bd3ea63a4f0c0b5aa52866be7b9ba5b1deb852e1f5'
    '6bf6ab57e5ba3ab955d6a67a0f65c926dab6a86b6fa6baeba6c9f6f7baeb6ee'
    'badb7e6bbaf6bb6eb96b7abebc6cbaebf6bb76fbaeb7ab7b5e8b9aeb9b6bba'.replace(' ','')) if False else None

def sbox_byte(x):
    # 仿射+求逆标准实现
    def ginv(v):
        if v == 0: return 0
        for y in range(1, 256):
            if gm(v, y) == 1: return y
        return 0
    b = ginv(x)
    r = 0
    for i in range(8):
        bit = ((b >> i) ^ (b >> ((i+4) % 8)) ^ (b >> ((i+5) % 8)) ^
               (b >> ((i+6) % 8)) ^ (b >> ((i+7) % 8)) ^ (0x63 >> i)) & 1
        r |= bit << i
    return r

rk = [bytes(key)]
for r in range(1, 11):
    p = rk[-1]
    t = [p[13], p[14], p[15], p[12]]
    rc = 1
    for _ in range(r - 1): rc = xt(rc)
    t = [sbox_byte(t[0]) ^ rc, sbox_byte(t[1]), sbox_byte(t[2]), sbox_byte(t[3])]
    n = bytearray(16)
    for i in range(16):
        prev = n[i - 4] if i >= 4 else t[i]
        n[i] = prev ^ p[i]
    rk.append(bytes(n))

# --- 自检: 用推导出的轮密钥加密 test_pt, 必须得到 test_ct ---
def xtime(v): return xt(v)
def aes_enc(pt, rks):
    def sr(s):
        o = bytearray(16)
        for d in range(16):
            row, col = d & 3, d >> 2
            o[d] = s[row + 4 * ((col + row) & 3)]
        return o
    s = bytes(a ^ b for a, b in zip(pt, rks[0]))
    for r in range(1, 10):
        s = bytes(sbox_byte(x) for x in s)
        s = sr(s)
        o = bytearray(16)
        M = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
        for c in range(4):
            for row in range(4):
                a = 0
                for k in range(4):
                    x, m = s[k + 4*c], M[row][k]
                    p = 0
                    for _ in range(8):
                        if m & 1: p ^= x
                        x = xtime(x); m >>= 1
                    a ^= p
                o[row + 4*c] = a
        s = bytes(a ^ b for a, b in zip(o, rks[r]))
    s = sr(bytes(sbox_byte(x) for x in s))
    return bytes(a ^ b for a, b in zip(s, rks[10]))

pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
ct_ref = bytes.fromhex('de23992aa3c7427f3ad40fda83730d07')
if aes_enc(pt, rk) != ct_ref:
    print("SELF-CHECK FAIL: 轮密钥推导错误")
    sys.exit(2)
print("  self-check: rk-expansion OK (matches test vector)")

hits = []
for r, k in enumerate(rk):
    if data.find(k) != -1: hits.append(('roundkey', r))
for i, kb in enumerate(key):
    # 单字节命中无意义 (69MB 随机数据必然含全部 256 字节), 只查 key 首尾 4B 序列
    pass
if data.find(bytes(key[:4])) != -1: hits.append(('key[0:4]', 0))
if data.find(bytes(key[12:])) != -1: hits.append(('key[12:16]', 0))
if data.find(bytes(key)) != -1: hits.append(('fullkey', 0))
# 标准 AES Sbox 前 16 字节指纹
sb16 = bytes(sbox_byte(x) for x in range(16))
if data.find(sb16) != -1: hits.append(('sbox16', 0))
# 测试向量明文/密文 (非密钥, 但确认测试向量在 — 供参考)
print("scan:", bin_path)
print("  hits:", hits if hits else "NONE")
print("  result:", "LEAK" if hits else "CLEAN")
sys.exit(1 if hits else 0)
