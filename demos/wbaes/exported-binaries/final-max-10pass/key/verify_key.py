#!/usr/bin/env python3
# verify_key.py — 从 wbaes_key.h 重组 AES-128 密钥并用 OpenSSL 验证测试向量
# 用法: python3 verify_key.py [wbaes_key.h 路径]
import re, subprocess, sys

path = sys.argv[1] if len(sys.argv) > 1 else 'wbaes_key.h'
src = open(path).read()

def blk(name):
    out = []
    for i in range(4):
        m = re.search(r'%s%d\[64\] = \{(.*?)\};' % (name, i), src, re.S)
        out.append([int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1))])
    return out

KBLK = blk('KBLK')
CBLK = blk('CBLK')
KOFF = [24, 6, 9, 25]
COFF = [4, 51, 41, 58]

# 密钥字节 i: KBLK[i>>2][KOFF[i>>2] + (i&3)] ^ CBLK[i>>2][COFF[i>>2] + (i&3)]
key = bytearray(16)
for s in range(4):
    for b in range(4):
        key[s*4 + b] = KBLK[s][KOFF[s] + b] ^ CBLK[s][COFF[s] + b]

key_hex = key.hex()
print("AES-128 key:", key_hex)

# 测试向量 (来自 wbaes_key.h 尾部)
pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
expect_ct = 'de23992aa3c7427f3ad40fda83730d07'
r = subprocess.run(['openssl', 'enc', '-aes-128-ecb', '-K', key_hex, '-nopad'],
                   input=pt, capture_output=True)
ct = r.stdout.hex()
print("AES-128-ECB(pt) =", ct)
print("expected ct     =", expect_ct)
ok = ct == expect_ct
print("MATCH:", ok)
sys.exit(0 if ok else 1)
