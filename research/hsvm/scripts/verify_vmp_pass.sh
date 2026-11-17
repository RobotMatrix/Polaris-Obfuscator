#!/usr/bin/env bash
# V-08 gate: the Polaris pass must lower HSV bytecode to native code, and must
# refuse bytecode it does not implement instead of miscompiling it.
#
# Runs against the rebuilt Polaris clang. Exits non-zero on any failure.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CLANG="$REPO/src/build/bin/clang"
WORK="${TMPDIR:-/tmp}/hsvm_pass_gate"
mkdir -p "$WORK"

fail=0
say() { printf '  %s\n' "$1"; }

if [ ! -x "$CLANG" ]; then
  echo "FAIL: $CLANG not built" >&2
  exit 2
fi

version="$("$CLANG" --version | head -1)"
say "clang: $version"

python3 - "$WORK" <<'PY'
import sys, os
work = sys.argv[1]

def ins(op, dst, a, b, imm):
    return bytes([op, dst, a, b]) + imm.to_bytes(4, 'little')

def emit(name, code, expect_hint):
    body = ",".join(str(b) for b in code)
    src = f'''
extern const unsigned char hsvm_bytecode[{len(code)}];
int hsvm_entry(void);
int main(void) {{ return hsvm_entry(); }}
const unsigned char hsvm_bytecode[{len(code)}] __attribute__((used)) = {{{body}}};
'''
    open(os.path.join(work, name + ".c"), "w").write(src)
    open(os.path.join(work, name + ".expect"), "w").write(expect_hint)

# movi r0,42 ; movi r1,7 ; add r0,r0,r1 ; halt  -> r0 = 49
emit("ok", ins(0x01,0,0,0,42) + ins(0x01,1,0,0,7) + ins(0x03,0,0,1,0) + ins(0x0f,0,0,0,0), "49")

# movi r0,5 ; ld r0,[r0+0] ; halt  -> memory opcode, must be refused
emit("refused", ins(0x01,0,0,0,5) + ins(0x0b,0,0,0,0) + ins(0x0f,0,0,0,0), "REFUSE")
PY

for name in ok refused; do
  hint="$(cat "$WORK/$name.expect")"
  if "$CLANG" -O1 -mllvm -passes=hsvm "$WORK/$name.c" -o "$WORK/$name.bin" 2>"$WORK/$name.err"; then
    if [ "$hint" = "REFUSE" ]; then
      say "FAIL: $name compiled, but this bytecode must be refused"
      fail=1
    else
      "$WORK/$name.bin"; rc=$?
      if [ "$rc" = "$hint" ]; then
        say "ok: $name returned $rc as expected"
      else
        say "FAIL: $name returned $rc, expected $hint"
        fail=1
      fi
    fi
  else
    if [ "$hint" = "REFUSE" ] && grep -q "not lowered yet" "$WORK/$name.err"; then
      say "ok: $name refused with a clear message"
    else
      say "FAIL: $name did not compile"
      sed -n '1,3p' "$WORK/$name.err" | sed 's/^/      /'
      fail=1
    fi
  fi
done

if [ "$fail" = "0" ]; then
  echo "PASS: hsvm pass gate"
else
  echo "FAIL: hsvm pass gate"
fi
exit "$fail"
