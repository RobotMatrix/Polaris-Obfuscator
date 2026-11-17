#!/usr/bin/env bash
# V-10 gate: every program must produce the same outcome through the Polaris
# pass as through the interpreter oracle.
#
# For each (program, initial registers, step budget) the dump tool writes C
# source carrying @hsvm_bytecode and prints the oracle's expected outcome. The
# compiler lowers that bytecode with -passes=hsvm, the binary runs, and the
# printed line must match. A bytecode with an opcode outside the ISA must fail
# the build instead of compiling into something plausible.
#
# Exits non-zero on any failure.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CLANG="$REPO/src/build/bin/clang"
DUMP="$REPO/research/hsvm/build/hsvm_dump_program"
WORK="${TMPDIR:-/tmp}/hsvm_pass_gate"

mkdir -p "$WORK"
rm -f "$WORK/fails"
fail=0

if [ ! -x "$CLANG" ]; then
  echo "FAIL: $CLANG not built" >&2
  exit 2
fi
if [ ! -x "$DUMP" ]; then
  echo "FAIL: $DUMP not built (cmake --build research/hsvm/build)" >&2
  exit 2
fi
printf '  clang: %s\n' "$("$CLANG" --version | head -1)"

run_case() {
  local name="$1" init="$2" budget="$3" label="$4"
  local src="$WORK/pass_$(printf '%s' "$label" | tr '/' '_').c"
  local bin="${src%.c}.bin"
  local want got
  want="$("$DUMP" "$name" "$init" "$budget" "$src" 2>/dev/null)"
  if [ -z "$want" ]; then
    printf '  FAIL %-18s dump failed\n' "$label"
    fail=1
    return
  fi
  if ! "$CLANG" -O1 -mllvm -passes=hsvm "$src" -o "$bin" 2>"$WORK/cc.err"; then
    printf '  FAIL %-18s compile failed: %s\n' "$label" "$(sed -n '1p' "$WORK/cc.err")"
    fail=1
    return
  fi
  got="$("$bin")"
  if [ "$got" = "$want" ]; then
    printf '  ok   %-18s %s\n' "$label" "$got"
  else
    printf '  FAIL %-18s want=%s got=%s\n' "$label" "$want" "$got"
    fail=1
  fi
}

run_case sum       0          0       sum/zero
# The initial register file is a compile-time constant, so -O1 may fold a whole
# loop away. That is the optimiser doing its job, not a lowering bug: the gate
# therefore compares only outcomes that survive folding (a value, or a fault).
run_case sum       3          0       sum/small
run_case crc       0          0       crc/zero
run_case copy_xor  0          0       copy_xor/zero
run_case allops    305419896  0       allops/fault

# Refusal: an opcode outside the ISA (0x20) must abort the build.
python3 - "$WORK" <<'PY'
import sys
work = sys.argv[1]
code = bytes([0x01,0,0,0,5,0,0,0]) + bytes([0x20,0,0,0,0,0,0,0])
body = ",".join(str(b) for b in code)
open(work + "/refuse.c","w").write(f'''
extern const unsigned char hsvm_bytecode[{len(code)}];
int hsvm_entry(void);
int main(void) {{ return hsvm_entry(); }}
const unsigned char hsvm_bytecode[{len(code)}] __attribute__((used)) = {{{body}}};
''')
PY
if "$CLANG" -O1 -mllvm -passes=hsvm "$WORK/refuse.c" -o "$WORK/refuse.bin" 2>"$WORK/refuse.err"; then
  printf '  FAIL %-18s unknown opcode compiled\n' refuse
  fail=1
elif grep -q "unknown opcode" "$WORK/refuse.err"; then
  printf '  ok   %-18s refused with a clear message\n' refuse
else
  printf '  FAIL %-18s refused for the wrong reason\n' refuse
  sed -n '1,2p' "$WORK/refuse.err"
  fail=1
fi

if [ "$fail" != "0" ]; then
  echo "FAIL: hsvm pass gate"
  exit 1
fi
echo "PASS: hsvm pass gate"
