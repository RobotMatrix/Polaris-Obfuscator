#!/usr/bin/env bash
# Pass fuzz gate: random bytecode, compiled through the Polaris pass, must match
# the interpreter's outcome program by program.
#
# The three-engine property test already covers interpreter/oracle/lowering. This
# one adds the real compiler: for each random program the oracle outcome is
# written next to the C source, the pass compiles it, and the binary's output must
# equal that file. Programs whose oracle run hit the step cap are skipped: the
# native form has no step budget, so it would loop forever.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CLANG="$REPO/src/build/bin/clang"
FUZZ="$REPO/research/hsvm/build/hsvm_fuzz"
WORK="${TMPDIR:-/tmp}/hsvm_pass_fuzz"
COUNT="${1:-20}"
SEED="${2:-424242}"

rm -rf "$WORK"
mkdir -p "$WORK"

if [ ! -x "$CLANG" ]; then echo "FAIL: $CLANG not built" >&2; exit 2; fi
if [ ! -x "$FUZZ" ]; then echo "FAIL: $FUZZ not built" >&2; exit 2; fi

printf '  clang: %s\n' "$("$CLANG" --version | head -1)"

# Generate and check the three-engine property first; a divergence here means the
# programs themselves are not trustworthy comparisons for the pass.
if ! "$FUZZ" --seed "$SEED" --count "$COUNT" --emit-dir "$WORK" > "$WORK/property.log" 2>&1; then
  printf '  FAIL property test diverged (see %s)\n' "$WORK/property.log"
  tail -3 "$WORK/property.log" | sed 's/^/      /'
  exit 1
fi
printf '  ok   property: %s\n' "$(tail -1 "$WORK/property.log")"

fail=0
checked=0
skipped=0
for src in "$WORK"/prog_*.c; do
  [ -e "$src" ] || continue
  stem="${src%.c}"
  want="$(cat "$stem.expect" 2>/dev/null)"
  if [ "$want" = "budget" ]; then
    skipped=$((skipped + 1))
    continue
  fi
  if ! "$CLANG" -O1 -mllvm -passes=hsvm "$src" -o "$stem.bin" 2>"$stem.err"; then
    printf '  FAIL %s: compile failed: %s\n' "$(basename "$stem")" "$(sed -n '1p' "$stem.err")"
    fail=1
    continue
  fi
  got="$(timeout 10 "$stem.bin" 2>/dev/null)"
  checked=$((checked + 1))
  if [ "$got" != "$want" ]; then
    printf '  FAIL %s: want=%s got=%s\n' "$(basename "$stem")" "$want" "$got"
    fail=1
  fi
done

printf '  compiled=%d skipped(budget)=%d\n' "$checked" "$skipped"
if [ "$fail" != "0" ]; then
  echo "FAIL: pass fuzz gate"
  exit 1
fi
if [ "$checked" = "0" ]; then
  echo "FAIL: pass fuzz gate (no program compiled, nothing was tested)"
  exit 1
fi
echo "PASS: pass fuzz gate"
