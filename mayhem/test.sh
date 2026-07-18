#!/usr/bin/env bash
#
# radare2/mayhem/test.sh -- behavioral known-answer test (KAT) for the ia_fuzz integration.
#
# /mayhem/kat_asm (built by mayhem/build.sh from mayhem/harnesses/kat_asm.c) feeds THREE fixed,
# well-known x86 opcode byte sequences into radare2's own disassembler (r_asm_tostring(), the same
# asm/arch backend ia_fuzz exercises via `ia`/`oba`) and prints a line ONLY if all three COMPUTED
# mnemonics are correct:
#   0x90       -> must contain "nop"
#   0xc3       -> must contain "ret"
#   0x89 0xd8  -> must contain "mov"   (mov eax, ebx)
#
# This is a behavioral oracle, not a smoke test: it asserts a computed OUTPUT value, not just an
# exit code. A radare2 that's broken, or a fuzzed-program neuter (LD_PRELOAD _exit(0) before main())
# makes kat_asm print NOTHING -- we grep for the exact KAT_PASS line with the expected values, so
# both "crashed" and "silently did nothing" register as FAILED, not as a false pass.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x /mayhem/kat_asm ]; then
  echo "missing /mayhem/kat_asm -- run mayhem/build.sh first" >&2
  emit_ctrf "radare2-asm-kat" 0 1 0
  exit 1
fi

KAT_OUT="$(/mayhem/kat_asm 2>&1)"
RC=$?
echo "$KAT_OUT"

if [ "$RC" -eq 0 ] && printf '%s' "$KAT_OUT" | grep -qE "KAT_PASS nop='[^']*nop[^']*' ret='[^']*ret[^']*' mov='[^']*mov[^']*'"; then
  emit_ctrf "radare2-asm-kat" 1 0 0
else
  echo "KAT FAILED (kat_asm exit=$RC)" >&2
  emit_ctrf "radare2-asm-kat" 0 1 0
fi
