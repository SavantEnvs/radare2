#!/usr/bin/env bash
#
# radare2/mayhem/test.sh -- behavioral known-answer test (KAT) for the fuzz_dwarf integration.
#
# /mayhem/kat_dwarf (built by mayhem/build.sh from mayhem/harnesses/kat_dwarf.c) parses a known ELF
# object (the committed seed kat.elf) with radare2's DWARF parser -- the code fuzz_dwarf exercises --
# and prints a KAT_PASS line ONLY if the COMPUTED values are right: one compile unit whose
# DW_AT_producer decodes to "mayhem-kat" and DW_AT_name to "kat.c" (DW_FORM_strp into .debug_str).
# A broken parser, or a fuzzed-program neuter (LD_PRELOAD _exit(0) before main()) makes kat_dwarf
# print NOTHING; we grep for the exact KAT_PASS line, so both "crashed" and "silently did nothing"
# register as FAILED, not as a false pass.
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

if [ ! -x /mayhem/kat_dwarf ]; then
  echo "missing /mayhem/kat_dwarf -- run mayhem/build.sh first" >&2
  emit_ctrf "radare2-dwarf-kat" 0 1 0
  exit 1
fi

KAT_OUT="$(/mayhem/kat_dwarf mayhem/fuzz_dwarf-mined-2e24d9e/testsuite/kat.elf 2>&1)"
RC=$?
echo "$KAT_OUT"

if [ "$RC" -eq 0 ] && printf '%s' "$KAT_OUT" | grep -qxF "KAT_PASS units=1 tag=compile_unit producer='mayhem-kat' name='kat.c'"; then
  emit_ctrf "radare2-dwarf-kat" 1 0 0
else
  echo "KAT FAILED (kat_dwarf exit=$RC)" >&2
  emit_ctrf "radare2-dwarf-kat" 0 1 0
fi
