#!/usr/bin/env bash
#
# radare2/mayhem/build.sh (mining layer on BASE 558a787) -- build radare2's libr as a sanitized static
# library and link upstream's libFuzzer harness test/fuzz/fuzz_dwarf.c (copied to mayhem/harnesses/, one
# change: a non-DWARF input is rejected with -1 instead of exit (1)) against it, both as a libFuzzer
# target and as a standalone reproducer. Also builds a behavioral DWARF known-answer oracle
# (mayhem/harnesses/kat_dwarf.c) for mayhem/test.sh. Sanitizers, SanCov and LSan-off follow the live layer.
#
# Build contract from org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/STANDALONE_FUZZ_MAIN).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg SANITIZER_FLAGS= builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX DEBUG_FLAGS

# radare2, the libr code it links and every harness build with the FULL $SANITIZER_FLAGS (ASan +
# UBSan, both halting), with ONE narrow UBSan relax: -fno-sanitize=function. radare2 registers its
# static plugins through a generic callback (libr/util/libstore.c calls each library's typed
# r_*_plugin_add through a `bool (*)(void *, void *)` pointer). UBSan's `function` check rejects that
# call inside r_core_new(), so it aborts on EVERY input before ia_fuzz reaches the fuzzed code.
# Measured on clang 19.1.7 with full $SANITIZER_FLAGS, on the first seed, the KAT oracle and every
# other input alike:
#   libstore.c:80:10: runtime error: call to function r_asm_plugin_add through pointer to incorrect
#   function type 'bool (*)(void *, void *)'
#   /mayhem/libr/asm/asm.c:18: note: r_asm_plugin_add defined here
#   SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior libstore.c:80:10
# ASan and every other UBSan check stay on and halting. Only added when sanitizers are on, so an
# explicit empty --build-arg SANITIZER_FLAGS= still builds with none.
R2_SANITIZER_FLAGS="${SANITIZER_FLAGS}"
[ -n "${SANITIZER_FLAGS// /}" ] && R2_SANITIZER_FLAGS="${R2_SANITIZER_FLAGS} -fno-sanitize=function"

# SanitizerCoverage instrumentation for the fuzzed radare2 code itself. libr.a was previously built
# with ONLY $R2_SANITIZER_FLAGS (ASan, no -fsanitize=fuzzer[-no-link]) -- so libFuzzer/Mayhem saw
# ZERO coverage edges inside radare2; the only instrumented code was the tiny ia_fuzz.cc harness TU
# (compiled+linked with $LIB_FUZZING_ENGINE=-fsanitize=fuzzer, which implies coverage). We add
# `-fsanitize=fuzzer-no-link` (coverage instrumentation only, no libFuzzer main/runtime, no conflict
# with the final link's $LIB_FUZZING_ENGINE) to libr.a's own CFLAGS/CXXFLAGS below, and also to the
# harness TU's compile flags alongside $R2_SANITIZER_FLAGS for consistency.
R2_COV_FLAGS="-fsanitize=fuzzer-no-link"

export USERCC="$CC" HOST_CC="$CC" NOLTO=1
export AR=llvm-ar

cd "$SRC"

BUILD="$SRC/mayhem-build"
mkdir -p "$BUILD"

# ── 0) Idempotent source patches (applied every run; no-ops once already applied) ───────────
python3 - "$SRC/libr/Makefile" <<'PYEOF'
import sys
p = sys.argv[1]
lines = open(p).read().split("\n")

# (a) Skip building libr.so: linking libr's merged libr.o (ASan-instrumented) into a shared object
#     makes clang's driver pull the STATIC ASan runtime into the .so, colliding with symbols already
#     baked into libr.o (".preinit_array section is not allowed in DSO" / duplicate-symbol errors).
#     We never need libr.so (only libr.a, to link the fuzz harness), so just don't build it.
# NOTE: matched by EXACT line (not substring) -- "\t$(MAKE) libr.${EXT_SO}" is also a PREFIX of the
# unrelated recursive rule "\t$(MAKE) libr.${EXT_SO} WITH_LIBR=1" a few lines down.
old_a = "\t$(MAKE) libr.${EXT_SO}"
new_a = "\t@true # mayhem: skip libr.so (ASan-static-runtime clash when linked into a DSO; only libr.a is needed for the fuzz harness)"
n_a = sum(1 for l in lines if l == old_a)
if n_a:
    assert n_a == 1, n_a
    lines = [new_a if l == old_a else l for l in lines]

# (b) libr.o is built via `clang -r -nostdlib --whole-archive ...` (a RELOCATABLE partial link, just
#     combining every component .a into one .o). clang's driver adds the sanitizer runtime to ANY
#     link-shaped invocation whenever -fsanitize=... is present in $(CFLAGS) -- including `-r` mode --
#     so libr.o ends up with a full baked-in copy of the ASan runtime. Then linking OUR harness
#     against libr.a (which also wants the runtime) collides with that baked-in copy ("multiple
#     definition of `__asan_check_load_add_16_RBX'", etc). `-fno-sanitize-link-runtime` suppresses
#     runtime linking for JUST this partial-link recipe (each .o was already compiled+instrumented
#     per-file beforehand; we only want to stop RE-linking the runtime at this aggregation step).
old_b = "\t$(CC) -r -nostdlib $(CFLAGS) $(WHOLEFLAG) -o libr.o $(wildcard */libr_*.${EXT_AR}) ../shlr/libr_shlr.${EXT_AR}"
new_b = "\t$(CC) -r -nostdlib -fno-sanitize-link-runtime $(CFLAGS) $(WHOLEFLAG) -o libr.o $(wildcard */libr_*.${EXT_AR}) ../shlr/libr_shlr.${EXT_AR}"
n_b = sum(1 for l in lines if l == old_b)
if n_b:
    assert n_b == 1, n_b
    lines = [new_b if l == old_b else l for l in lines]

open(p, 'w').write("\n".join(lines))
print("mayhem: libr/Makefile patches applied (idempotent)")
PYEOF

# (c) At BASE, libr/debug/p/debug_evm.c guards its `radare_plugin` with `#ifndef CORELIB`, a macro nothing
#     defines (the static build defines R2_PLUGIN_INCORE), so it exports `radare_plugin` next to qjs.c's.
#     Under ASan both objects carry `__odr_asan_gen_radare_plugin`, and libr.o's partial link dies with
#     "multiple definition". Upstream later switched the guard to R2_PLUGIN_INCORE; do the same here.
python3 - "$SRC/libr/debug/p/debug_evm.c" <<'PYEOF'
import sys
p = sys.argv[1]
s = open(p).read()
s2 = s.replace("#ifndef CORELIB\nRLibStruct radare_plugin", "#ifndef R2_PLUGIN_INCORE\nRLibStruct radare_plugin")
if s2 != s:
    open(p, 'w').write(s2)
print("mayhem: debug_evm.c plugin guard patched" if s2 != s else "mayhem: debug_evm.c guard already patched / absent")
PYEOF

# ── 1) Configure + build libr.a (sanitized + SanCov-instrumented), skipping libr.so and the CLI
#       tools (binr) ────────────────────────────────────────────────────────────────────────────
export CFLAGS="${R2_SANITIZER_FLAGS} ${R2_COV_FLAGS} ${DEBUG_FLAGS}"
export CXXFLAGS="${CFLAGS}"

./configure-plugins
./configure --prefix=/usr --without-gpl --with-libr --quiet

make -j"${MAYHEM_JOBS}" plugins.cfg libr/include/r_version.h

# ── 1a) Git subprojects from an in-image cache (air-gapped re-run + git-clean'ed graded rebuild) ──
# `make -C shlr sdbs` runs `$(MAKE) -C ../subprojects` when subprojects/sdb is missing
# (shlr/Makefile, $(SDB_ROOT) rule). That target `git clone`s from github.com every git subproject
# this configuration builds (FINALDEPS, computed from the config-user.mk the ./configure above wrote:
# sdb, qjs, otezip, capstone-v5; zydis is built from tracked packagefiles/). All of those checkouts
# are .gitignore'd, so the grader's `git clean -ffdX` deletes them and the offline rebuild cannot
# re-clone them. mayhem/subprojects-cache.sh mirrors each pinned url@revision into
# $R2_SUBPROJECTS_CACHE (outside the tree, so the clean leaves it alone; the mirror is fetched online
# only on a cache miss) and points the unmodified .mk clones at that mirror. A pin bump from an
# upstream sync just re-populates the cache on the next online build. Nothing is fatal here: an
# unfillable miss leaves the .mk to clone from the network, as upstream does.
: "${R2_SUBPROJECTS_CACHE:=/opt/toolchains/radare2-subprojects}"
# shellcheck source=mayhem/subprojects-cache.sh
. "$SRC/mayhem/subprojects-cache.sh"
# shellcheck disable=SC2016  # $(...) below is make syntax, expanded by make
SPRJ_DEPS="$(make -s --no-print-directory -C subprojects \
               --eval='mayhem-print-deps: ; @echo $(or $(FINALDEPS),$(DEPS))' mayhem-print-deps 2>/dev/null || true)"
[ -n "$SPRJ_DEPS" ] || echo "mayhem: WARNING: could not list subprojects/ FINALDEPS; no subproject is cached" >&2
# shellcheck disable=SC2086  # word-split the dep list
sprj_cache_setup "$SRC/subprojects" "$R2_SUBPROJECTS_CACHE" $SPRJ_DEPS

make -j"${MAYHEM_JOBS}" -C shlr sdbs
make -j"${MAYHEM_JOBS}" -C shlr/zip
make -j"${MAYHEM_JOBS}" -C libr/util
make -j"${MAYHEM_JOBS}" -C libr/socket
make -j"${MAYHEM_JOBS}" -C shlr
make -j"${MAYHEM_JOBS}" -C libr

LIBR_A="$SRC/libr/libr.a"
[ -f "$LIBR_A" ] || { echo "ERROR: $LIBR_A not produced" >&2; exit 1; }
echo "built radare2 libr.a: $(du -h "$LIBR_A" | cut -f1)"

# ── 2) Assemble a $RADARE2_STATIC_BUILD dist dir (mirrors OSS-Fuzz's r2-static/usr layout) ──────
RADARE2_STATIC_BUILD="$BUILD/r2static-dist"
rm -rf "$RADARE2_STATIC_BUILD"
mkdir -p "$RADARE2_STATIC_BUILD/usr/lib" "$RADARE2_STATIC_BUILD/usr/include/libr/sdb"
cp "$LIBR_A" "$RADARE2_STATIC_BUILD/usr/lib/libr.a"
cp -r "$SRC/libr/include/." "$RADARE2_STATIC_BUILD/usr/include/libr/"
cp -r "$SRC/subprojects/sdb/include/sdb/." "$RADARE2_STATIC_BUILD/usr/include/libr/sdb/"
export RADARE2_STATIC_BUILD

# ── 3) Build the harness (mayhem/harnesses/fuzz_dwarf.c) against libr.a ────────────────────────────
# -fuse-ld=lld: the default bfd `ld` takes minutes to link against the single giant merged-object
# libr.a; lld does the identical link in seconds.
LIBS="${RADARE2_STATIC_BUILD}/usr/lib/libr.a -lpthread -lutil -ldl -lm"
INCS="-I ${RADARE2_STATIC_BUILD}/usr/include/libr -I ${RADARE2_STATIC_BUILD}/usr/include/libr/sdb"

# Build-time LSan off-switch (SPEC §6.2 item 15), linked into every binary below. See lsan_off.cc.
$CXX ${R2_SANITIZER_FLAGS} ${DEBUG_FLAGS} -c "$SRC/mayhem/lsan_off.cc" -o "$BUILD/lsan_off.o"

$CC -fuse-ld=lld ${R2_SANITIZER_FLAGS} ${R2_COV_FLAGS} ${DEBUG_FLAGS} ${INCS} \
    "$SRC/mayhem/harnesses/fuzz_dwarf.c" "$BUILD/lsan_off.o" ${LIBS} \
    "$LIB_FUZZING_ENGINE" -lstdc++ \
    -o /mayhem/fuzz_dwarf

# ── 4) Standalone reproducer (no libFuzzer runtime), same harness source ────────────────────────
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
$CC ${R2_SANITIZER_FLAGS} ${DEBUG_FLAGS} -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"
$CC -fuse-ld=lld ${R2_SANITIZER_FLAGS} ${DEBUG_FLAGS} ${INCS} \
    "$SRC/mayhem/harnesses/fuzz_dwarf.c" "$BUILD/standalone_main.o" "$BUILD/lsan_off.o" ${LIBS} -lstdc++ \
    -o /mayhem/fuzz_dwarf-standalone

# ── 5) Behavioral DWARF KAT oracle for mayhem/test.sh (mayhem/harnesses/kat_dwarf.c) ─────────────
$CC -fuse-ld=lld ${R2_SANITIZER_FLAGS} ${DEBUG_FLAGS} ${INCS} \
    "$SRC/mayhem/harnesses/kat_dwarf.c" "$BUILD/lsan_off.o" ${LIBS} -lstdc++ \
    -o /mayhem/kat_dwarf

echo ""
echo "build.sh complete:"
ls -lh /mayhem/fuzz_dwarf /mayhem/fuzz_dwarf-standalone /mayhem/kat_dwarf
