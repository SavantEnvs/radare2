// Build-time LeakSanitizer off-switch (fleet convention, SPEC §6.2 item 15).
//
// -fsanitize=address always bundles LeakSanitizer; leaks are not the defect class this target is
// fuzzed for. radare2's r_bin loader and plugins leak small allocations on many inputs (strdup'd
// machine names, r_list_new / sdb_new in plugin init, RVec reallocs), so with LSan on, Mayhem recorded
// only CWE-401 "leaks" (run #3: 4 of 4 defects). LSan consults this hook both at process exit and in
// libFuzzer's in-process leak check, so leak detection is skipped while ASan stays fully active.
// build.sh compiles it with the same sanitizer flags as the harness and links it into ia_fuzz,
// ia_fuzz-standalone and the kat_asm oracle.
extern "C" int __lsan_is_turned_off() { return 1; }
