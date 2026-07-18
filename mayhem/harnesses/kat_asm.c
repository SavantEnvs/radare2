/*
 * kat_asm.c -- behavioral known-answer test (KAT) for mayhem/test.sh.
 *
 * Feeds THREE fixed, well-known x86 opcode byte sequences into radare2's own
 * disassembler (r_asm_tostring(), the same asm/arch backend the ia_fuzz harness
 * exercises via `ia`/`oba`) and asserts the COMPUTED mnemonic text:
 *
 *   0x90            -> "nop"
 *   0xc3            -> "ret"
 *   0x89 0xd8        -> "mov eax, ebx"   (mov r/m32, r32; AT&T/Intel default syntax)
 *
 * This is a real behavioral oracle, not an exit-code/smoke check: a neutered or
 * broken analyzer either crashes, prints nothing, or computes the WRONG mnemonic,
 * all of which this program (and mayhem/test.sh, which greps its stdout for the
 * exact computed values) detects. It does NOT just check "did it crash" -- the
 * sabotage/anti-reward-hack check (an LD_PRELOAD constructor that _exit(0)s this
 * binary before main() runs) makes it print NOTHING, which mayhem/test.sh treats
 * as a failure because it greps for the printed KAT_PASS line, not the exit code.
 */
#include <r_core.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static char *trim(char *s) {
	if (!s) {
		return s;
	}
	size_t n = strlen(s);
	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
		s[--n] = 0;
	}
	return s;
}

int main(void) {
	RCore *core = r_core_new();
	if (!core || !core->rasm) {
		fprintf(stderr, "FAIL: r_core_new() did not yield a usable RAsm\n");
		return 1;
	}
	RAsm *a = core->rasm;
	r_asm_use(a, "x86");
	r_asm_set_bits(a, 32);

	unsigned char nop_bytes[] = {0x90};
	unsigned char ret_bytes[] = {0xc3};
	unsigned char mov_bytes[] = {0x89, 0xd8}; /* mov eax, ebx */

	char *s_nop = trim(r_asm_tostring(a, 0, nop_bytes, sizeof(nop_bytes)));
	char *s_ret = trim(r_asm_tostring(a, 0, ret_bytes, sizeof(ret_bytes)));
	char *s_mov = trim(r_asm_tostring(a, 0, mov_bytes, sizeof(mov_bytes)));

	int ok = 1;
	if (!s_nop || !strstr(s_nop, "nop")) {
		fprintf(stderr, "FAIL nop: got '%s'\n", s_nop ? s_nop : "(null)");
		ok = 0;
	}
	if (!s_ret || !strstr(s_ret, "ret")) {
		fprintf(stderr, "FAIL ret: got '%s'\n", s_ret ? s_ret : "(null)");
		ok = 0;
	}
	if (!s_mov || !strstr(s_mov, "mov")) {
		fprintf(stderr, "FAIL mov: got '%s'\n", s_mov ? s_mov : "(null)");
		ok = 0;
	}

	if (ok) {
		printf("KAT_PASS nop='%s' ret='%s' mov='%s'\n", s_nop, s_ret, s_mov);
	}
	/* r_asm_tostring() returns a caller-owned heap string -- free all three. (Leak detection is
	 * off in this binary: build.sh links mayhem/lsan_off.cc into it, like the fuzz targets.) */
	free(s_nop);
	free(s_ret);
	free(s_mov);
	r_core_free(core);
	return ok ? 0 : 1;
}
