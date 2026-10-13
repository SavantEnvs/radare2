/*
 * kat_dwarf.c -- behavioral known-answer test (KAT) for mayhem/test.sh.
 *
 * Loads a known ELF object (argv[1]) whose .debug_info holds one compile unit with
 * DW_AT_producer = "mayhem-kat" and DW_AT_name = "kat.c" (both DW_FORM_strp into .debug_str),
 * parses it with radare2's DWARF parser (the code fuzz_dwarf exercises) and asserts the COMPUTED
 * values: one unit, DW_TAG_compile_unit, and the two decoded strings. Prints KAT_PASS only if all hold.
 */
#include <r_bin.h>
#include <r_io.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf (stderr, "usage: kat_dwarf <elf>\n");
		return 2;
	}
	size_t len = 0;
	ut8 *data = (ut8 *)r_file_slurp (argv[1], &len);
	if (!data) {
		fprintf (stderr, "FAIL: cannot read %s\n", argv[1]);
		return 1;
	}
	RBuffer *buf = r_buf_new_with_bytes (data, len);
	RBin *bin = r_bin_new ();
	RIO *io = r_io_new ();
	r_io_bind (io, &bin->iob);
	RBinFileOptions bo;
	r_bin_file_options_init (&bo, -1, 0x10000000, 0, 0);
	bo.filename = strdup ("kat");
	r_bin_open_buf (bin, buf, &bo);

	int rc = 1;
	RBinDwarfDebugAbbrev *da = r_bin_dwarf_parse_abbrev (bin, 0);
	RBinDwarfDebugInfo *info = da ? r_bin_dwarf_parse_info (da, bin, 0) : NULL;
	if (info && info->count == 1 && info->comp_units[0].count >= 1) {
		RBinDwarfDie *die = &info->comp_units[0].dies[0];
		const char *producer = NULL, *name = NULL;
		size_t i;
		for (i = 0; i < die->count; i++) {
			RBinDwarfAttrValue *v = &die->attr_values[i];
			if (v->kind != DW_AT_KIND_STRING) {
				continue;
			}
			if (v->attr_name == DW_AT_producer) {
				producer = v->string.content;
			} else if (v->attr_name == DW_AT_name) {
				name = v->string.content;
			}
		}
		if (die->tag == DW_TAG_compile_unit && producer && name
				&& !strcmp (producer, "mayhem-kat") && !strcmp (name, "kat.c")) {
			printf ("KAT_PASS units=1 tag=compile_unit producer='%s' name='%s'\n", producer, name);
			rc = 0;
		}
	}
	r_bin_dwarf_free_debug_info (info);
	r_bin_dwarf_free_debug_abbrev (da);
	r_bin_free (bin);
	free (bo.filename);
	r_io_free (io);
	r_buf_free (buf);
	free (data);
	if (rc) {
		fprintf (stderr, "KAT FAILED\n");
	}
	return rc;
}
