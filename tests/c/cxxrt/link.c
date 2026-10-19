/*
 * dl_iterate_phdr and dladdr in a static program: one object, the program,
 * whose headers hold the code calling them, with this thread's TLS block.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#if __SIZEOF_POINTER__ == 8 && !defined(DLFO_EH_SEGMENT_TYPE)
/* libunwind compares it with PT_GNU_EH_FRAME wherever DLFO_STRUCT_HAS_EH_DBASE
 * is defined, and <dlfcn.h> alone must define it. */
#error dlfcn.h declares _dl_find_object but not the segment it finds
#endif
#include <elf.h>
#include <link.h>
#if __SIZEOF_POINTER__ == 8 && DLFO_EH_SEGMENT_TYPE != PT_GNU_EH_FRAME
#error _dl_find_object retrieves an unexpected section type
#endif
#include <stdint.h>

#include "check.h"

static __thread int tls_value = 42;

struct seen {
	int calls;
	int code_covered;
	int tls_covered;
	uintptr_t eh_segment;
};

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	struct seen *seen = data;
	uintptr_t code = (uintptr_t)&callback;
	uintptr_t tls = (uintptr_t)&tls_value;
	seen->calls++;
	CHECK(size >= sizeof *info);
	CHECK(info->dlpi_name != 0 && info->dlpi_name[0] == 0);
	CHECK(info->dlpi_phnum > 0);
	CHECK(info->dlpi_adds == 1 && info->dlpi_subs == 0);
	CHECK(info->dlpi_tls_modid == 1);
	for (int i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		uintptr_t start = info->dlpi_addr + ph->p_vaddr;
		if (ph->p_type == PT_LOAD && code >= start && code - start < ph->p_memsz)
			seen->code_covered = 1;
		if (ph->p_type == PT_GNU_EH_FRAME)
			seen->eh_segment = start;
		if (ph->p_type == PT_TLS) {
			uintptr_t block = (uintptr_t)info->dlpi_tls_data;
			if (tls >= block && tls - block < ph->p_memsz)
				seen->tls_covered = 1;
		}
	}
	return 7;
}

int main(void)
{
	struct seen seen = {0};
	CHECK(tls_value == 42);
	CHECK(dl_iterate_phdr(callback, &seen) == 7);
	CHECK(seen.calls == 1);
	CHECK(seen.code_covered);
	CHECK(seen.tls_covered);

	Dl_info info = {0};
	CHECK(dladdr(&callback, &info) != 0);
	CHECK(info.dli_fname != 0 && info.dli_fname[0] == 0);
	CHECK(info.dli_sname == 0 && info.dli_saddr == 0);
	CHECK(dladdr((void *)16, &info) == 0);

#if __SIZEOF_POINTER__ == 8
	/* What libgcc's unwinder asks, and since GCC 12 the only thing it
	 * asks: the object holding an address, and its unwind table. */
	struct dl_find_object found = {0};
	uintptr_t code = (uintptr_t)&callback;
	found.__dlfo_reserved[6] = 0x5a5a;
	CHECK(_dl_find_object(&callback, &found) == 0);
	CHECK((uintptr_t)found.dlfo_map_start <= code && code < (uintptr_t)found.dlfo_map_end);
	CHECK(found.dlfo_flags == 0 && found.dlfo_link_map == 0);
	CHECK(found.__dlfo_reserved[6] == 0x5a5a);
	/* dlfo_eh_frame is the segment DLFO_EH_SEGMENT_TYPE names, or null
	 * where the program has none. */
	CHECK((uintptr_t)found.dlfo_eh_frame == seen.eh_segment);
	/* The table is `.eh_frame_hdr`, version 1, inside the object, where
	 * the program was linked with one; a static C program may have none. */
	if (found.dlfo_eh_frame != 0) {
		CHECK((uintptr_t)found.dlfo_map_start <= (uintptr_t)found.dlfo_eh_frame
			&& (uintptr_t)found.dlfo_eh_frame < (uintptr_t)found.dlfo_map_end);
		CHECK(*(unsigned char *)found.dlfo_eh_frame == 1);
	}
	CHECK(_dl_find_object((void *)16, &found) == -1);
#endif
	return t_status;
}
