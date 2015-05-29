#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "lh_common.h"
#include "lh_mod_common.h"

uintptr_t lhm_mmap(uintptr_t address, size_t size) {
	return (uintptr_t) mmap((void *)address, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

int lhm_munmap(uintptr_t address, size_t size) {
	return munmap((void *)address, size);
}

uintptr_t lhm_memcpy(uintptr_t dst_address, uintptr_t src_address) {
	return (uintptr_t) memcpy((void *)dst_address, (void *)src_address, LHM_FN_COPY_BYTES);
}

void lhm_hexdump(uintptr_t address, size_t size) {
	lh_hexdump(">> ", (void *)address, (int)size);
}
