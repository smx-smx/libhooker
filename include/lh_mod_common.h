/*
 * Stuff.
 *
 */

#ifndef __HOOKER_MOD_H
#    define __HOOKER_MOD_H

#    include "lh_common.h"

#    define LHM_MAX_FN_HOOKS 32

#    define LHM_STR_LENGTH 64
#    define LHM_FN_COPY_BYTES 16

enum {
	LHM_FN_HOOK_TRAILING = 0,
	LHM_FN_HOOK_BY_NAME,
	LHM_FN_HOOK_BY_OFFSET
};

/*
 * Function hook definition
 */
typedef struct {
	int hook_kind;
	char libname[LHM_STR_LENGTH];
	char symname[LHM_STR_LENGTH];
	// or offset to codesegment
	uintptr_t sym_offset;
	uintptr_t hook_fn;
	uintptr_t orig_function_ptr;
	size_t opcode_bytes_to_restore;
} lh_fn_hook_t;


/*
 * Module definition
 */
typedef struct {
	int version;
	int (*autoinit_pre) (int argc, char **argv);
	void (*autoinit_post) (lh_r_process_t *);
	lh_fn_hook_t fn_hooks[LHM_MAX_FN_HOOKS];
} lh_hook_t;

extern lh_hook_t hook_settings;

uintptr_t lhm_mmap(uintptr_t address, size_t size);
uintptr_t lhm_memcpy(uintptr_t dst_address, uintptr_t src_address);
void lhm_hexdump(uintptr_t address, size_t size);

void lh_printf(const char *fmt, ...);
void lh_stdout_set(int fd);
void lh_stdout_clear();
int lh_stdout_getcurrent();
int lh_get_stdout(char *tty);
lh_r_process_t *lh_get_procinfo(int argc, char **argv);

#endif
