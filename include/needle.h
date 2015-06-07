/*
 * Stuff.
 *
 */

#ifndef __HOOKER_NEEDLE_H
#define __HOOKER_NEEDLE_H

#include <stdint.h>

#include "lh_common.h"
#include "interface/if_cpu.h"
#include "interface/if_os.h"
#include "interface/inject/inject_linux.h" //temporary. needs a unified lh_session_t

#define LH_LIB_MAX 128

typedef struct {
	lh_r_process_t proc;

	struct user original_regs;

	enum elf_bit is64;
	struct elf_symbol *exe_symbols;
	size_t exe_symbols_num;
	uintptr_t exe_entry_point;
	struct elf_interp exe_interp;	/* dynamic loader from .interp in the exe */
	struct ld_procmaps *ld_maps;
	size_t ld_maps_num;
	/* addresses useful */
	uintptr_t fn_malloc;
	uintptr_t fn_realloc;
	uintptr_t fn_free;
	uintptr_t fn_dlopen;
	uintptr_t fn_dlclose;
	uintptr_t fn_dlsym;

} lh_session_t;

int inj_pokedata(pid_t pid, uintptr_t target, uintptr_t pokedata);

lh_session_t *lh_alloc();
int lh_attach(lh_session_t * session, pid_t pid);
int lh_inject_library(lh_session_t * session, const char *library, uintptr_t * out_libaddr);
int lh_detach(lh_session_t * session);
void lh_free(lh_session_t ** session);

#endif
