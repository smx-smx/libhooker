/*
 * Stuff.
 *
 */

#ifndef __INTERFACE_INJECT_LINUX_H
#define __INTERFACE_INJECT_LINUX_H

#include <stdlib.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/ptrace.h>

#include "lh_common.h"
#include "interface/if_cpu.h"
//#include "interface/if_inject.h"
#include "interface/exe/elf/linux_elf.h"

#define LH_PRELOAD_SO "lh_preload.so"

//TODO: Every Arch should have its own lh_session_t
typedef struct {
	lh_r_process_t proc; //lh_common.h
	bool started_by_needle;

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


#define LH_LIB_MAX 128
#define LH_MAX_ARGS 4

lh_session_t *lh_alloc();
int lh_attach(lh_session_t * session, pid_t pid);
int lh_inject_library(lh_session_t * session, const char *library, uintptr_t * out_libaddr);
int lh_detach(lh_session_t * session);
void lh_free(lh_session_t ** session);
uintptr_t lh_dlsym(lh_session_t * lh, struct user *iregs, char *symbolName);
uintptr_t lh_call_func(lh_session_t * lh, struct user *iregs, uintptr_t function, char *funcname, uintptr_t arg0, uintptr_t arg1);
#endif
