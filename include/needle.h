/*
 * Stuff.
 *
 */

#ifndef __HOOKER_NEEDLE_H
#    define __HOOKER_NEEDLE_H

#    include <stdint.h>
#    include <sys/ptrace.h>
#    include <unistd.h>

#    include "lh_common.h"
#    include "inject.h"

#    define LH_LIB_MAX 128
typedef struct {
	lh_main_process_t proc;

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

int inj_build_rel_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address);
int inj_reljmp_opcode_bytes();
int inj_build_abs_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address);
int inj_absjmp_opcode_bytes();

int inj_trap(pid_t pid, struct user *iregs);
int inj_pass_args2func(struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2);

void lh_rset_ip(struct user *r, uintptr_t value);
uintptr_t lh_rget_ip(struct user *r);

void lh_rset_sp(struct user *r, uintptr_t value);
uintptr_t lh_rget_sp(struct user *r);

void lh_rset_ax(struct user *r, uintptr_t value);
uintptr_t lh_rget_ax(struct user *r);

int lh_redzone();

void lh_dump_regs(struct user *regs);
lh_session_t *lh_alloc();
int lh_attach(lh_session_t * session, pid_t pid);
int lh_inject_library(lh_session_t * session, const char *library, uintptr_t * out_libaddr);
int lh_detach(lh_session_t * session);
void lh_free(lh_session_t ** session);

#endif
