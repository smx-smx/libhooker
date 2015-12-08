#ifndef __INTERFACE_CPU_H
#define __INTERFACE_CPU_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef __linux__
#include <sys/wait.h>
#endif
#include <errno.h>

#if __android__
struct user {
	long uregs[18];
};
#elif __linux__
#include <sys/user.h>
#endif

#include "lh_common.h"

#if defined(__i386__) || defined(__x86_64__)
#include "interface/cpu/cpu_intel.h"
#endif

#include <capstone/capstone.h>

/*
 * Common Functions
 */
size_t inj_getjmp_size();
uint8_t *inj_build_jump(uintptr_t dstAddr, uintptr_t srcAddr, size_t *jumpSz);

int inj_getbackup_size(uint8_t *codePtr, size_t codeSz, size_t payloadSz);
int inj_relocate_code(uint8_t *codePtr, size_t codeSz, uintptr_t sourcePC, uintptr_t destPC);


/*
 * Per-CPU Functions
 */
int inj_trap_bytes();
int inj_opcode_bytes();
int inj_absjmp_opcode_bytes();
int inj_reljmp_opcode_bytes();
int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes);

int inj_build_trap(uint8_t *buffer);
int inj_build_rel_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address);
int inj_build_abs_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address);
int inj_reljmp_opcode_bytes();
int lh_redzone();

int inj_trap(pid_t pid, struct user *iregs);
int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2);

void lh_rset_ip(struct user *r, uintptr_t value);
uintptr_t lh_rget_ip(struct user *r);

void lh_rset_sp(struct user *r, uintptr_t value);
uintptr_t lh_rget_sp(struct user *r);

void lh_rset_fp(struct user *r, uintptr_t value);
uintptr_t lh_rget_fp(struct user *r);

void lh_rset_ax(struct user *r, uintptr_t value);
uintptr_t lh_rget_ax(struct user *r);

void lh_dump_regs(struct user *regs);

#endif
