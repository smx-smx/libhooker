#ifndef __INTERFACE_CPU_H
#define __INTERFACE_CPU_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>
#include <errno.h>

#include "needle.h"
//#include "inject.h"

#if defined(__i386__) || defined(__x86_64__)
#include "interface/cpu/cpu_intel.h"
#endif

/* 
 * Common Functions
 */
size_t inj_getjmp_size();
int inj_build_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address);
int inj_getbackup_size(uint8_t *codePtr, size_t codeSz, size_t payloadSz);


/* 
 * Per-CPU Functions
 */
int inj_opcode_bytes();
int inj_absjmp_opcode_bytes();
int inj_reljmp_opcode_bytes();
int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes);

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