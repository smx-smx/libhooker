#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>

#include "needle.h"
#include "inject.h"

#if __x86_64__


//------------------------------------------ x86 begin
inline int inj_reljmp_opcode_bytes() {
	return 5;
}

int inj_build_rel_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	uintptr_t operand = jump_destination - jump_opcode_address - 5;

	LH_VERBOSE(4, "REL JUMP (X64) TO " LX " FROM " LX " IS: " LX, jump_destination, jump_opcode_address, operand);

	uint32_t lo = operand & 0xFFFFFFFF;
	uint32_t hi = ((operand >> 32) & 0xFFFFFFFF);
	if ((hi != 0) && (hi != 0xFFFFFFFF)) {
		LH_VERBOSE(4, "ERROR: high byte is %u, cant build reljump", hi);
		return -1;
	}

	buffer[0] = 0xE9;
	uint32_t *x = (uint32_t *) & (buffer[1]);
	*x = lo;
// 0:   e9 44 33 22 11          jmpq   0x11223349

	return LH_SUCCESS;
}

inline int inj_absjmp_opcode_bytes() {
	return 5 + 8 + 1;
}

int inj_build_abs_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	uint32_t lo = jump_destination & 0xFFFFFFFF;
	uint32_t hi = ((jump_destination >> 32) & 0xFFFFFFFF);

	int i = 0;
	buffer[i++] = 0x68;
	uint32_t *x = (uint32_t *) & (buffer[i]);
// 0: 68 44 33 22 11    push $11223344

	*x = lo;
	i += sizeof(uint32_t);
	buffer[i++] = 0xC7;
	buffer[i++] = 0x44;
	buffer[i++] = 0x24;
	buffer[i++] = 0x04;
	x = (uint32_t *) & (buffer[i]);
	*x = hi;
	i += sizeof(uint32_t);
// 5: c7 44 24 04 88 77 66 55    mov 4(%rsp), 55667788  # upper 4 bytes

	buffer[i++] = 0xC3;
//d: c3                retq

	return LH_SUCCESS;
}

inline int inj_trap(pid_t pid, struct user *iregs) {
	uintptr_t nullcode = 0;
	LH_VERBOSE(3, "Copying Null to stack.");
	return inj_pokedata(pid, lh_rget_sp(iregs), nullcode);
}
int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2) {
	LH_VERBOSE(3, "function address is: 0x" LX, fn);
	iregs->regs.rsi = arg2;
	iregs->regs.rdi = arg1;
	lh_rset_ip(iregs, fn);
	lh_rset_ax(iregs, 0);

	return LH_SUCCESS;
}

inline void lh_rset_ip(struct user *r, uintptr_t value) {
	r->regs.rip = value;
}

inline uintptr_t lh_rget_ip(struct user *r) {
	return r->regs.rip;
}

inline void lh_rset_sp(struct user *r, uintptr_t value) {
	r->regs.rsp = value;
}

inline uintptr_t lh_rget_sp(struct user *r) {
	return r->regs.rsp;
}

inline void lh_rset_ax(struct user *r, uintptr_t value) {
	r->regs.rax = value;
}

inline uintptr_t lh_rget_ax(struct user *r) {
	return r->regs.rax;
}
inline int lh_redzone() {
	return 128;
}

void lh_dump_regs(struct user *r) {
	LH_VERBOSE(3, "--------------------------- x86_64");
	LH_VERBOSE(3, "%%rip : 0x" LX, r->regs.rip);
	LH_VERBOSE(3, "%%rax : 0x" LX, r->regs.rax);
	LH_VERBOSE(3, "%%rbx : 0x" LX, r->regs.rbx);
	LH_VERBOSE(3, "%%rcx : 0x" LX, r->regs.rcx);
	LH_VERBOSE(3, "%%rdx : 0x" LX, r->regs.rdx);
	LH_VERBOSE(3, "%%rsi : 0x" LX, r->regs.rsi);
	LH_VERBOSE(3, "%%rdi : 0x" LX, r->regs.rdi);
	LH_VERBOSE(3, "%%rbp : 0x" LX, r->regs.rbp);
	LH_VERBOSE(3, "%%orax: 0x" LX, r->regs.orig_rax);
	LH_VERBOSE(3, "%%rsp : 0x" LX, r->regs.rsp);
}
//------------------------------------------ x86 end




#elif __i386__

//-------------------------------------------- i386 begin
inline int inj_reljmp_opcode_bytes() {
	return 5;
}

inline int inj_absjmp_opcode_bytes() {
	return 5 + 1;
}

int inj_build_rel_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t source) {
	uintptr_t operand = jump_destination - source - 5;

	LH_VERBOSE(4, "REL JUMP (X64) TO " LX " FROM " LX " IS: " LX, jump_destination, source, operand);

	uint32_t lo = (uint32_t) (operand);

	buffer[0] = 0xE9;
	uint32_t *x = (uint32_t *) & (buffer[1]);
	*x = lo;
// 0:   e9 44 33 22 11          jmpq   0x11223349

	return LH_SUCCESS;
}

int inj_build_abs_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t source) {
	uint32_t lo = (uint32_t) jump_destination;

	int i = 0;
	buffer[i++] = 0x68;
	uint32_t *x = (uint32_t *) & (buffer[i]);
	*x = lo;
	i += sizeof(uint32_t);
// 0: 68 44 33 22 11    push $11223344

	buffer[i++] = 0xC3;
//5: c3                retq

	return LH_SUCCESS;
}

inline int inj_trap(pid_t pid, struct user *iregs) {
	uintptr_t nullcode = 0;
	LH_VERBOSE(3, "Copying Null to stack.");
	return inj_pokedata(pid, lh_rget_sp(iregs), nullcode);
}

int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2) {
	int rc;

	LH_VERBOSE(3, "function address is: 0x" LX, fn);

	LH_VERBOSE(3, "Copying Arg 1 to stack.");
	if ((rc = inj_pokedata(pid, lh_rget_sp(iregs) + sizeof(size_t), arg1)) != LH_SUCCESS)
		return rc;
	LH_VERBOSE(3, "Copying Arg 2 to stack.");
	if ((rc = inj_pokedata(pid, lh_rget_sp(iregs) + 2 * sizeof(size_t), arg2)) != LH_SUCCESS)
		return rc;

	lh_rset_ip(iregs, fn);
	lh_rset_ax(iregs, 0); 

        return LH_SUCCESS;
}

inline void lh_rset_ip(struct user *r, uintptr_t value) {
	r->regs.eip = value;
}

inline uintptr_t lh_rget_ip(struct user *r) {
	return r->regs.eip;
}

inline void lh_rset_sp(struct user *r, uintptr_t value) {
	r->regs.esp = value;
}

inline uintptr_t lh_rget_sp(struct user *r) {
	return r->regs.esp;
}

inline void lh_rset_ax(struct user *r, uintptr_t value) {
	r->regs.eax = value;
}

inline uintptr_t lh_rget_ax(struct user *r) {
	return r->regs.eax;
}

inline int lh_redzone() {
	return 0;
}

void lh_dump_regs(struct user *r) {
	LH_VERBOSE(3, "--------------------------- i386");
	LH_VERBOSE(3, "%%eip : 0x" LX, r->regs.eip);
	LH_VERBOSE(3, "%%eax : 0x" LX, r->regs.eax);
	LH_VERBOSE(3, "%%ebx : 0x" LX, r->regs.ebx);
	LH_VERBOSE(3, "%%ecx : 0x" LX, r->regs.ecx);
	LH_VERBOSE(3, "%%edx : 0x" LX, r->regs.edx);
	LH_VERBOSE(3, "%%esi : 0x" LX, r->regs.esi);
	LH_VERBOSE(3, "%%edi : 0x" LX, r->regs.edi);
	LH_VERBOSE(3, "%%ebp : 0x" LX, r->regs.ebp);
	LH_VERBOSE(3, "%%oeax: 0x" LX, r->regs.orig_eax);
	LH_VERBOSE(3, "%%esp : 0x" LX, r->regs.esp);
}
//-------------------------------------------- i386 end



#elif __arm__


//----------------------------------------------------- arm begin
inline int inj_absjmp_opcode_bytes() {
	return 4 + 4;
}

inline int inj_reljmp_opcode_bytes() {
	return 4;
}

int inj_build_rel_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	if (jump_destination % 4 != 0) {
		LH_ERROR("Destination address is not multiple of 4");
		return -1;
	}
	if (jump_opcode_address % 4 != 0) {
		LH_ERROR("Opcode address is not multiple of 4");
		return -1;
	}

	uint32_t offset = (uint32_t) jump_destination - jump_opcode_address - 4;
	LH_VERBOSE(4, "Offset is: " LX, offset);
	uint32_t operand = (offset / 4) - 1;
	LH_VERBOSE(4, "Operand is: " LX, operand);

/*
// todo: validate this somehow
  if((operand & 0xFF000000) > 0) {
     LH_ERROR("Jump is too big");
     return -1;
  }
*/
	uint32_t *x = (uint32_t *) buffer;
	*x = operand;
	buffer[3] = 0xEA;

	return LH_SUCCESS;
}

//ldr pc, [pc, #-4] => 04 f0 1f e5
int inj_build_abs_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	int i = 0;
	buffer[i++] = 0x04;
	buffer[i++] = 0xf0;
	buffer[i++] = 0x1f;
	buffer[i++] = 0xe5;

	uint32_t dest = (uint32_t) jump_destination;
	uint32_t *x = (uint32_t *) & (buffer[i]);
	*x = dest;

	return LH_SUCCESS;
}

/*
inline int inj_reljmp_opcode_bytes() {
  return inj_absjmp_opcode_bytes();
}
int inj_build_rel_jump(unsigned char* buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address)
{
  return inj_build_abs_jump(buffer, jump_destination, jump_opcode_address);
}
// other useful: http://www.davespace.co.uk/arm/introduction-to-arm/addressing.html
// http://stackoverflow.com/questions/6097958/what-does-the-value-associated-with-the-arm-ldr-instruction-mean
// based on: http://www.codepwn.com/posts/assembling-from-scratch-encoding-blx-instruction-in-arm-thumb/
int inj_build_rel_jump(unsigned char* buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address)
{
  LH_VERBOSE(4, "Calculating relative jump "LX" -> "LX, jump_opcode_address, jump_destination);
  uint32_t aligned = (uint32_t) ((jump_opcode_address + 4) & 0xFFFFFFFC); // +4 => opcode address
  LH_VERBOSE(4,"Aligned: "LX, aligned);
  uint32_t offset = (uint32_t) (jump_destination - aligned);
  LH_VERBOSE(4,"Offset: "LX, offset);

  if( (offset & 0x3) > 0) {
    LH_PRINT("ERROR: offset "LX" is not aligned to 4", offset);
    return -1;
  }

  uint32_t thi = (offset & 0xFE000000) >> 25;
  if((thi  != 0)&&(thi != 0x7F))
  {
    LH_PRINT("ERROR: bits 31-25 in offset "LX" are nonzero "LX," ("LX")", offset, thi);
    return -2;
  }

  uint32_t L = (offset >> 2) & 0x3FF;
  LH_VERBOSE(4,"L: "LX, L);
  uint32_t H = (offset >> 12) & 0x3FF;
  LH_VERBOSE(4,"H: "LX, H);

  uint32_t I2 = (offset >> 22) & 0x1;
  uint32_t I1 = (offset >> 23) & 0x1;
  uint32_t S  = (offset >> 24) & 0x1;

  LH_VERBOSE(4,"S: "LX, S);
  LH_VERBOSE(4,"I1: "LX, I1);
  LH_VERBOSE(4,"I2: "LX, I2);

  uint32_t J1 = (~I1 ^ S) & 0x1;
  LH_VERBOSE(4,"J1: "LX, J1);
  uint32_t J2 = (~I2 ^ S) & 0x1;
  LH_VERBOSE(4,"J2: "LX, J2);

  uint32_t raw_op =
     (L << 1)
     |
     (J2 << 11)
     |
     (J1 << 13)
     |
     (0x3 << 14)
     |
     (H << 16)
     |
     (S << 26)
     |
     (0xF << 28)
  ;
  LH_VERBOSE(4, "Raw op: "LX, raw_op);

  uint32_t shuffled =
    ((raw_op >> 16) & 0xFFFF)
    |
    ((raw_op & 0xFFFF) << 16)
  ;

  uint32_t* x = (uint32_t*) buffer;
  *x = shuffled;

  return LH_SUCCESS;
}
*/

inline void lh_rset_lr(struct user *r, uintptr_t value) {
	r->regs.uregs[14] = value;
}

inline uintptr_t lh_rget_lr(struct user *r) {
	return r->regs.uregs[14];
}

inline int inj_trap(pid_t pid, struct user *iregs) {
	LH_VERBOSE(3, "Copying Null to LR");
	lh_rset_lr(iregs, 0x0);
	return LH_SUCCESS;
}
int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2) {
	LH_VERBOSE(3, "function address is: 0x" LX, fn);
	LH_VERBOSE(3, "link register is: 0x" LX, lh_rget_lr(iregs));

	LH_VERBOSE(3, "copying Arg 1 to r0.");
	iregs->regs.uregs[0] = arg1;

	LH_VERBOSE(3, "opying Arg 2 to r1.");
	iregs->regs.uregs[1] = arg2;
	lh_rset_ip(iregs, fn);

	return LH_SUCCESS;

}

inline void lh_rset_ip(struct user *r, uintptr_t value) {
	r->regs.uregs[15] = value;
}

inline uintptr_t lh_rget_ip(struct user *r) {
	return r->regs.uregs[15];
}

inline void lh_rset_sp(struct user *r, uintptr_t value) {
	r->regs.uregs[13] = value;
}

inline uintptr_t lh_rget_sp(struct user *r) {
	return r->regs.uregs[13];
}

inline void lh_rset_ax(struct user *r, uintptr_t value) {
	r->regs.uregs[0] = value;
}

inline uintptr_t lh_rget_ax(struct user *r) {
	return r->regs.uregs[0];
}
inline int lh_redzone() {
	return 0;
}

void lh_dump_regs(struct user *r) {
	LH_VERBOSE(3, "--------------------------- ARM");
	LH_VERBOSE(3, "%%pc : 0x" LX, r->regs.uregs[15]);
	LH_VERBOSE(3, "%%lr : 0x" LX, r->regs.uregs[14]);
	LH_VERBOSE(3, "%%sp : 0x" LX, r->regs.uregs[13]);
	LH_VERBOSE(3, "%%fp : 0x" LX, r->regs.uregs[11]);
	LH_VERBOSE(3, "%%r0 : 0x" LX, r->regs.uregs[0]);
	LH_VERBOSE(3, "%%r1 : 0x" LX, r->regs.uregs[1]);
	LH_VERBOSE(3, "%%r2 : 0x" LX, r->regs.uregs[2]);
	LH_VERBOSE(3, "%%r3 : 0x" LX, r->regs.uregs[3]);
	LH_VERBOSE(3, "%%r4 : 0x" LX, r->regs.uregs[4]);
	LH_VERBOSE(3, "%%r5 : 0x" LX, r->regs.uregs[5]);
	LH_VERBOSE(3, "%%r6 : 0x" LX, r->regs.uregs[6]);
	LH_VERBOSE(3, "%%r7 : 0x" LX, r->regs.uregs[7]);
	LH_VERBOSE(3, "%%r8 : 0x" LX, r->regs.uregs[8]);
	LH_VERBOSE(3, "%%r9 : 0x" LX, r->regs.uregs[9]);
	LH_VERBOSE(3, "%%r10: 0x" LX, r->regs.uregs[10]);
	
}
//----------------------------------------------------- arm end


#endif

size_t inj_getjmp_size(){
	#ifdef LH_JUMP_ABS
		return inj_absjmp_opcode_bytes();
	#else
		return inj_reljmp_opcode_bytes();
	#endif
}

int inj_build_jump(unsigned char *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address){
	#ifdef LH_JUMP_ABS
		return inj_build_abs_jump(buffer, jump_destination, jump_opcode_address);
	#else
		return inj_build_rel_jump(buffer, jump_destination, jump_opcode_address);
	#endif
}