#include "interface/if_cpu.h"

//----------------------------------------------------- arm begin
inline int inj_opcode_bytes(){
	return 4;
}

/*
inline int inj_trap_bytes(){
	return 4;
}

int inj_build_trap(uint8_t *buffer){
#ifndef __ARM_EABI__
	memcpy(buffer, 0xef9f0001, inj_trap_bytes());
#else
	memcpy(buffer, 0xe7f001f0, inj_trap_bytes());
#endif
	return LH_SUCCESS;
}
*/


/*
int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes){
	return sz / inj_opcode_bytes();
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

	LH_VERBOSE(3, "copying Arg 2 to r1.");
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

inline void lh_rset_fp(struct user *r, uintptr_t value) {
	r->regs.uregs[11] = value;
}

inline uintptr_t lh_rget_fp(struct user *r) {
	return r->regs.uregs[11];
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
