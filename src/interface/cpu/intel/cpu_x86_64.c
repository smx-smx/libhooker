#include "interface/if_inject.h"
#include "interface/if_cpu.h"
#include "interface/cpu/cpu_intel.h"

//------------------------------------------ x86 begin
inline int inj_opcode_bytes(){
	return -1;
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

inline void lh_rset_fp(struct user *r, uintptr_t value) {
	r->regs.rbp = value;
}

inline uintptr_t lh_rget_fp(struct user *r) {
	return r->regs.rbp;
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
