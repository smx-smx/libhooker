#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>

#include "needle.h"
#include "inject.h"

#if __x86_64__
#    include "inject_x64.cx"
#elif __i386__
#    include "inject_i386.cx"
#elif __arm__
#    include "inject_arm.cx"
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