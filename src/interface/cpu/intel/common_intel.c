#include "interface/cpu/cpu_intel.h"

inline int inj_trap_bytes(){
	return 1;
}

int inj_build_trap(uint8_t *buffer){
	buffer[0] = 0xCC; //int 3
	return LH_SUCCESS;
}

int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes){
	csh handle;
	cs_insn *insn;
	#if __i386__
		if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
			goto err_open;
	#elif __x86_64__
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			goto err_open;
	#endif

	size_t count, i;
	count = cs_disasm(handle, buf, sz, 0x0, 0, &insn);
	if(count < 0)
		goto err_disasm;

	if(validbytes == NULL)
		goto ret;

	*validbytes = 0;
	for(i=0; i<count; i++){
		*validbytes += insn[i].size;
	}
	
	ret:
		cs_free(insn, count);
		return count;

	err_open:
		LH_ERROR("cs_open failed!");
		return -1;
	err_disasm:
		LH_ERROR("cs_disasm failed!");
		cs_close(&handle);
		return -1;
}