#include "interface/if_cpu.h"

int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes){
	csh handle;
	cs_insn *insn;
	#if __i386__
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
	#elif __x86_64__
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
	#elif __arm__
	if (cs_open(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK)
	#endif
		goto err_open;

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

int inj_getbackup_size(uint8_t *codePtr, size_t codeSz, size_t payloadSz){
	int i = 0, opSz;
	if((opSz = inj_opcode_bytes()) > 0){ //fixed opcode size
		while(i < payloadSz)
			i += opSz;
		return i;
	} else { //dynamic opcode size
		int valid = 0; //total number of valid opcode bytes
		for(i=1; i<codeSz; i++){
			//disassemble a byte at a time
			int _valid = 0; //numer of valid opcode bytes
			if(inj_getinsn_count(codePtr, i, &_valid) < 0)
				return -1;
			LH_VERBOSE(3, "VALID %2d READ %2d REQUIRED %2d", valid, i-1, payloadSz);
			if(valid >= payloadSz)
				return valid;
			valid += _valid;
			codePtr += _valid;
		}
	}
	return -1;
}

/*
 * Relocates code pointed by codePtr from sourcePC to destPC
 */
#if !defined(__i386__) && !defined(__x86_64__)
int inj_relocate_code(uint8_t *codePtr, size_t codeSz, uintptr_t sourcePC, uintptr_t destPC){
	return LH_SUCCESS;
}
#endif
