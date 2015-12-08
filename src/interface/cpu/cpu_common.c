#include "interface/if_inject.h"
#include "interface/if_cpu.h"

size_t inj_getjmp_size(){
	#ifdef LH_JUMP_ABS
		return inj_absjmp_opcode_bytes();
	#else
		return inj_reljmp_opcode_bytes();
	#endif
}

uint8_t *inj_build_jump(uintptr_t dstAddr, uintptr_t srcAddr, size_t *jumpSzPtr){
	size_t jumpSz = inj_getjmp_size();
	uint8_t *buffer = calloc(jumpSz, 1);
	if(!buffer)
		return NULL;
	#ifdef LH_JUMP_ABS
		if(inj_build_abs_jump(buffer, dstAddr, srcAddr) != LH_SUCCESS)
			goto error;
	#else
		if(inj_build_rel_jump(buffer, dstAddr, srcAddr) != LH_SUCCESS)
			goto error;
	#endif
	if(jumpSzPtr)
		*jumpSzPtr = jumpSz;
	lh_hexdump("jump", buffer, jumpSz);
	return buffer;
	error:
		free(buffer);
		return NULL;
}

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
		int totalBytes = 0;
		int total_insn = inj_getinsn_count(codePtr, payloadSz, &totalBytes);
		if(total_insn <= 0 || totalBytes == 0)
			return -1;
		int _payloadSz = payloadSz;
		while(totalBytes < payloadSz){
			inj_getinsn_count(codePtr, ++_payloadSz, &totalBytes);
			LH_PRINT("VALID: %d  REQUIRED: %d", totalBytes, payloadSz);
		}
		return totalBytes;
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
