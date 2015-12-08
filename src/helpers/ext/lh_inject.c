#include "lh_module.h"
#include "helpers/lh_inject.h"

int unprotect(void *addr) {
	// Move the pointer to the page boundary
	int page_size = getpagesize();
	addr -= (unsigned long)addr % page_size;

	if(mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
			LH_ERROR_SE("mprotect");
	    return -1;
	}

	return 0;
}

int inj_inject_payload(lh_fn_hook_t *fnh, uintptr_t symboladdr){
	size_t jumpSz;
	// Calculate the JUMP from Original to Replacement, so we can get the minimum size to save
	// We need this to avoid opcode overlapping (especially on Intel, where we can have variable opcode size)
	uint8_t *replacement_jump;	//original -> custom
	if(!(replacement_jump = inj_build_jump(fnh->hook_fn, 0, &jumpSz)))
		return -1;

	if( unprotect((void *)symboladdr) < 0)
			return -1;

	memcpy((void *)symboladdr, replacement_jump, jumpSz);

	return LH_SUCCESS;
}

/*
 * Same as needle variant, but we don't need to copy data back and forth
 */
void *inj_build_payload_user(lh_fn_hook_t *fnh, uintptr_t symboladdr){
	uint8_t *original_code = (uint8_t *)symboladdr;
	if(original_code == NULL){
		LH_PRINT("ERROR: Code Address not specified");
		return NULL;
	}

	int num_opcode_bytes;
	if(fnh->opcode_bytes_to_restore > 0){
		// User specified bytes to save manually
		num_opcode_bytes = fnh->opcode_bytes_to_restore;
	} else {
		// Calculate amount of bytes to save (important for Intel, variable opcode size)
		// NOTE: original_code being passed is just a random address to calculate a jump size (for now)
		num_opcode_bytes = inj_getbackup_size(original_code, LHM_FN_COPY_BYTES, inj_getjmp_size((uintptr_t)original_code));
	}

	if(num_opcode_bytes < 0){
		LH_ERROR("Cannot determine number of opcode bytes to save");
		LH_PRINT("Code size of %d bytes (LHM_NF_COPY_BYTES) may be too small", LHM_FN_COPY_BYTES);
		num_opcode_bytes = LHM_FN_COPY_BYTES;
	}
	LH_PRINT("Opcode bytes to save: %d", num_opcode_bytes);

	size_t jumpSz;
	uint8_t *jump_back;			//custom -> original
	// JUMP from Replacement back to Original code (skip the original bytes that have been replaced to avoid loop)
	if(!(jump_back = inj_build_jump(symboladdr + num_opcode_bytes, 0, &jumpSz)))
		return NULL;

	// Allocate space for the payload (code size + jump back)
	// Unlike needle variant, we call mmap here, as we're in the user process
	size_t payloadSz = num_opcode_bytes + jumpSz;

	void *pMem = mmap(0, payloadSz, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(pMem == MAP_FAILED){
		LH_ERROR_SE("mmap");
		return NULL;
	}
	uint8_t *remote_code = (uint8_t *)pMem;

	memcpy(remote_code, original_code, num_opcode_bytes);
	// Make sure code doesn't contain any PC-relative operation once moved to the new location
	inj_relocate_code(remote_code, num_opcode_bytes, symboladdr, (uintptr_t)pMem);
	memcpy(remote_code + num_opcode_bytes, jump_back, jumpSz);

	LH_PRINT("Payload Built! 0x"LX" -> 0x"LX" -> 0x"LX" -> 0x"LX"",
		symboladdr, fnh->hook_fn, pMem, symboladdr + num_opcode_bytes);

	return pMem;
}
