#include "lh_module.h"
#include "interface/inject/inject_linux.h"

int inj_build_payload(
	pid_t r_pid,
	lh_fn_hook_t *fnh,
	struct ld_procmaps *lib_to_hook,
	uintptr_t symboladdr
)
{
	int result = -1;

	// Read remote code (max LHM_FN_COPY_BYTES bytes)
	uint8_t *remote_code = inj_blowdata(r_pid, symboladdr, LHM_FN_COPY_BYTES);
	if(remote_code == NULL){
		LH_PRINT("ERROR: Can't read code at 0x"LX, symboladdr);
		return -1;
	}

	size_t jumpSz;
	// Calculate the JUMP from Original to Replacement, so we can get the minimum size to save
	// We need this to avoid opcode overlapping (especially on Intel, where we can have variable opcode size)
	uint8_t *replacement_jump;	//original -> custom
	if(!(replacement_jump = inj_build_jump(fnh->hook_fn, 0, &jumpSz)))
		return -1;

	int num_opcode_bytes;
	if(fnh->opcode_bytes_to_restore > 0){
		// User specified bytes to save manually
		num_opcode_bytes = fnh->opcode_bytes_to_restore;
	} else {
		// Calculate amount of bytes to save (important for Intel, variable opcode size)
		num_opcode_bytes = inj_getbackup_size(remote_code, LHM_FN_COPY_BYTES, jumpSz);
	}

	if(num_opcode_bytes < 0){
		LH_ERROR("Cannot determine number of opcode bytes to save");
		LH_PRINT("Code size of %d bytes (LHM_NF_COPY_BYTES) may be too small", LHM_FN_COPY_BYTES);
		num_opcode_bytes = LHM_FN_COPY_BYTES;
	}
	LH_PRINT("Opcode bytes to save: %d", num_opcode_bytes);

	// Make sure code doesn't contain any PC-relative operation once moved to the new location
	inj_relocate_code(remote_code, num_opcode_bytes, symboladdr, lib_to_hook->mmap);

	//LH_PRINT("Copying %d original bytes to 0x"LX"", num_opcode_bytes, lib_to_hook->mmap);

	uint8_t *jump_back;			//custom -> original
	// JUMP from Replacement back to Original code (skip the original bytes that have been replaced to avoid loop)
	if(!(jump_back = inj_build_jump(symboladdr + num_opcode_bytes, 0, &jumpSz)))
		return -1;

	// Allocate space for the payload (code size + jump back)
	size_t payloadSz = num_opcode_bytes + jumpSz;
	remote_code = realloc(remote_code, payloadSz);
	if (!remote_code) {
		LH_ERROR_SE("realloc");
		if(remote_code)
			free(remote_code);
		return -1;
	}

	memcpy(remote_code + num_opcode_bytes, jump_back, jumpSz);

	//Write the payload to the process
	if (LH_SUCCESS != inj_copydata(r_pid, lib_to_hook->mmap, remote_code, payloadSz)) {
		LH_ERROR("Failed to copy payload bytes");
		goto end;
	}

	//Write the replacement jump to the process
	if (LH_SUCCESS != inj_copydata(r_pid, symboladdr, replacement_jump, jumpSz)) {
		LH_ERROR("Failed to copy replacement bytes");
		goto end;
	}

	/*if (lh_verbose > 3) {
		LH_VERBOSE(4, "Dumping the overwritten original function");
		lh_call_func(lh, &iregs, lhm_hexdump, "lhm_hexdump", symboladdr, 0x10);
		if(errno)
			break;

		LH_VERBOSE(4, "Dumping the corresponding payload area");
		lh_call_func(lh, &iregs, lhm_hexdump, "lhm_hexdump", remote_code, payloadSz);
		if(errno)
			break;
	}*/


	// Check we have enough room
	if (lib_to_hook->mmap + payloadSz > lib_to_hook->mmap_end) {
		LH_ERROR("Not enough memory!");
		result = -1;
		goto end;
	}


	// Copy payload to tracked program
	if (LH_SUCCESS != inj_copydata(r_pid, lib_to_hook->mmap, remote_code, payloadSz)) {
		LH_ERROR("Unable to copy payload");
		goto end;
	}

	LH_PRINT("Payload Built! 0x"LX" -> 0x"LX" -> 0x"LX" -> 0x"LX"",
		symboladdr, fnh->hook_fn, lib_to_hook->mmap, symboladdr + num_opcode_bytes);

	result = LH_SUCCESS;

	end:
		if(remote_code)
			free(remote_code);
		return result;
}
