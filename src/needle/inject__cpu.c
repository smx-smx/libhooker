#include "interface/if_cpu.h"

size_t inj_getjmp_size(){
	#ifdef LH_JUMP_ABS
		return inj_absjmp_opcode_bytes();
	#else
		return inj_reljmp_opcode_bytes();
	#endif
}

int inj_build_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address){
	#ifdef LH_JUMP_ABS
		return inj_build_abs_jump(buffer, jump_destination, jump_opcode_address);
	#else
		return inj_build_rel_jump(buffer, jump_destination, jump_opcode_address);
	#endif
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
