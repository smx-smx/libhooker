#include <stdio.h>
#include "lh_mod_common.h"
#include <sys/mman.h>

void (*original_test_function) (int a, char *b);

void hooked_autoinit_post(lh_main_process_t * proc) {
	LH_PRINT("This function is called after the wanted functions are hooked.");
}

int hooked_autoinit(lh_main_process_t * proc) {

	original_test_function = NULL;

	LH_PRINT("This function is intended to autorun at each time being injected to an executable.");
	LH_PRINT("At this time, we were injected into: %d (%s)", proc->pid, proc->exename);

	return LH_SUCCESS;
}

int hooked_otherfunction(int a, char *s) {
	LH_PRINT("Okay, other function is hooked too. %d, %s", a, s);
	// we dont call the original here.

	return 1;
}

int hooked_testfunction(int a, char *s) {
	LH_PRINT("We are in the hooked test function! %d %s", a, s);

	LH_PRINT("Lets call the original one with new parameters:");

	original_test_function(12345, "_____________________ IS THERE ANYBODY IN THERE?");

	LH_PRINT("Good, hah?\n\n");

	return 0;
}

lh_hook_t hook_settings = {
	.version = 1,
	.autoinit_pre = hooked_autoinit,
	.autoinit_post = hooked_autoinit_post,
	.fn_hooks =
	{
		{
			.hook_kind = LHM_FN_HOOK_BY_NAME,
			.libname = "",	// means the fn symbol should be defined in the main executable
			.symname = "otherfunction",
			.hook_fn = (uintptr_t) hooked_otherfunction,
			.orig_function_ptr = 0,
			.opcode_bytes_to_restore = 8
		},
		{
			.hook_kind = LHM_FN_HOOK_BY_NAME,
			.libname = "",
			.symname = "testfunction",
			.hook_fn = (uintptr_t) hooked_testfunction,
			.orig_function_ptr = (uintptr_t) & original_test_function, //save the original function address to "original_test_function"
			.opcode_bytes_to_restore = 8
		},
		{
			.hook_kind = LHM_FN_HOOK_TRAILING
		}
	}
};

/*
//--------------------------------------------------------------- dont care about these ones, was just testing
  LH_PRINT("Right before calling otherfunction()");
  otherfunction(1, proc->exename);

  void (*of)(int a, char*b);
  of = (void*) 0x00000000004006b1;
  of(1, proc->exename);
  LH_PRINT("Otherfunction() is theoritically called");

  void* addr = (void*)0x00400000;
  if (mprotect(addr, 0x01000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
    LH_PRINT("Page successfully modified made writeable");
  } else {
    LH_PRINT("couldnt modify page protection");
  }
*/
