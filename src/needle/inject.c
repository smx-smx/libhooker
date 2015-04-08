#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>
#include <dlfcn.h>

#include "needle.h"
#include "inject.h"
#include "lh_mod_common.h"

#define MMAP_SIZE 0x1000 //4096 bytes

/*
 *
 */
static int inj_gather_functions(lh_session_t * lh) {
	struct ld_procmaps *lib_ld = NULL;
	struct ld_procmaps *lib_dl = NULL;
	struct ld_procmaps *lib_c = NULL;

	bool ld_found = false;
	bool c_found = false;
	bool dl_found = false;
	if (!lh)
		return -1;
	if (lh->ld_maps_num <= 0)
		return -1;

#define LIBNAME_LD "ld"
#define LIBNAME_LIBC "libc"
#define LIBNAME_LIBDL "libdl"
#undef LD_PROCMAPS_FIND_LIB
#define LD_PROCMAPS_FIND_LIB(name,flag,alib,retval) \
do { \
        LH_VERBOSE(2, "Checking if %s exists in procmaps.", name);\
        if (ld_find_library(lh->ld_maps, lh->ld_maps_num, \
                                                name, flag, alib) < 0) { \
                LH_VERBOSE(1, "%s not mapped.", name); \
                retval = false; \
        } else { \
                retval = true; \
                LH_VERBOSE(1,  "Found %s", name); \
        } \
} while (0)
#undef LD_LIB_FIND_FN_ADDR
#define LD_LIB_FIND_FN_ADDR(fn,outfn,alib) \
do { \
        if (outfn) break; \
        outfn = ld_find_address(alib, fn, NULL); \
        if (outfn != 0) { \
                LH_VERBOSE(1,"Found %s at 0x"LX" in %s",  fn, outfn, index); \
        } else { \
                LH_VERBOSE(1, "%s not found in %s.", fn, index); \
        } \
} while (0)
	if (lh->exe_interp.name) {
		LD_PROCMAPS_FIND_LIB(lh->exe_interp.name, true, &lib_ld, ld_found);
	}
	if (!ld_found) {
		LH_VERBOSE(1, "No interpreter found. Guessing.");
		LD_PROCMAPS_FIND_LIB(LIBNAME_LD, false, &lib_ld, ld_found);
	}
	LD_PROCMAPS_FIND_LIB(LIBNAME_LIBC, false, &lib_c, c_found);
	LD_PROCMAPS_FIND_LIB(LIBNAME_LIBDL, false, &lib_dl, dl_found);

	if (c_found) {
		LD_LIB_FIND_FN_ADDR("malloc", lh->fn_malloc, lib_c);
		LD_LIB_FIND_FN_ADDR("realloc", lh->fn_realloc, lib_c);
		LD_LIB_FIND_FN_ADDR("free", lh->fn_free, lib_c);
	}
	if (ld_found) {
		LD_LIB_FIND_FN_ADDR("malloc", lh->fn_malloc, lib_ld);
		LD_LIB_FIND_FN_ADDR("realloc", lh->fn_realloc, lib_ld);
		LD_LIB_FIND_FN_ADDR("free", lh->fn_free, lib_ld);
	}
	if (!lh->fn_malloc || !lh->fn_realloc || !lh->fn_free) {
		LH_ERROR("Some memory allocation routines are unavailable. Cannot proceed.");
		return -1;
	}
	if (dl_found) {
		LD_LIB_FIND_FN_ADDR("dlopen", lh->fn_dlopen, lib_dl);
		LD_LIB_FIND_FN_ADDR("dlclose", lh->fn_dlclose, lib_dl);
		LD_LIB_FIND_FN_ADDR("dlsym", lh->fn_dlsym, lib_dl);
	} else {
		LD_LIB_FIND_FN_ADDR("__libc_dlopen_mode", lh->fn_dlopen, lib_c);
		LD_LIB_FIND_FN_ADDR("__libc_dlclose", lh->fn_dlclose, lib_c);
		LD_LIB_FIND_FN_ADDR("__libc_dlsym", lh->fn_dlsym, lib_c);
	}
/*
// TODO:
        if (!lh->fn_dlopen || !lh->fn_dlsym) {
                android_way(lh);
                return -1;
        }
*/

	if (!lh->fn_dlopen) {		// || !lh->fn_dlsym)
		LH_ERROR("Dynamic Library loading routines were not found. Cannot proceed.");

		return -1;
	}

#undef LD_PROCMAPS_FIND_LIB
#undef LD_LIB_FIND_FN_ADDR
	return LH_SUCCESS;
}

/*
 *
 */
static int inj_process(lh_session_t * lh) {
	int rc = LH_SUCCESS;
	do {
		pid_t pid = lh->proc.pid;
		char filename[PATH_MAX];
		if (pid <= 0) {
			LH_ERROR("Invalid pid");
			rc = -3;
			break;
		}
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename), "/proc/%d/exe", pid);
		LH_VERBOSE(2, "Exe symlink for pid %d : %s", pid, filename);

		readlink(filename, lh->proc.exename, PATH_MAX);

		lh->is64 = HOTPATCH_EXE_IS_NEITHER;
		lh->exe_symbols = exe_load_symbols(filename, &lh->exe_symbols_num, &lh->exe_entry_point, &lh->exe_interp, &lh->is64);
		if (!lh->exe_symbols) {
			LH_ERROR("Unable to find any symbols in exe.");
			rc = -2;
			break;
		}
		if (lh->exe_entry_point == 0) {
			LH_ERROR("Entry point is 0. Invalid.");
			rc = -1;
			break;
		}
		LH_VERBOSE(1, "Executable headers are loaded");
		lh->ld_maps = ld_load_maps(lh->proc.pid, &lh->ld_maps_num);
		if (!lh->ld_maps) {
			LH_PRINT("ERROR: Unable to load data in /proc/%d/maps.", pid);
			rc = -1;
			break;
		}
		LH_VERBOSE(2, "/proc/%d/maps loaded.", pid);
		if (lh->exe_symbols && lh->exe_symbols_num > 0) {
			qsort(lh->exe_symbols, lh->exe_symbols_num, sizeof(*lh->exe_symbols), elf_symbol_cmpqsort);
		}

		if (LH_SUCCESS != inj_gather_functions(lh)) {
			LH_ERROR("Unable to find all the functions needed. Cannot proceed.");
			rc = -1;
			break;
		}

	} while (0);
	return rc;
}

/*
 * Continues execution of a paused process
 */
static int inj_exec(pid_t pid) {
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		LH_ERROR_SE("Ptrace Continue failed");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Waits for a trap or termination signal
 */
static int inj_wait(pid_t pid) {
	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		LH_ERROR("Waitpid failed");
		return -1;
	}
	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		LH_ERROR("Process was terminated.");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Fetches and returns the registers of the tracked pid
 */
static int inj_get_regs(pid_t pid, struct user *regs) {
	if (!regs)
		return -1;
	memset(regs, 0, sizeof(*regs));
	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
		LH_ERROR_SE("Ptrace Getregs failed");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Sets the registers of the tracked pid from *regs
 */
static int inj_set_regs(pid_t pid, const struct user *regs) {
	if (!regs)
		return -1;
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
		LH_ERROR_SE("Ptrace Setregs failed");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Creates and returns a new empty session (lh_session_t)
 */
lh_session_t *lh_alloc() {
	lh_session_t *re = (lh_session_t *) malloc(sizeof(lh_session_t));
	if (!re) {
		LH_ERROR_SE("malloc");
		return NULL;
	}
	memset(re, 0, sizeof(*re));

	return re;
}

/*
 * Attaches ptrace to the running process specified by the pid "pid"
 */
int lh_attach(lh_session_t * session, pid_t pid) {
	int re = LH_SUCCESS;
	do {
		session->proc.pid = pid;

		if (LH_SUCCESS != (re = inj_process(session)))
			break;

		// printf("sizeof lh: %d %d\n", sizeof(*session), sizeof(lh_main_process_t));return -1;

		LH_VERBOSE(1, "Attaching to pid %d", pid);

		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
			LH_ERROR_SE("ptrace attach");
			re = -2;
			break;
		}

		LH_VERBOSE(2, "Waiting...");
		if (LH_SUCCESS != inj_wait(session->proc.pid))
			break;

		// make a copy of the registers at attach time and store them in the session
		if (LH_SUCCESS != (re = inj_get_regs(pid, &(session->original_regs))))
			break;

		lh_dump_regs(&(session->original_regs));
	} while (0);

	if (re != LH_SUCCESS)
		session->proc.pid = 0;

	return re;
}

/*
 * Frees a session object
 */
void lh_free(lh_session_t ** session) {
	if (session == NULL)
		return;

	if (*session != NULL)
		free(*session);

	*session = NULL;
}

/*
 * Detaches ptrace from the tracked pid
 */
int lh_detach(lh_session_t * session) {

	pid_t pid = session->proc.pid;

	if (LH_SUCCESS != inj_set_regs(pid, &(session->original_regs)))
		return 2;

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		LH_ERROR_SE("detach");
		return 1;
	}

	return LH_SUCCESS;
}

/*
 * set, exec, wait, get
 * - Sets the tracked pid registers with the values in "iregs"
 * - Steps once in the tracked pid
 * - Waits till the step is complete
 * - Gets the new registers values
 *
 * The "fn" field is actually unused
 */
int inj_setexecwaitget(lh_session_t * lh, const char *fn, struct user *iregs) {
	int rc = LH_SUCCESS;
	do {
		LH_VERBOSE(1, "Setting registers and invoking %s.", fn);
		if ((rc = inj_set_regs(lh->proc.pid, iregs)) != LH_SUCCESS)
			break;
		LH_VERBOSE(2, "Executing..");
		if ((rc = inj_exec(lh->proc.pid)) != LH_SUCCESS)
			break;
		LH_VERBOSE(2, "Waiting...");
		if ((rc = inj_wait(lh->proc.pid)) != LH_SUCCESS)
			break;
		LH_VERBOSE(2, "Getting registers.");
		if ((rc = inj_get_regs(lh->proc.pid, iregs)) != LH_SUCCESS)
			break;
	} while (0);

	return rc;
}

/*
 * Reads memory in the tracked pid at the address specified by "src_in_remote"
 * Stores the data in the address pointed by "outpeek"
 */
static int inj_peekdata(pid_t pid, uintptr_t src_in_remote, uintptr_t *outpeek) {
	int err = 0;
	long peekdata = ptrace(PTRACE_PEEKDATA, pid, src_in_remote, NULL);
	err = errno;
	LH_VERBOSE(3, "Peekdata: %p", (void *)peekdata);
	if (peekdata == -1 && err != 0) {
		LH_ERROR_SE("Ptrace PeekText failed with error");
		return -1;
	}
	if (outpeek)
		*outpeek = peekdata;
	else
		LH_ERROR("Invalid arguments.");
	return outpeek ? LH_SUCCESS : -1;
}

/*
 * Stores "datasz" bytes from "data" into the tracked pid in the address pointed by "target"
 */
static int inj_copydata(pid_t pid, uintptr_t target, const unsigned char *data, size_t datasz) {
	size_t pos = 0;
	size_t idx = 0;
	while (pos < datasz) {

		size_t pokedata = 0, jdx = 0;

		// !SAFETY!
		if (pos + sizeof(uintptr_t) > datasz) {

			int err = 0;
			pokedata = ptrace(PTRACE_PEEKDATA, pid, target + idx, NULL);
			err = errno;
			LH_VERBOSE(3, "Peekdata: %p", (void *)pokedata);
			if (pokedata == -1 && err != 0) {
				LH_ERROR_SE("Ptrace PeekText failed with error");
				return -1;
			}
			// LH_VERBOSE(4, "prefetched for pokedata: %p", pokedata);
		}

		const size_t pksz = sizeof(size_t);
		for (jdx = 0; jdx < pksz && pos < datasz; ++jdx)
			((unsigned char *)&pokedata)[jdx] = data[pos++];

		LH_VERBOSE(3, "Pokedata: %p", pokedata);
		if (ptrace(PTRACE_POKEDATA, pid, target + idx, pokedata) < 0) {
			LH_ERROR_SE("Ptrace PokeText failed with error");
			return -1;
		}
		idx += sizeof(size_t);
	}
	return LH_SUCCESS;
}

/*
 * Reads "datasz" bytes of data from "src_in_remote" addres in the tracked pid
 * Allocates and returns a pointer to memory containing the read data
 */
static void *inj_blowdata(pid_t pid, uintptr_t src_in_remote, size_t datasz) {
	void *re = malloc(datasz);
	if (re != NULL) {

		uintptr_t *a = (uintptr_t *) re;
		uintptr_t aaddress = src_in_remote;
		uintptr_t aread;
		size_t read = 0;
		while (read < datasz) {
			if (LH_SUCCESS != inj_peekdata(pid, aaddress, &aread))
				return NULL;

			*a = aread;
			a += 1;
			aaddress += sizeof(uintptr_t);
			read += sizeof(uintptr_t);
		}
	} else {
		LH_ERROR_SE("malloc");
	}
	return re;
}

/*
 * Stores data in "pokedata" in the tracked pid at address "target_in_remote"
 * Size of the data is the pointer size on the host machine
 */
int inj_pokedata(pid_t pid, uintptr_t target_in_remote, uintptr_t pokedata) {
	int err = 0;
	LH_VERBOSE(3, "Pokedata: %p", (void *)pokedata);
	if (ptrace(PTRACE_POKEDATA, pid, target_in_remote, (void *)pokedata) < 0) {
		LH_ERROR_SE("Ptrace PokeText failed with error", pid, strerror(err));
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Calls mmap in the tracked pid
 */
void inj_find_mmap(lh_session_t * lh, struct user *iregs, struct ld_procmaps *lib_to_hook, uintptr_t lhm_mmap, uintptr_t lhm_munmap) {
	int i;
	for (i = 1; i <= 8192; i++)	// 4096*4096 => +-16 MBytes
	{
		if (lib_to_hook->mmap)
			return;

		int64_t offset = ((i >= 4096 ? i - 4095 : -1 * i) * MMAP_SIZE);
		int64_t address = (int64_t) lib_to_hook->addr_begin;
		address = address + offset;
		if (address < 16384)
			continue;

		uintptr_t wanted_address = (uintptr_t) address;
		LH_VERBOSE(4, "Wanted address for mmap: " LX, wanted_address);

		int rc;
		// Pause the process
		if ((rc = inj_trap(lh->proc.pid, iregs)) != LH_SUCCESS)
			break;
		// Encode call to mmap with address and size
		if ((rc = inj_pass_args2func(iregs, lhm_mmap, wanted_address, MMAP_SIZE)) != LH_SUCCESS)
			break;
		// Run the call and wait for completion
		if ((rc = inj_setexecwaitget(lh, "lhm_mmap", iregs)) != LH_SUCCESS)
			break;

		uintptr_t returned = lh_rget_ax(iregs);
		LH_VERBOSE(2, "returned: " LX, returned);

		// If the memory has been mapped at the wanted address
		if (returned == wanted_address) {
			lib_to_hook->mmap = returned;
			lib_to_hook->mmap_begin = lib_to_hook->mmap;
			lib_to_hook->mmap_end = lib_to_hook->mmap_begin + MMAP_SIZE;
			return;
		}
		// The OS allocated memory somewhere else, we just dont want it.
		if ((rc = inj_trap(lh->proc.pid, iregs)) != LH_SUCCESS)
			break;
		if ((rc = inj_pass_args2func(iregs, lhm_munmap, returned, MMAP_SIZE)) != LH_SUCCESS)
			break;
		if ((rc = inj_setexecwaitget(lh, "lhm_munmap", iregs)) != LH_SUCCESS)
			break;
	}

}

/*
 * Loads a library shared object (module) in the target (must be built with -fPIC!)
 * lh			=> Session object
 * dll			=> Path of the library to load
 * out_libaddr	=> (optional) Where to store the address of the loaded library (relative in the tracked process)
 */
int lh_inject_library(lh_session_t * lh, const char *dll, uintptr_t *out_libaddr) {
	LH_PRINT("Loading: %s into %d (%s)", dll, lh->proc.pid, lh->proc.exename);

	size_t dllsz = 0;
	size_t tgtsz = 0;
	size_t procsz = 0;
	int rc = LH_SUCCESS;
	
	uintptr_t dlopen_handle;
	bool oneshot = true;
	
	unsigned char *mdata = NULL;

	/* calculate the size to allocate */
	dllsz = strlen(dll) + 1;
	procsz = sizeof(lh_main_process_t);
	tgtsz = dllsz + procsz + 32;	/* general buffer */
	tgtsz = (tgtsz > 1024) ? tgtsz : 1024;

	/* align the memory */
	tgtsz += (tgtsz % sizeof(void *) == 0) ? 0 : (sizeof(void *) - (tgtsz % sizeof(void *)));
	mdata = calloc(sizeof(unsigned char), tgtsz);
	if (!mdata) {
		LH_ERROR_SE("malloc");
		return -1;
	}
	memcpy(mdata, dll, dllsz);
	memcpy(mdata + dllsz + 1, &(lh->proc), procsz);
	LH_VERBOSE(1, "Allocating " LU " bytes in the target.\n", tgtsz);

	do {
		uintptr_t result = 0;
		uintptr_t heap = 0;
		uintptr_t stack[4] = { 0, 0, 0, 0 };	/* max arguments of the functions we
												   are using */
		int idx = 0;

		struct user oregs;
		struct user iregs;

		// Get original registers from the tracked process
		LH_VERBOSE(2, "Getting original registers.");
		if ((rc = inj_get_regs(lh->proc.pid, &oregs)) != LH_SUCCESS)
			break;

		// Make a copy of the registers
		memcpy(&iregs, &oregs, sizeof(struct user));

		// Get a copy the stack. Ignore the redzone as it includes local, volatile function data
		lh_rset_sp(&iregs, lh_rget_sp(&iregs) - lh_redzone());
		LH_VERBOSE(2, "Copying stack out.");

		for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
			if ((rc = inj_peekdata(lh->proc.pid, lh_rget_sp(&iregs) + idx * sizeof(size_t), &stack[idx])) != LH_SUCCESS)
				break;
			if ((rc = inj_pokedata(lh->proc.pid, lh_rget_sp(&iregs) + idx * sizeof(size_t), (uintptr_t)0)) != LH_SUCCESS)
				break;
		}
		if (rc < 0){
			break; //something went wrong
		}

		/* We're now going to call malloc to allocate the path of the library we want to load */

		// Pause the process
		if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
			break;
		// Encode call to malloc
		if ((rc = inj_pass_args2func(&iregs, lh->fn_malloc, tgtsz, 0)) != LH_SUCCESS)
			break;
		lh_dump_regs(&iregs);
		// Call malloc and wait for completion
		if ((rc = inj_setexecwaitget(lh, "malloc", &iregs)) != LH_SUCCESS)
			break;
		lh_dump_regs(&iregs);
		// Get the malloc result
		heap = result = lh_rget_ax(&iregs);
		if(!result){
			LH_ERROR("malloc failed!\n");
			break;
		}

		// Copy the path to the target process
		LH_VERBOSE(2, "Copying " LU " bytes to 0x" LX, tgtsz, result);
		if (!result)
			break;
		// Copy "mdata" to the address of the allocated memory (held in "result" from the previous malloc call)
		if ((rc = inj_copydata(lh->proc.pid, result, mdata, tgtsz)) != LH_SUCCESS)
			break;

		// Stop the process again
		if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
			break;
		// Encode call to dlopen
		if ((rc = inj_pass_args2func(&iregs, lh->fn_dlopen, result, (RTLD_LAZY | RTLD_GLOBAL))) != LH_SUCCESS)
			break;
		// Call dlopen and wait for completion
		if ((rc = inj_setexecwaitget(lh, "dlopen", &iregs)) != LH_SUCCESS)
			break;
		// Get the dlopen result
		dlopen_handle = lh_rget_ax(&iregs);
		LH_VERBOSE(1, "Dll opened at 0x" LX, dlopen_handle);
		if(!dlopen_handle){
			LH_ERROR("dlopen failed: pathname %s cannot be found\n", heap);
			break;
		}
		if (out_libaddr)
			*out_libaddr = dlopen_handle;

		/* 
			Verify that the library load succeded by probung /proc/<pid>/maps,
			<pid> is the pid of the process we're tracking
		*/
		do {
			// Get a new copy of the maps after the lib load
			lh->ld_maps = ld_load_maps(lh->proc.pid, &lh->ld_maps_num);

			struct ld_procmaps *lib_just_loaded;
			// Iterate the maps looking for "dll" (the library path)
			if (ld_find_library(lh->ld_maps, lh->ld_maps_num, dll, true, &lib_just_loaded) != LH_SUCCESS) {
				LH_ERROR("Couldnt find the loaded library in proc/maps");
				break;
			}

			/*
				We're now going to check the existance of the hook_settings structure by looking for its symbol
			*/

			LH_VERBOSE(2, "We found the library just loaded");
			size_t size;
			uintptr_t outfn = ld_find_address(lib_just_loaded, "hook_settings", &size);
			if (outfn == 0) {
				LH_ERROR("hook_settings symbol not found");
				break;
			}

			LH_VERBOSE(2, "hook_settings found at " LX ", size %d", outfn, size);

			lh_hook_t *hook_settings = (lh_hook_t *) inj_blowdata(lh->proc.pid, outfn, size);
			if (hook_settings == NULL) {
				LH_ERROR("Couldnt retrieve hook_settings symbol");
				break;
			}

			LH_VERBOSE(1, "Hook settings found, v%d", hook_settings->version);

			// For future versions of the structure
			if (hook_settings->version != 1) {
				LH_ERROR("hook_settings version is not supported");
				break;
			}

			uintptr_t ttyptr = 0;
			if(g_tty != NULL){
				LH_VERBOSE(2, "Copying tty name to target...");
				size_t sz = strlen(g_tty) + 1;
				if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
					break;
				if ((rc = inj_pass_args2func(&iregs, (uintptr_t) lh->fn_malloc, sz, 0)) != LH_SUCCESS)
					break;
				if ((rc = inj_setexecwaitget(lh, "malloc", &iregs)) != LH_SUCCESS)
					break;
				
				ttyptr = result = lh_rget_ax(&iregs);
				if(!result){
					LH_ERROR("malloc failed!\n");
					break;
				}
				if ((rc = inj_copydata(lh->proc.pid, ttyptr, (const unsigned char *)g_tty, sz)) != LH_SUCCESS)
					break;
			}
			
			// Call autoinit_pre before hook (if specified in the settings)
			if (hook_settings->autoinit_pre != NULL) {
				LH_VERBOSE(2, "Calling autoinit_pre " LX, hook_settings->autoinit_pre);
				if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
					break;
				if ((rc = inj_pass_args2func(&iregs, (uintptr_t) hook_settings->autoinit_pre, heap + dllsz + 1, ttyptr)) != LH_SUCCESS)
					break;
				if ((rc = inj_setexecwaitget(lh, "autoinit_pre", &iregs)) != LH_SUCCESS)
					break;
				LH_VERBOSE(2, "Registers after call");
				//lh_dump_regs(&iregs);
				result = lh_rget_ax(&iregs);
				LH_VERBOSE(2, "returned: %d", (int)result);

				if (result != LH_SUCCESS) {
					LH_VERBOSE(1, "Not continuing, autoinit_pre is not successful");
					break;
				}
			}

			/*
				Every module is equipped with
					lhm_helper.c
					lh_common.c
				Those files provide wrappers to basic functions
				
				We do some checks to ensure those functions are present in the loaded library/module
			*/
			uintptr_t lhm_mmap = ld_find_address(lib_just_loaded, "lhm_mmap", NULL);
			if (lhm_mmap == 0) {
				LH_ERROR("lhm_mmap not found");
				break;
			}

			uintptr_t lhm_munmap = ld_find_address(lib_just_loaded, "lhm_munmap", NULL);
			if (lhm_munmap == 0) {
				LH_ERROR("lhm_munmap not found");
				break;
			}

			uintptr_t lhm_memcpy = ld_find_address(lib_just_loaded, "lhm_memcpy", NULL);
			if (lhm_memcpy == 0) {
				LH_ERROR("lhm_memcpy not found");
				break;
			}

			uintptr_t lhm_hexdump = ld_find_address(lib_just_loaded, "lhm_hexdump", NULL);
			if (lhm_hexdump == 0) {
				LH_ERROR("lhm_hexdump not found");
				break;
			}

			int hook_successful = 0;

			uintptr_t hookend = (uintptr_t) hook_settings + size;
			int fni = 0;
			lh_fn_hook_t *fnh = &(hook_settings->fn_hooks[0]);
			LH_VERBOSE(4, "Function hooks: " LX " / " LX " (size " LX ")", (uintptr_t) fnh, hookend, (int)size);
			// For every hook definition
			while ((uintptr_t) fnh < hookend) {

				hook_successful = 0;

				if (fnh->hook_kind == LHM_FN_HOOK_TRAILING){
					break;
				}

				if (!fnh->hook_fn) {
					LH_PRINT("ERROR: hook_settings->fn_hooks[%d], hook_fn is null", fni);
					break;
				}

				LH_VERBOSE(1, "Function hook libname: %s, symbol: %s, offset: " LX ", opcode bytes to restore: %d", fnh->libname, fnh->symname,
																													fnh->sym_offset, fnh->opcode_bytes_to_restore);
				LH_VERBOSE(3, "The replacement function: " LX, fnh->hook_fn);

				// Locate the library specified in the hook section (if any)
				struct ld_procmaps *lib_to_hook;
				if (ld_find_library(lh->ld_maps, lh->ld_maps_num, fnh->libname, false, &lib_to_hook) != LH_SUCCESS) {
					LH_ERROR("Couldnt find the loaded library in proc/maps");
					break;
				}

				uintptr_t symboladdr = 0;
				if (fnh->hook_kind == LHM_FN_HOOK_BY_NAME) {
					symboladdr = ld_find_address(lib_to_hook, fnh->symname, NULL);
				} else if (fnh->hook_kind == LHM_FN_HOOK_BY_OFFSET) {
					symboladdr = lib_to_hook->addr_begin + fnh->sym_offset;
				}

				if (symboladdr == 0) {
					LH_PRINT("ERROR: hook_settings->fn_hooks[%d] was not found.", fni);
					break;
				}

				// Get the number of bytes required to build an absolute jump
				int abs_jump_size = inj_absjmp_opcode_bytes();
				// Get the number of bytes required to build a relative jump
				int rel_jump_size = inj_reljmp_opcode_bytes();
				// Check that the user provided enough bytes to replace in the hook settings
				if (fnh->opcode_bytes_to_restore < rel_jump_size) {
					LH_PRINT("ERROR: we need to overwrite %d bytes (%d bytes of opcode to restore specified)", rel_jump_size, fnh->opcode_bytes_to_restore);
					break;
				}

				//If we haven't allocated a payload buffer yet
				if (lib_to_hook->mmap == 0)
					// Allocate MMAP_SIZE bytes for our payload
					inj_find_mmap(lh, &iregs, lib_to_hook, lhm_mmap, lhm_munmap);

				if (lib_to_hook->mmap == 0) {
					LH_ERROR("mmap did not work :(");
					break;
				}

				/*
					We now have an empty 4MB (MMAP_SIZE) memory region.
					We proceed as following:
					-> Create a backup of the first 16 bytes (LHM_FN_COPY_BYTES) of the original function, and store it in the map. The map now contains a part of the original function code
					-> Go after opcode_bytes_to_restore in the new map, and place a relative jump to the remaining part of the code (in the original address space)
					-> After this relative jump, place the absolute jump to the replacement code address in the lib/module.
					-> Create a jump trampoline, to make a near jump to the absolute jump, that will in turn jump to the replacement code. Store this trampoline in the original addres,
					   Overwriting the original code
				*/

				uintptr_t r_payload_start = lib_to_hook->mmap;
				size_t hook_area = fnh->opcode_bytes_to_restore + rel_jump_size + abs_jump_size;
				uintptr_t mmap_after_hooked = lib_to_hook->mmap + hook_area;

				if ((mmap_after_hooked > lib_to_hook->mmap_end) || (lib_to_hook->mmap + LHM_FN_COPY_BYTES > lib_to_hook->mmap_end)) {
					LH_PRINT("ERROR: not enough memory for hook_settings->fn_hooks[%d]", fni);
					break;
				}

				// Copy LHM_FN_COPY_BYTES bytes (16) of the original function to mmapped area
				if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
					break;
				if ((rc = inj_pass_args2func(&iregs, lhm_memcpy, lib_to_hook->mmap, symboladdr)) != LH_SUCCESS) // lh_memcpy has size hardcoded to value defined in LHM_FN_COPY_BYTES
					break;
				if ((rc = inj_setexecwaitget(lh, "lhm_memcpy", &iregs)) != LH_SUCCESS)
					break;
				if (lib_to_hook->mmap != lh_rget_ax(&iregs)) {
					LH_ERROR("Failed to copy original bytes");
					break;
				}

				uintptr_t r_addr_to_call_orig_fn = lib_to_hook->mmap;
				lib_to_hook->mmap += fnh->opcode_bytes_to_restore;

				uintptr_t r_new_payload_address = lib_to_hook->mmap;
				size_t new_payload_size = rel_jump_size + abs_jump_size;

				// Allocate space for the payload
				unsigned char *l_new_payload = (unsigned char *)malloc(new_payload_size);
				if (!l_new_payload) {
					LH_ERROR_SE("malloc");
					break;
				}

				unsigned char *l_new_payload_start = l_new_payload;

				LH_VERBOSE(4, "REL JUMP CALCULATION: this is the place, where the control flow must jump back to the original place");
				// JUMP from payload to original code (skip the original bytes that have been replaced to avoid loop)
				if (LH_SUCCESS != inj_build_rel_jump(l_new_payload, symboladdr + fnh->opcode_bytes_to_restore, r_new_payload_address)) {
					LH_ERROR("Unable to build relative jump");
					break;
				}
				lib_to_hook->mmap += rel_jump_size;
				l_new_payload += rel_jump_size;

				// Call the replacement function with an absolute jump
				uintptr_t r_hook_abs_jump_address = lib_to_hook->mmap;
				if (LH_SUCCESS != inj_build_abs_jump(l_new_payload, fnh->hook_fn, r_new_payload_address + rel_jump_size)) {
					LH_ERROR("Unable to build absolute jump");
					break;
				}
				lib_to_hook->mmap += abs_jump_size;
				l_new_payload += abs_jump_size;

				// assert
				if (lib_to_hook->mmap != mmap_after_hooked) {
					LH_ERROR("Seems we broke up something, mmap address is not the same as wanted");
					break;
				}

				// Write the jumps
				if (LH_SUCCESS != inj_copydata(lh->proc.pid, r_new_payload_address, l_new_payload_start, new_payload_size)) {
					LH_ERROR("Unable to copy payload");
					break;
				}

				// We store the original function address, if wanted
				if (fnh->orig_function_ptr != 0) {
					if (LH_SUCCESS != inj_pokedata(lh->proc.pid, fnh->orig_function_ptr, r_addr_to_call_orig_fn)) {
						LH_ERROR("Failed to copy original bytes");
						break;
					}
				}

				LH_VERBOSE(4, "REL JUMP CALCULATION: and now we overwrite the original function with our jump to the payload");
				//JUMP from symboladdr to TRAMPOLINE
				if (LH_SUCCESS != inj_build_rel_jump(l_new_payload_start, r_hook_abs_jump_address, symboladdr)) {
					LH_ERROR("Failed to build relative jump for the replacement");
					break;
				}

				LH_VERBOSE(4, "------------------------------------- replacing first opcodes for %s/%s begin:", fnh->libname, fnh->symname);
				// Copy the jump to trampoline in place of the original function
				if (LH_SUCCESS != inj_copydata(lh->proc.pid, symboladdr, l_new_payload_start, rel_jump_size)) {
					LH_ERROR("Unable to copy back relative jump into the original function");
					break;
				}
				LH_VERBOSE(4, "------------------------------------- replacing first opcodes for %s/%s end", fnh->libname, fnh->symname);

				if (lh_verbose > 3) {
					LH_VERBOSE(4, "Dumping the overwritten original function");
					if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
						break;
					if ((rc = inj_pass_args2func(&iregs, lhm_hexdump, symboladdr, 0x10)) != LH_SUCCESS)
						break;
					if ((rc = inj_setexecwaitget(lh, "lhm_hexdump", &iregs)) != LH_SUCCESS)
						break;

					LH_VERBOSE(4, "Dumping the corresponding payload area");
					if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
						break;
					if ((rc = inj_pass_args2func(&iregs, lhm_hexdump, r_payload_start, hook_area)) != LH_SUCCESS)
						break;
					if ((rc = inj_setexecwaitget(lh, "lhm_hexdump", &iregs)) != LH_SUCCESS)
						break;
				}

				hook_successful = 1;
				oneshot = false;

				fni++;
				fnh = &(hook_settings->fn_hooks[fni]);
		}
			//If the hook succeded and the used defined a post hook function, call it
			if ((hook_settings->autoinit_post != NULL) && (hook_successful)) {
				LH_VERBOSE(2, "Calling autoinit_post " LX, hook_settings->autoinit_post);

				if ((rc = inj_trap(lh->proc.pid, &iregs)) != LH_SUCCESS)
					break;
				if ((rc = inj_pass_args2func(&iregs, (uintptr_t) hook_settings->autoinit_post, heap + dllsz + 1, 0)) != LH_SUCCESS)
					break;
				if ((rc = inj_setexecwaitget(lh, "autoinit_post", &iregs)) != LH_SUCCESS)
					break;
			}

		} while (0);

		if(oneshot){
			LH_VERBOSE(1, "Freeing library handle " LX, dlopen_handle);
			// Encode call to dlopen
			if ((rc = inj_pass_args2func(&iregs, lh->fn_dlclose, dlopen_handle, 0)) != LH_SUCCESS)
				break;
			// Call dlopen and wait for completion
			if ((rc = inj_setexecwaitget(lh, "dlclose", &iregs)) != LH_SUCCESS)
				break;
			// Get the dlopen result
			result = lh_rget_ax(&iregs);
			if(result != 0){
				LH_ERROR("dlclose() failed!\n");
			}
		}

		// Cleanup part
		// Restore the original registers
		LH_VERBOSE(2, "Setting original registers.");
		if ((rc = inj_set_regs(lh->proc.pid, &oregs)) != LH_SUCCESS)
			break;

		// Restore the original stack
		LH_VERBOSE(2, "Copying stack back.");
		for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
			if ((rc = inj_pokedata(lh->proc.pid, lh_rget_sp(&oregs) - lh_redzone()
								   + idx * sizeof(size_t), stack[idx])) < 0)
				break;
		}
		if (rc < 0)
			break;
	} while (0);

	if (mdata)
		free(mdata);
	mdata = NULL;

	return rc;

}

/*
void lh_hook_init(lh_session_t* session) {
  LH_VERBOSE(1,"Shared object init is running");

  LH_VERBOSE(1,"Autoinit pre: "LX, hook_settings.autoinit_pre);
  if(hook_settings.autoinit_pre != NULL) {
     int a = hook_settings.autoinit_pre(session);
     LH_VERBOSE(1,"Autoinit returned %d", a);
     if(a != LH_SUCCESS) return;
  }

  // TODO?

  LH_VERBOSE(1,"Autoinit post: "LX, hook_settings.autoinit_post);
  if(hook_settings.autoinit_post != NULL) {
     hook_settings.autoinit_post(session);
  }
}
*/
