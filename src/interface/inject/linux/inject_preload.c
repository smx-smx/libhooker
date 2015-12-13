/*
 * Copyright (c) 2015 Smx
 * Copyright (c) 2011 Roman Tokarev <roman.s.tokarev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *        may be used to endorse or promote products derived from this software
 *        without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include "helpers/lh_inject.h"
#include "lh_common.h"

int (*real_main)(int, char **, char **);

#ifdef LH_EXPERIMENTAL_PRELOAD
void *lh_temp_mem = NULL;
#endif

int fake_main(int argc, char **argv, char **envp){
	LH_PRINT("Hello there!\n");

	// Make sure we don't propagate LD_PRELOAD
	unsetenv("LD_PRELOAD");

	#ifdef LH_EXPERIMENTAL_PRELOAD
	lh_temp_mem = calloc(1, 1024 * 1024); //1MB
	printf("0x%lx\n", lh_temp_mem);

	printf("Stopping at libc_start_main...\n");
	// Raise SIGSTOP so that needle can hook main
	raise(SIGSTOP);

	lh_hexdump("lh_temp_mem", lh_temp_mem, 1 * 1024 * 1024);
	free(lh_temp_mem);
	#endif

	int orig_argc = 0, i;
	for(i=0; i<argc; i++, orig_argc++){
		if(!strcmp(argv[i], "-original"))
			break;
	}

	if(orig_argc <= 1 || orig_argc >= argc){
		LH_ERROR("-original not specified\n");
		return 1;
	}

	size_t procmemSz = 0;
	for(i=1; i<orig_argc; i++){
		procmemSz += sizeof(char *);
	}
	procmemSz += sizeof(size_t);

	uintptr_t procmem = (uintptr_t)calloc(1, procmemSz);
	uintptr_t p = procmem;
	for(i=1; i<orig_argc; i++){
		*(uintptr_t *)p = argv[i];
		p += sizeof(char *);
	}
	// no header
	*(size_t *)p = 0;

	int ret = inj_inject_library(argv[1], orig_argc - 1, procmem, NULL);
	LH_PRINT("inj_inject_library() => %d\n", ret);

	//free(procmem);
	return real_main(argc - orig_argc, &argv[orig_argc], envp);


	#if 0
	int needle_argc = 0, i;
	for(i=0; i<argc; i++, needle_argc++){
		if(!strcmp(argv[i], "-original"))
			break;
	}
	needle_argc += 2;

	pid_t thisPid = getpid();
	char *thisPidArg;
	asprintf(&thisPidArg, "%zu", thisPid);

	char **needle_argv = calloc(sizeof(char *), needle_argc);
	for(i=0; i<needle_argc; i++){
		if(i == 0){
			needle_argv[i] = strdup("/home/sm/libhooker_sljit/bin/linux/x86_64/needle");
		} else if(i == 1){
			needle_argv[i++] = strdup("-g");
			needle_argv[i] = thisPidArg;
		} else {
			needle_argv[i] = strdup(argv[i - 2]);
		}
	}

	printf("NEEDLE_ARGC => %u\n", needle_argc);
	for(i=0; i<needle_argc; i++){
		printf("NEEDLE_ARGV[%u] => %s\n", i, needle_argv[i]);
	}

	pid_t fpid = fork();
	if(fpid == 0){
		execv("/home/sm/libhooker_sljit/bin/linux/x86_64/needle", needle_argv);
	} else {
		int status;
		do {
			waitpid(fpid, &status, WNOHANG);
		} while(!WIFEXITED(status));
		printf("Needle finished\n");
	}

	for(i=0; i<needle_argc; i++){
		free(needle_argv[i]);
	}

	free(needle_argv);

#if 0
	void (*needle_main)(int, char **) = dlsym(RTLD_DEFAULT, "needle_main");
	if(needle_main <= 0){
		LH_ERROR_SE("dlsym");
		_exit(EXIT_FAILURE);
	}


	printf("We are going to call needle_main(%u args)\n", needle_argc);
	for(i=0; i<needle_argc; i++){
		printf("Arg[%u] => %s\n", i, argv[i]);
	}
	needle_main(needle_argc, argv);
#endif
	return real_main(argc - (needle_argc - 2), &argv[needle_argc - 2], envp);
#endif

	//while(1) sleep(60 * 60);

	return real_main(argc, argv, envp);
}

int __libc_start_main(int (* main)(int, char **, char **), int argc, char **ubp_av,
				void (* init)(void), void (* fini)(void),
				void (* rtld_fini)(void), void *stack_end)
{
	int (* __real___libc_start_main)(int (* main)(int, char **, char **), int argc, char **ubp_av,
				void (* init)(void), void (* fini)(void),
				void (* rtld_fini)(void), void *stack_end);
	__real___libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
	if(__real___libc_start_main <= 0){
		LH_ERROR_SE("dlsym");
		_exit(EXIT_FAILURE);
	}

	#if 0
	// Make sure we don't propagate LD_PRELOAD
	unsetenv("LD_PRELOAD");

	printf("Stopping at libc_start_main...\n");

	// Raise SIGSTOP so that needle can hook main
	raise(SIGSTOP);

	return __real___libc_start_main(main, argc, ubp_av, init,
		fini, rtld_fini, stack_end);
	#endif

	real_main = main;
	return __real___libc_start_main(&fake_main, argc, ubp_av, init,
		fini, rtld_fini, stack_end);
}
