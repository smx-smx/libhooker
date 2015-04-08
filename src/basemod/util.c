/*
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

#include <util.h>

#include <symfile.h>

#include <dlfcn.h>
#include <stdio.h>


void *sym2addr(const char *name)
{
	void *addr = (void *)symfile_addr_by_name(name);

	if (addr == NULL)
		addr = dlsym(RTLD_NEXT, name);

	return addr;
}

const char *addr2sym(const void *addr)
{
	const char *name = symfile_name_by_addr((uint32_t)addr);

	if (name == NULL) {
		Dl_info info;

		if (dladdr(addr, &info) == 0)
			return NULL;

		name = info.dli_sname;
	}

	return name;
}

#if 0
/* 
 * Backtrace: getting the call stack without a frame pointer:
 *  http://www.yosefk.com/blog/getting-the-call-stack-without-a-frame-pointer.html
 */

/* get previous stack pointer and return address given the current ones */
static int get_prev_sp_ra(void** prev_sp, void** prev_ra, void* sp, void* ra)
{
	unsigned* wra = (unsigned*)ra;
	int spofft;

	/* scan towards the beginning of the function -
	   addui sp,sp,spofft should be the first command */
	while((*wra >> 16) != 0x27bd) {
		/* test for "scanned too much" elided */
		wra--;
	}
	spofft = ((int)*wra << 16) >> 16; /* sign-extend */
	*prev_sp = (char*)sp - spofft;

	/* now scan forward for sw r31,raofft(sp) */
	while(wra < (unsigned*)ra) {
		if((*wra >> 16) == 0xafbf) {
			int raofft = ((int)*wra << 16) >> 16; /* sign */
			*prev_ra = *(void**)((char*)sp + raofft);

			return 1;
		}
		wra++;
	}

	return 0; /* failed to find where ra is saved */
}

const char *backtrace(void)
{
	static char buf[4096];
	char *p = NULL;
	void* sp; /* stack pointer register */
	void* ra; /* return address register */
	/* adjust sp by the offset by which this function has just decremented it */
	int* funcbase = (int*)(int)&backtrace;
	/* funcbase points to an addiu sp,sp,spofft command */
	int spofft = (*(funcbase + 3) << 16) >> 16; /* 16 LSBs */

	/* read sp and ra registers */
	__asm__("move %0, $29"
		:"=r"(sp)
		:
	);
	__asm__("move %0, $31"
		:"=r"(ra)
		:
	);

	sp = (char*)sp - spofft;
	buf[0] = '\0';
	p = buf;
	do {
		const char *name = addr2sym(ra);

		if (name != NULL)
			p += snprintf(p, sizeof(buf) - (p - buf), "\n%s", name);
		else
			p += snprintf(p, sizeof(buf) - (p - buf), "\n%p", ra);
	} while(get_prev_sp_ra(&sp, &ra, sp, ra));

	return buf; /* backtrace */
}
#endif