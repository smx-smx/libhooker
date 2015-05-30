#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>

#include "lh_common.h"

int lh_verbose = 0;
int lh_stdout = STDOUT_FILENO;

void lh_stdout_set(int fd){
	lh_stdout = fd;
}
void lh_stdout_clear(){
	lh_stdout = -1;
}
int lh_stdout_getcurrent(){
	return lh_stdout;
}

void lh_vaprintf(const char *fmt, va_list ap){
	if(lh_stdout > -1){
		vdprintf(lh_stdout, fmt, ap);
	} else {
		vprintf(fmt, ap);
	}
}

void lh_printf(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	lh_vaprintf(fmt, ap);
	va_end(ap);
}

int lh_get_stdout(char *tty){
	if(strstr(tty, "pipe:") != NULL){
		uintptr_t start = (uintptr_t)strchr(tty, '[');
		uintptr_t end = (uintptr_t)strchr(tty, ']');
		if(start == 0 || end == 0){
			return -1;
		}
		start += 1; //skip '[' char
		size_t sz = end-start;
		char *pipeno = malloc(sz);
		strncpy(pipeno, (char *)start, sz);
		int fd = atoi(pipeno);
		lh_stdout_set(fd);
		return 0;
	} else {
		int fd = open(tty, O_RDWR);
		if(fd < 0) return -1;
		lh_stdout_set(fd);
		return 0;
	}
	return -1;
}

lh_r_process_t *lh_get_procinfo(int argc, char **argv){
	uintptr_t hdr = (uintptr_t)argv;

	uint32_t hdrSz = *(uint32_t *)(hdr + (sizeof(char *) * argc));

	lh_r_process_t *proc = (lh_r_process_t *)(hdr + hdrSz);
	if(strncmp(proc->magic, "LHFO", sizeof(proc->magic)) != 0) //check the magic
		return NULL;

	/*proc->argv = argv;
	proc->prog_argv = (char **)(hdr + (sizeof(char *) * argc) + sizeof(hdrSz));*/

	if(proc->lh_verbose > 3){
		printf("hdrSz: %zu\n", hdrSz);
		lh_hexdump("hdr", proc, sizeof(*proc));
	}
	return proc;
}

void lh_print(int verbose, int newline, char *fn, int lineno, const char *fmt, ...) {

#ifndef DEBUG
	if (verbose > lh_verbose)
		return;
#endif
	printf("[%s:%d] ", fn, lineno);

	va_list arglist;
	va_start(arglist, fmt);
	vprintf(fmt, arglist);
	va_end(arglist);

	if (newline)
		printf("\n");

}

void lh_hexdump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char *)addr;

	// Output description if given.
	if (desc != NULL)
		fprintf(stderr, "%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				fprintf(stderr, "  %s\n", buff);

			// Output the offset.
			fprintf(stderr, "  %04x ", i);
		}
		// Now the hex code for the specific character.
		fprintf(stderr, " %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		fprintf(stderr, "   ");
		i++;
	}

	// And print the final ASCII bit.
	fprintf(stderr, "  %s\n", buff);
}

char *readlink_safe(char *path){
	size_t bufferSize = 1;
	char *buf = calloc(1, bufferSize);
	if(!buf){
		LH_ERROR_SE("Not enough memory");
		return NULL;
	}
	while(1){
		int c = readlink(path, buf, bufferSize);
		if(c < 0){
			LH_ERROR_SE("readlink");
			return NULL;
		} else if(c == bufferSize) {
			buf = realloc(buf, bufferSize+1);
			memset(buf+(bufferSize++), 0x0, 1);
			continue;
		} else {
			return buf;
		}
	}
}
