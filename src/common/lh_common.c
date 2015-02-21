#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#include "lh_common.h"

int lh_verbose = 0;
void lh_print(int verbose, int newline, char *fn, int lineno, const char *fmt, ...) {

#ifndef DEBUG
  if(verbose > lh_verbose) return;
#endif

  printf("[%s:%d] ", fn, lineno);

  va_list arglist;
  va_start( arglist, fmt );
  vprintf(fmt, arglist);
  va_end( arglist );

  if(newline)
    printf("\n");

}

void lh_hexdump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        fprintf(stderr,"%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf(stderr,"  %s\n", buff);

            // Output the offset.
            fprintf(stderr,"  %04x ", i);
        }

        // Now the hex code for the specific character.
        fprintf(stderr," %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf(stderr,"   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf(stderr,"  %s\n", buff);
}
