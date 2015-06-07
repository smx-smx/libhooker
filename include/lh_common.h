/*
 * Stuff.
 *
 */

#ifndef __LH_COMMON_H
#    define __LH_COMMON_H

#    if __x86_64__
#    elif __i386__
#    elif __arm__
#    else
#        error Unsupported architecture!
#    endif

#    include <stdint.h>
#    include <stdbool.h>
#    include <unistd.h>
#    include "interface/if_os.h"
#    include <string.h>
#    include <sys/stat.h>
#ifdef __linux__
#    include <linux/limits.h>
#endif
#    include <errno.h>

#    define LH_SUCCESS 0
#    define LH_FAILURE 1

extern int lh_verbose;
void lh_print(int verbose, int newline, char *fn, int lineno, const char *fmt, ...);
void lh_hexdump(char *desc, void *addr, int len);

char *readlink_safe(char *path);

#    define WHEREARG  __FILE__, __LINE__
#    define LH_PRINT(...) lh_print(0,1, WHEREARG, __VA_ARGS__)
#    define LH_VERBOSE(N,...) lh_print(N,1, WHEREARG, __VA_ARGS__)
#    define LH_VERBOSE_NN(N,...) lh_print(N,0, WHEREARG, __VA_ARGS__)
#    define LH_ERROR_SE(fmt, ...) lh_print(0, 1, WHEREARG, "ERROR: "fmt" (%s)", ## __VA_ARGS__, strerror(errno))
#    define LH_ERROR(...) lh_print(0, 1, WHEREARG, "ERROR: " __VA_ARGS__)

#    if __WORDSIZE == 64
#        define LX "%lx"
#        define LU "%lu"
#    else
#        define LX "%x"
#        define LU "%u"
#    endif

/*
 * Any info you want to pass to the hooked process
 */
PACK(typedef struct {
	char magic[4];

	int argc;
	char **argv;

	int prog_argc;
	char **prog_argv;

	int lh_verbose;
	pid_t pid;
	char *exename;
}) lh_r_process_t;

#endif
