/*
 * Stuff.
 *
 */

#ifndef __HOOKER_H
#    define __HOOKER_H

#    if __x86_64__
#    elif __i386__
#    elif __arm__
#    else
#        error Unsupported architecture!
#    endif

#    include <sys/stat.h>
#    include <stdint.h>
#    include <unistd.h>
#    include <errno.h>
#    include <linux/limits.h>
#    include <string.h>

#    define LH_SUCCESS 0
#    define LH_ONESHOT 1

extern int lh_verbose;
void lh_print(int verbose, int newline, char *fn, int lineno, const char *fmt, ...);
void lh_hexdump(char *desc, void *addr, int len);

#    define WHEREARG  __FILE__, __LINE__
#    define LH_PRINT(...) lh_print(0,1, WHEREARG, __VA_ARGS__)
#    define LH_VERBOSE(N,...) lh_print(N,1, WHEREARG, __VA_ARGS__)
#    define LH_VERBOSE_NN(N,...) lh_print(N,0, WHEREARG, __VA_ARGS__)
#    define LH_ERROR_SE(...) lh_print(0, 1, WHEREARG, "ERROR: %s (%s)", __VA_ARGS__, strerror(errno))
#    define LH_ERROR(...) lh_print(0, 1, WHEREARG, "ERROR: %s", __VA_ARGS__)

#    if __WORDSIZE == 64
#        define LX "%lx"
#        define LU "%lu"
#    else
#        define LX "%x"
#        define LU "%u"
#    endif

#    ifdef __android__

struct user {
	long uregs[18];
};

#    else
#        include <sys/user.h>
#    endif

typedef struct {
	pid_t pid;
	char exename[PATH_MAX];
} lh_main_process_t;

#endif
