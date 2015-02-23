#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#include "needle.h"

#define APP_NAME "needle"

int g_libraries = 0;
pid_t g_pid = 0;

uint64_t parse_address(const char *s) {
	if (0 == strncmp(s, "0x", 2))
		return strtoull(s, NULL, 0);
	return strtoull(s, NULL, 16);
}

int print_usage_and_quit(const char *errfmt, ...) {
	if (errfmt != NULL) {
		fprintf(stderr, "ERROR: ");

		va_list arglist;
		va_start(arglist, errfmt);
		vfprintf(stderr, errfmt, arglist);
		va_end(arglist);

		fprintf(stderr, "\n\n");
	}

	fprintf(stderr, "Hooker library, main injection tool\n\n");
	fprintf(stderr, "Usage:\n %s [-v level] pid library1.so [library2.so ...]\n", APP_NAME);
	fprintf(stderr, "   -v: verbose\n");
	fprintf(stderr, "   -e hex_memory_address: memory address for the injection\n");
	fprintf(stderr, "                      if not specified, main() will be used (if found)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " pid is the process id you want to hook\n");
	fprintf(stderr, " Then list of libraries you want to inject\n\n");

	return -3;

}

pid_t parse_pid(char *s) {
	int re = atoi(s);
	if (re <= 0)
		print_usage_and_quit("invalid pid specified: %s", s);

	return (pid_t) re;
}

int parse_opts(int argc, char *argv[]) {

	if (argc == 1)
		return print_usage_and_quit(NULL);

	char c;
	while ((c = getopt(argc, argv, "v:")) != -1) {
		switch (c) {
		case 'v':
			lh_verbose = atoi(optarg);
			LH_VERBOSE(4, "verbose set to %d", lh_verbose);
			break;
		case '?':
			if (isprint(optopt))
				return print_usage_and_quit("Unknown option `-%c'.\n", optopt);
			else
				return print_usage_and_quit("Unknown option character `\\x%x'.", optopt);
		default:
			goto sogood;
			// return print_usage_and_quit("Invalid parameter?");
		}
	}

 sogood:
	if (argc == optind)
		return print_usage_and_quit("pid missing");

	g_pid = parse_pid(argv[optind++]);

	if (argc == optind)
		return print_usage_and_quit("no libraries specified");

	g_libraries = optind;

	return LH_SUCCESS;
}

int main(int argc, char *argv[]) {
	int re = LH_SUCCESS;

	do {
		if (LH_SUCCESS != (re = parse_opts(argc, argv)))
			break;

		//create a new session object
		lh_session_t *session = lh_alloc();
		if (session == NULL) {
			re = -6;
			break;
		}
		
		//start tracking the pid specified by the user
		if (LH_SUCCESS != (re = lh_attach(session, g_pid)))
			break;

		int i;
		for (i = g_libraries; i < argc; i++) {
			//inject the libraries specified by the user
			if (LH_SUCCESS != (re = lh_inject_library(session, argv[i], NULL))) {
				break;
			}
		}

		//detach from the process
		re |= lh_detach(session);

		//free the session object
		lh_free(&session);

	} while (0);

	if (re == LH_SUCCESS)
		LH_PRINT("Successful.");

	return re;
}

/*
unsigned char *s = malloc(10);  
inj_build_rel_jump(s,  0xDAEB8, 0x2EA6); lh_hexdump("http://www.codepwn.com/posts/assembling-from-scratch-encoding-blx-instruction-in-arm-thumb/", s, 8);  
inj_build_rel_jump(s, 0x14, 0x8); lh_hexdump("goforth", s, 8);  
inj_build_rel_jump(s, 0x0, 0x1c); lh_hexdump("goback", s, 8);  
return -1;

char *s = malloc(10);  inj_build_rel_jump(s, 0x02980000, 0x6259326B); lh_hexdump("crap", s, 10);  return -1;
unsigned char *s = malloc(10);  test_inj_build_rel_jump(s, 0xDAEB8, 0x2EA6); lh_hexdump("crap", s, 10);  return -1;

  int x = -1;  lh_hexdump("-1: ", &x, 4);return 1;

char *c = malloc(20);
inj_build_abs_jump(c, 7, 0);
hexDump ("REL", c, inj_absjmp_opcode_bytes());
return 1;
*/
