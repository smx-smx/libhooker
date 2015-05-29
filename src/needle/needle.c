#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#include "util.h"
#include "needle.h"

#define APP_NAME "needle"
int g_optind_lib = 0;
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
	fprintf(stderr, "Usage:\n %s [-v level] pid library.so [module args]\n", APP_NAME);
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

	g_optind_lib = optind;

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

		//obtain the current tty name
		//TODO: handle pipes (could use FIFOs)
		char *cur_tty = readlink_safe("/proc/self/fd/0");
		if(!cur_tty){
			return EXIT_FAILURE;
		}
		LH_PRINT("Running on TTY: %s", cur_tty);

		char *libpath = realpath(argv[g_optind_lib], NULL);
		if(!libpath){
			LH_ERROR_SE("realpath");
			return EXIT_FAILURE;
		}


		//don't subtract 1 because we need tty name
		//add 1 because we need the module name
		int argp = argc - g_optind_lib + 1;
		
		//create and prepare module arguments
		char **mod_argv = calloc(1, sizeof(char *) * argp);
		argp = 0;
		mod_argv[argp++] = strdup(libpath);
		mod_argv[argp++] = strdup(cur_tty);

		free(cur_tty);

		int i;
		for (i = g_optind_lib + 1; i < argc; i++) {
			//read any extra argument passed on the command line
			mod_argv[argp++] = strdup(argv[i]);
			//inject the libraries specified by the user
		}

		session->proc.argc = argp;
		session->proc.argv = mod_argv;


		//crate and prepare memory for hooked program arguments
		char *cmdline;
		char **prog_argv = NULL;
		argp = 0;
		do {
			FILE *pargs;
			asprintf(&cmdline, "/proc/%d/cmdline", g_pid);
			pargs = fopen(cmdline, "r");
			if(!pargs){
				LH_ERROR("Cannot open '%s' for reading, ignoring program args...", cmdline);
				break;
			}
			free(cmdline);

			char ch;
			int argSz = 0;
			char *arg;
			while(1){
				if((ch=fgetc(pargs)) == EOF){
					break;
				}
				argSz++;
				if(ch == 0x00){
					fseek(pargs, -argSz, SEEK_CUR);
					arg = calloc(1, argSz);
					fread(arg, argSz, 1, pargs);
					argSz = 0;
					if(!prog_argv){
						//initialize argument vector
						prog_argv = calloc(sizeof(char *), argp + 1);
					} else {
						//add a new argument to argument vector
						char **tmp = realloc(prog_argv, sizeof(char *) * (argp + 1)); //add a new char *
						if(!tmp){
							LH_ERROR_SE("realloc");
							break;
						}
						prog_argv = tmp;
						prog_argv[argp + 1] = NULL;
					}
					prog_argv[argp++] = arg;
				}
			}
			fclose(pargs);
			session->proc.prog_argc = argp;
			session->proc.prog_argv = prog_argv;
		} while(0);

		for(argp=0; argp<session->proc.prog_argc; argp++)
			printf("ProgArg %d => %s\n", argp, session->proc.prog_argv[argp]);
		for(argp=0; argp<session->proc.argc; argp++)
			printf("ModArg %d => %s\n", argp, session->proc.argv[argp]);

		LH_PRINT("Injecting %s", libpath);
		if (LH_SUCCESS != (re = lh_inject_library(session, libpath, NULL))) {
			break;
		}
		free(libpath);

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
