#include <iostream>
#include <set>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <fcntl.h>

#include "jitrop.h"

using namespace std;

/* Flag set by ‘--verbose’. */
static int verbose_flag;

void print_usage() {
	printf("%s\n", "\tUsage: sudo ./jitrop -p <pid> -a <address> -o <operation> [-c <number of starting pointers> -executable_only]");
}

int main (int argc, char **argv)
{
	int c;

	bool exec_only = false;

	int pid = 0, operation = 0, codepages = 0;
	unsigned long addr = 0;

	while (1) {
		static struct option long_options[] = {
			/* These options set a flag. */
			{"verbose", no_argument, &verbose_flag, 1},
			{"brief",   no_argument, &verbose_flag, 0},
			
			/* These options don’t set a flag. We distinguish them by their indices. */
			{"executable_only",     no_argument,       0, 'e'},
			{"address",  required_argument,       0, 'a'},
			{"pid",  required_argument, 0, 'p'},
			{"operation",  required_argument, 0, 'o'},
			{"codepages",    required_argument, 0, 'c'}
		};

		/* getopt_long stores the option index here. */

		int option_index = 0;
		c = getopt_long (argc, argv, "ea:p:o:c:", long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1) break;

		switch (c) {
			case 'e':
	          		exec_only = true;
	         		break;

	        	case 'a':
	          		//printf ("option -c with value `%s'\n", optarg);
	          		addr = strtol (optarg, NULL, 16);
	          		break;

	        	case 'p':
	          		//printf ("option -c with value `%s'\n", optarg);
	          		pid  = strtol (optarg, NULL, 10);
	          		break;

	        	case 'o':
	          		//printf ("option -d with value `%s'\n", optarg);
	          		operation = strtol (optarg, NULL, 10);
	          		break;

	        	case 'c':
	          		//printf ("option -f with value `%s'\n", optarg);
	          		codepages = strtol (optarg, NULL, 10);
	          		break;

	        	case '?':
	          		/* getopt_long already printed an error message. */
	          		break;

	        	default:
	          		abort ();
	        }
	}

	//cout << pid << " " << addr << " " << operation << " " << codepages << endl;

	if (pid > 0 && addr > 0) {
		/* attach, to the target application, which should cause a SIGSTOP */
    		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1L) {
        		fprintf(stderr, "error: failed to attach to %d, %s, Try running as root\n", pid,
                	strerror(errno));
        		return 0;
    		}

    		if (operation <= 0) find_tc_gadgets(pid, addr, exec_only);
    		else init_rerand_timing(pid, addr, operation, codepages);

		if (ptrace(PTRACE_DETACH, pid, NULL, 0) == -1L) {
        		fprintf(stderr, "error: failed to detach to %d, %s\n", pid,
               		strerror(errno));
        		return 0;
		}
	}else print_usage();

	return 0;
}


