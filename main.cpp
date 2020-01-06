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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <fcntl.h>

#include "jitrop.h"

using namespace std;


int main(int argc, char* argv[]) {

  	int           pid  = strtol (argv[1], NULL, 10);
  	unsigned long addr = strtoul(argv[2], NULL, 16);
  	//int           len  = strtol (argv[3], NULL, 10);
    
	/* attach, to the target application, which should cause a SIGSTOP */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1L) {
        fprintf(stderr, "error: failed to attach to %d, %s, Try running as root\n", pid,
                strerror(errno));
        return 0;
    }

	init_rerand_timing(pid, addr);

    //_DEBUGINT = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    //printf("Output from ptrace : %lx\n", _DEBUGINT); // currently just reads one word, but later i will add more data types.

	if (ptrace(PTRACE_DETACH, pid, NULL, 0) == -1L) {
        fprintf(stderr, "error: failed to detach to %d, %s\n", pid,
                strerror(errno));
        return 0;
	}

	return 0;
}




