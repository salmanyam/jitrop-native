#include <iostream>
#include <set>
#include <vector>
#include <chrono>

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

#include <capstone/capstone.h>

#include "jitrop.h"
#include "gadget.h"
#include "lookup.h"
#include "constants.h"

using namespace std;



/* Reads data from the target process, and places it on the `dest_buffer`
 * using either `ptrace` or `pread` on `/proc/pid/mem`.
 * The target process is not passed, but read from the static peekbuf.
 * `sm_attach()` MUST be called before this function. */
size_t readmemory(int pid, uint8_t *dest_buffer, const char *target_address, size_t size)
{
    size_t nread = 0;

    /* Read the memory with `ptrace()`: the API specifies that `ptrace()` returns a `long`, which
     * is the size of a word for the current architecture, so this section will deal in `long`s */
    assert(size % sizeof(long) == 0);
    errno = 0;

    for (nread = 0; nread < size; nread += sizeof(long)) {
        const char *ptrace_address = target_address + nread;
        long ptraced_long = ptrace(PTRACE_PEEKDATA, pid, ptrace_address, NULL);

        /* check if ptrace() succeeded */
        if (ptraced_long == -1L && errno != 0) {
            /* it's possible i'm trying to read partially oob */
            if (errno == EIO || errno == EFAULT) {
                int j;
                /* read backwards until we get a good read, then shift out the right value */
                for (j = 1, errno = 0; j < sizeof(long); j++, errno = 0) {
                    /* try for a shifted ptrace - 'continue' (i.e. try an increased shift) if it fails */
                    ptraced_long = ptrace(PTRACE_PEEKDATA, pid, ptrace_address - j, NULL);
                    if ((ptraced_long == -1L) && (errno == EIO || errno == EFAULT))
                        continue;

                    /* store it with the appropriate offset */
                    uint8_t* new_memory_ptr = (uint8_t*)(&ptraced_long) + j;
                    memcpy(dest_buffer + nread, new_memory_ptr, sizeof(long) - j);
                    nread += sizeof(long) - j;

                    /* interrupt the partial gathering process */
                    break;
                }
            }
            /* interrupt the gathering process */
            break;
        }
        /* otherwise, ptrace() worked - store the data */
        memcpy(dest_buffer + nread, &ptraced_long, sizeof(long));
    }
   
	return nread;
}

/*
#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int disas_raw_code(unsigned char *custom_code, size_t code_size, unsigned long start_addr){
	csh handle;
	cs_insn *insn;
	size_t count;

	printf("%ld\n", sizeof(custom_code));

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	
	count = cs_disasm(handle,  custom_code, code_size-1, start_addr, 0, &insn);
	
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

	return 0;
}
*/

unsigned long page_no(unsigned long addr){
	return addr & 0xFFFFFFFFFFFFF000;
}

unsigned long get_got_slot(unsigned long code_ptr, int pid) {
	
	unsigned char *data = NULL;
	size_t read_size = 16;

	if ((data = (unsigned char *)malloc(read_size * sizeof(char))) == NULL) {
		if (IS_LOG) printf("sorry, there was a memory allocation error for plt data.\n");
		return -1;
	}
	
	size_t nread = readmemory(pid, data, (const char *) code_ptr, read_size);
	
	if (nread <= 0) {
		if (IS_LOG) printf("get_got_slot::Memory read error, no data to disassemble.\n");
		return 0;
	}

	csh handle;
	cs_insn *insn;
	size_t count;

	string first_inst = "";

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		if (IS_LOG) printf("got slot::Capstone cs_open() error!\n");
		return 0;
	}

	unsigned long library_ptr = 0x0;
	char libptr_raw[16];

	count = cs_disasm(handle, data, nread, code_ptr, 0, &insn);
	
	if (count == 3) {

		if (strcmp(insn[0].mnemonic, "jmp") == 0 &&
			strcmp(insn[1].mnemonic, "push") == 0 &&
			strcmp(insn[2].mnemonic, "jmp") == 0) {
				
				first_inst = insn[0].op_str;
				//cout << insn[0].address << " ";
				//cout << first_inst.substr(first_inst.find("0x"), first_inst.find("]") - first_inst.find("0x")) << endl;

				unsigned long got_slot = insn[0].address + 
						strtoul(first_inst.substr(first_inst.find("0x"), first_inst.find("]") - first_inst.find("0x")).c_str(),
								NULL, 16) + 0x6;

				//cout << got_slot << endl;

				nread = readmemory(pid, data, (const char *) got_slot, 8);
				//cout << nread << endl;

				sprintf(libptr_raw, "0x%x%x%x%x%x%x%x%x", data[7], data[6], data[5], data[4], data[3], data[2], data[1], data[0]);
				//printf("%s\n", libptr_raw);
				library_ptr = strtoul(libptr_raw, NULL, 0);
				//printf("%lx\n", library_ptr);

		}
		cs_free(insn, count);
	} //else {
		//printf("ERROR: Failed to disassemble given code!\n");
	//}

	cs_close(&handle);
	free(data);

	return library_ptr;
}

bool is_complete(int *tc_set) {
	for (int i=0; i<11; i++)
		if(!tc_set[i])
			return false;

	return true;
}

int sum_tc(int *tc_set) {
	int total = 0;
	for (int i=0; i<11; i++)
		total += tc_set[i];
	return total;
}

vector<string> recursive_codepage_harvest(
				int pid, 
				unsigned long codeptr, 
				set<unsigned long> *visited, 
				bool is_rerand, 
				int *tc_set,
				double start_time,
				bool executable_only) 
{	
	vector<string> to_return, new_result;

	if (is_rerand) {
		if(is_complete(tc_set))
			return to_return;
	}

	unsigned long pageno = page_no(codeptr);

	set<unsigned long>::iterator it = visited->find(pageno);

	if (*it == pageno)
			return to_return;

	visited->insert(pageno);

	//printf("%lx\n", pageno);

	unsigned char *data = NULL;
	size_t read_size = 4096;

	if ((data = (unsigned char *)malloc(read_size * sizeof(char))) == NULL) {
		if (IS_LOG) printf("sorry, there was a memory allocation error.\n");
		//return -1;
		return to_return; // to_return is empty at this point
	}

	size_t nread = readmemory(pid, data, (const char *) pageno, read_size);
	
	if (nread <= 0) {
		if (IS_LOG) printf("Memory read error, no data to disassemble.\n");
		return to_return; // to_return is empty at this point
	}

	csh handle;
	cs_insn *insn;
	size_t count;

	//printf("%ld\n", sizeof(custom_code));

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		if (IS_LOG) printf("Capstone cs_open() error!\n");
		//return -1;
		return to_return; // to_return is empty at this point
	}

	vector<string> result = create_gadgets(data, nread, pageno, 5, 3);
	if(is_rerand) {
		get_min_tc_set(result, tc_set);
		chrono::milliseconds cur_time = chrono::duration_cast< chrono::milliseconds >(
                    chrono::system_clock::now().time_since_epoch()
    	);
		cout.precision(2);
		cout << (cur_time.count()-start_time)/1000.0 << " " << sum_tc(tc_set) << endl;
	}
	
	count = cs_disasm(handle, data, nread, pageno, 0, &insn);
	
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			if (strcmp(insn[j].mnemonic, "call") == 0 ||
				strcmp(insn[j].mnemonic, "jmp") == 0 ||
				strcmp(insn[j].mnemonic, "je") == 0 ||
				strcmp(insn[j].mnemonic, "jl") == 0 ||
				strcmp(insn[j].mnemonic, "jle") == 0 ||
				strcmp(insn[j].mnemonic, "jb") == 0 ||
				strcmp(insn[j].mnemonic, "jbe") == 0 ||
				strcmp(insn[j].mnemonic, "jg") == 0 ||
				strcmp(insn[j].mnemonic, "jge") == 0 ||
				strcmp(insn[j].mnemonic, "ja") == 0 ||
				strcmp(insn[j].mnemonic, "jae") == 0 ||
				strcmp(insn[j].mnemonic, "js") == 0 ||
				strcmp(insn[j].mnemonic, "jo") == 0 ||
				strcmp(insn[j].mnemonic, "jnp") == 0 ||
				strcmp(insn[j].mnemonic, "jns") == 0 )
			{
				if (insn[j].op_str[0] == '0' && insn[j].op_str[1] == 'x'){
					//printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					//		insn[j].op_str);
					
  					unsigned long new_codeptr = strtoul(insn[j].op_str, NULL, 16);
					//printf("%ld %lx\n", new_codeptr, new_codeptr);
					
					if (strcmp(insn[j].mnemonic, "call") == 0) {
						if (!executable_only)
							new_codeptr = get_got_slot(new_codeptr, pid);
					}

					new_result = recursive_codepage_harvest(pid, new_codeptr, visited, is_rerand, tc_set, start_time, executable_only);
					copy(new_result.begin(), new_result.end(), back_inserter(to_return));
					copy(result.begin(), result.end(), back_inserter(to_return));
					new_result.clear();
					result.clear();

				}
			}
		}

		cs_free(insn, count);
	} //else {
		//printf("ERROR: Failed to disassemble given code!\n");
	//}

	cs_close(&handle);

	free(data);

	return to_return;
}

void init_rerand_timing(int pid, unsigned long addr) {
	set<unsigned long> visited;
	int tc_set[11] = {0, };
	chrono::milliseconds start_time = chrono::duration_cast< chrono::milliseconds >(
                    chrono::system_clock::now().time_since_epoch()
    );
	vector<string> result = recursive_codepage_harvest(pid, addr, &visited, true, tc_set, start_time.count(), false);	
}
