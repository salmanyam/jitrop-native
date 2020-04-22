#include <iostream>
#include <set>
#include <string>
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
		return 0;
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

bool branch_inst(cs_insn insn){
	if (strcmp(insn.mnemonic, "call") == 0 ||
				strcmp(insn.mnemonic, "jmp") == 0 ||
				strcmp(insn.mnemonic, "je") == 0 ||
				strcmp(insn.mnemonic, "jl") == 0 ||
				strcmp(insn.mnemonic, "jle") == 0 ||
				strcmp(insn.mnemonic, "jb") == 0 ||
				strcmp(insn.mnemonic, "jbe") == 0 ||
				strcmp(insn.mnemonic, "jg") == 0 ||
				strcmp(insn.mnemonic, "jge") == 0 ||
				strcmp(insn.mnemonic, "ja") == 0 ||
				strcmp(insn.mnemonic, "jae") == 0 ||
				strcmp(insn.mnemonic, "js") == 0 ||
				strcmp(insn.mnemonic, "jo") == 0 ||
				strcmp(insn.mnemonic, "jnp") == 0 ||
				strcmp(insn.mnemonic, "jns") == 0 )

		return true;
	return false;
}

bool is_complete(int *tc_set, int tc_priority_mv) {
	int gsize = get_gadget_size(tc_priority_mv); // defined in lookup.cpp
	
	for (int i = 0; i < gsize; i++)
		if(!tc_set[i])
			return false;

	return true;
}

int sum_tc(int *tc_set, int tc_priority_mv) {
	int gsize = get_gadget_size(tc_priority_mv); // defined in lookup.cpp

	int total = 0;
	for (int i = 0; i < gsize; i++){
		//cout << "TCSET: " << i << " " << tc_set[i] << endl;
		total += tc_set[i]? 1: 0;
	}
	return total;
}



void rerand_recursive_codepage_harvest(
				int pid, 
				unsigned long codeptr, 
				set<unsigned long> *visited, 
				int *tc_set,
				set<string> *gadget_set,
				set<string> *regset,
				int which,
				double start_time,
				bool exec_only) 
{	
	bool complete = is_complete(tc_set, which);

	jitrop_timing category = (jitrop_timing) which;

	if (category == JITROP_TIME_MOVTC || category == JITROP_TIME_MOVTC_COUNT) {
		if (complete && regset->size() >= 4) return;
	} else {
		if (complete) return;
	}

	unsigned long pageno = page_no(codeptr);

	set<unsigned long>::iterator it = visited->find(pageno);

	if (*it == pageno) return;

	visited->insert(pageno);

	unsigned char *data = NULL;
	size_t read_size = 4096;

	if ((data = (unsigned char *) malloc(read_size * sizeof(char))) == NULL) {
		if (IS_LOG) printf("sorry, there was a memory allocation error.\n");
		return;
	}

	size_t nread = readmemory(pid, data, (const char *) pageno, read_size);
	
	//printf("Code pointer = %lx %ld\n", pageno, nread);

	if (nread <= 0) {
		if (IS_LOG) printf("Memory read error, no data to disassemble.\n");
		return;
	}

	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		if (IS_LOG) printf("Capstone cs_open() error!\n");
		return;
	}
	
	printf("%lx ", pageno);
	
	chrono::milliseconds gstart_time = chrono::duration_cast< chrono::milliseconds >(
					chrono::system_clock::now().time_since_epoch());

	vector<string> result = create_gadgets(data, nread, pageno, 5, 3);

	chrono::milliseconds gend_time = chrono::duration_cast< chrono::milliseconds >(
					chrono::system_clock::now().time_since_epoch());

	//cout << (gend_time.count() - gstart_time.count()) << " " << endl;
	
	switch(category) {
		case JITROP_TIME_TC: get_min_tc_set(result, tc_set); break;
		case JITROP_TIME_PRIORITY: get_priority_set(result, tc_set); break;
		case JITROP_TIME_MOVTC: get_mov_tc_set(result, tc_set, regset); break;
		case JITROP_TIME_MOVTC_COUNT: get_mov_tc_count(result, tc_set, gadget_set, regset); break;
		case JITROP_TIME_PAYLOAD1: get_payload_set_one(result, tc_set); break;
		default: get_min_tc_set(result, tc_set); break;
	}

	chrono::milliseconds cur_time = chrono::duration_cast< chrono::milliseconds >(
                    chrono::system_clock::now().time_since_epoch());

	cout << (gend_time.count() - gstart_time.count()) << " " 
				<< (cur_time.count() - gend_time.count()) << " "
				<< (cur_time.count()- start_time) << " "
				<< sum_tc(tc_set, which) << endl;
	
	result.clear();

	count = cs_disasm(handle, data, nread, pageno, 0, &insn);

	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			//printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			if (branch_inst(insn[j])) {
				if (insn[j].op_str[0] == '0' && insn[j].op_str[1] == 'x'){
					//printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
					
  					unsigned long old_codeptr = strtoul(insn[j].op_str, NULL, 16);

  					if (!exec_only) {
						if (strcmp(insn[j].mnemonic, "call") == 0) {
							unsigned long new_codeptr = get_got_slot(old_codeptr, pid);
							//printf("%lx\n", new_codeptr);
							if (new_codeptr > 0) {
								rerand_recursive_codepage_harvest(
												pid, 
												new_codeptr, 
												visited, 
												tc_set,
												gadget_set,
												regset,
												which, 
												start_time, 
												exec_only );
							}
						}
					}
					
					rerand_recursive_codepage_harvest(
									pid, 
									old_codeptr, 
									visited, 
									tc_set,
									gadget_set,
									regset,
									which,
									start_time, 
									exec_only );
				}
			}
		}

		cs_free(insn, count);
	}

	cs_close(&handle);
	free(data);
}



void run_rerand_timing(int pid, unsigned long addr, int which) {
	set<unsigned long> visited;
	int gsize = get_gadget_size(which);

	int tc_set[gsize] = {0, };

	set<string> regset;
	set<string> gadget_set;

	chrono::milliseconds start_time = chrono::duration_cast< chrono::milliseconds >(
                    chrono::system_clock::now().time_since_epoch());

	rerand_recursive_codepage_harvest(
					pid, 
					addr, 
					&visited, 
					tc_set, 
					&gadget_set,
					&regset,
					which,
					start_time.count(), 
					false );	

	chrono::milliseconds cur_time = chrono::duration_cast< chrono::milliseconds >(
                    chrono::system_clock::now().time_since_epoch());

	//cout.precision(3);
	cout << (cur_time.count() - start_time.count()) << " " 
				<< sum_tc(tc_set, which) << endl;

	jitrop_timing category = (jitrop_timing) which;
	if (category == JITROP_TIME_MOVTC_COUNT) {
		for (int i = 0; i < gsize; i++) {
			cout << tc_set[i] << " ";
		}
		cout << endl;
	}
}


int scan_codepages (
				int pid, 
				unsigned long codeptr, 
				set<unsigned long> *visited, 
				bool exec_only,
				int which,
				int *limit,
				int total_cp) 
{	
	if (codeptr == 0x0) return 0;

	if (total_cp > 0 && *limit > total_cp) return 0;

	unsigned long pageno = page_no(codeptr);

	set<unsigned long>::iterator it = visited->find(pageno);

	if (*it == pageno)
			return 0;

	visited->insert(pageno);

	printf("0x%lx\n", pageno);
	run_rerand_timing(pid, pageno, which);
	*limit += 1;

	unsigned char *data = NULL;
	size_t read_size = 4096;

	if ((data = (unsigned char *)malloc(read_size * sizeof(char))) == NULL) {
		if (IS_LOG) printf("sorry, there was a memory allocation error.\n");
		return -1;
	}

	size_t nread = readmemory(pid, data, (const char *) pageno, read_size);
	
	if (nread <= 0) {
		if (IS_LOG) printf("Memory read error, no data to disassemble.\n");
		return -1;
	}

	csh handle;
	cs_insn *insn;
	size_t count;

	//printf("%ld\n", sizeof(custom_code));

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		if (IS_LOG) printf("Capstone cs_open() error!\n");
		return -1;
	}
	
	count = cs_disasm(handle, data, nread, pageno, 0, &insn);
	
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			if (branch_inst(insn[j])) {
				if (insn[j].op_str[0] == '0' && insn[j].op_str[1] == 'x') {
					//printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					//		insn[j].op_str);
					
  					unsigned long new_codeptr = strtoul(insn[j].op_str, NULL, 16);
					//printf("%ld %lx\n", new_codeptr, new_codeptr);
					
					scan_codepages(pid, new_codeptr, visited, exec_only, which, limit, total_cp);
				}
			}
		}
		cs_free(insn, count);
	} //else {
		//printf("ERROR: Failed to disassemble given code!\n");
	//}

	cs_close(&handle);

	free(data);

	return 0;
}

void init_rerand_timing(int pid, unsigned long addr, int which, int cpages) {
	set<unsigned long> visited_for_scan;
	int limit = 0;
	scan_codepages(pid, addr, &visited_for_scan, true, which, &limit, cpages);	
	//printf("%s\n", "Here");
	//run_rerand_timing(pid, addr, which);
}







vector<string> tc_recursive_codepage_harvest(
				int pid, 
				unsigned long codeptr, 
				set<unsigned long> *visited, 
				bool exec_only) 
{	
	vector<string> to_return, new_result;

	unsigned long pageno = page_no(codeptr);

	set<unsigned long>::iterator it = visited->find(pageno);

	if (*it == pageno)
			return to_return;

	visited->insert(pageno);

	unsigned char *data = NULL;
	size_t read_size = 4096;

	if ((data = (unsigned char *)malloc(read_size * sizeof(char))) == NULL) {
		if (IS_LOG) printf("sorry, there was a memory allocation error.\n");
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
		return to_return; // to_return is empty at this point
	}

	printf("0x%lx\n", pageno);

	vector<string> result = create_gadgets(data, nread, pageno, 5, 3);
	
	count = cs_disasm(handle, data, nread, pageno, 0, &insn);

	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			//printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
				//	insn[j].op_str);
			if (branch_inst(insn[j]))
			{
				if (insn[j].op_str[0] == '0' && insn[j].op_str[1] == 'x'){
					//printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
					
  					unsigned long old_codeptr = strtoul(insn[j].op_str, NULL, 16);

					if (!exec_only) {
						if (strcmp(insn[j].mnemonic, "call") == 0) {
							unsigned long new_codeptr = get_got_slot(old_codeptr, pid);
							//printf("%lx\n", new_codeptr);
							if (new_codeptr > 0) {
								new_result = tc_recursive_codepage_harvest(
										pid, 
										new_codeptr, 
										visited, 
										exec_only );
								copy(new_result.begin(), new_result.end(), back_inserter(to_return));
								copy(result.begin(), result.end(), back_inserter(to_return));
								new_result.clear();
								result.clear();
							}
						}
					}
					new_result = tc_recursive_codepage_harvest(
									pid, 
									old_codeptr, 
									visited, 
									exec_only );
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


void find_tc_gadgets(int pid, unsigned long addr, bool exec_only) {
	set<unsigned long> visited;
	int tc_set[TC_GADGETS] = {0, };

	vector<string> result = tc_recursive_codepage_harvest(pid, addr, &visited, exec_only);
	lookup_gadgets(result);
}
