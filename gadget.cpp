#include <iostream>
#include <string>
#include <regex>
#include <tuple>
#include <queue> 

#include "gadget.h"
#include <capstone/capstone.h>

using namespace std;


vector<vector<Ending> > myvect{ 
		{
				Ending("\xc3", 1, 1),
				Ending("\xc2([\x00-\x7f\x80-\xff]{2})", 14, 3)
		},
		{
				Ending("\x0f\x05", 2, 2),
				Ending("\x0f\x05\xc3", 3, 3)
		},
		{
				Ending("\xff[\x20\x21\x22\x23\x26\x27]", 9, 2),
                Ending("\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]", 10, 2),
                Ending("\xff[\x10\x11\x12\x13\x16\x17]", 9, 2),
                Ending("\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]", 10, 2),
               	Ending("\xff[\x14\x24]\x24", 6, 3),
                Ending("\xff\x55\x00", 3, 3),
                Ending("\xff\x65\x00", 3, 3),
                Ending("\xff[\xa0\xa1\xa2\xa3\xa6\xa7][\x00-\x7f\x80-\xff]{4}", 20, 6),
                Ending("\xff\xa4\x24[\x00-\x7f\x80-\xff]{4}", 14, 7),
                Ending("\xff[\x50-\x53\x55-\x57][\x00-\x7f\x80-\xff]{1}", 20, 3),
                Ending("\xff[\x60-\x63\x65-\x67][\x00-\x7f\x80-\xff]{1}", 20, 3),
                Ending("\xff[\x90\x91\x92\x93\x94\x96\x97][\x00-\x7f\x80-\xff]{4}", 21, 6)

		}


};

#define BAD_INST_COUNT 22

string _badInstructions[] = {"retf","enter","loop","loopne","int3", "db", "ret", "jmp",
                 "les", "lds", "jle","jl", "jb","jbe","jg","jge","ja","jae",
                 "jne", "je", "js", "jrcxz"};


bool find_bad_inst(char *mnem) {
	for (int i=0; i < BAD_INST_COUNT; i++) { // BAD_INST_COUNT defined in x86inst.h
		if(_badInstructions[i].compare(mnem) == 0)
			return true;
	}
	return false;
}

int disas_raw_code2(unsigned char *custom_code, size_t code_size, unsigned long start_addr){
    csh handle;
    cs_insn *insn;
    size_t count;

	//printf("%ld\n", sizeof(custom_code));

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    count = cs_disasm(handle,  custom_code, code_size, start_addr, 0, &insn);

    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);
			printf("%" PRIu16 "\n", insn[j].size);
        }
		printf("\n\n");

        cs_free(insn, count);
    } else
        printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);

	return 0;
}


Gadget create_gadget(char *code, int start, int end, unsigned long start_addr, Ending ending) {
	
	Gadget to_return, empty_gadget;
		
	csh handle;
    cs_insn *insn;
    size_t count;

	//printf("%d\n", end-start);
	unsigned char *new_code = (unsigned char *)&code[start];
	//disas_raw_code2(new_code, end-start, start_addr);


	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return empty_gadget; //gadget is empty at this point

    count = cs_disasm(handle,  new_code, end-start, start_addr, 0, &insn);


	regex r2e(ending.rgx, ending.rlen, std::regex_constants::ECMAScript);

	bool hasret = false;

    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {

			char *ibytes = (char *)insn[j].bytes;
			//cout << "Match = " << regex_match(ibytes, ibytes+ending.blen, r2e) << endl;

					/*
			//for(int li=0; li<3; li++)printf("%x ", ibytes[li]);
			//printf("\n");

			auto match_start = cregex_iterator(&ibytes[0], &ibytes[ending.blen], r2e);
    		auto match_end = cregex_iterator();

			//cout << "Number of matches " << distance(match_start, match_end) << endl;

			if (distance(match_start, match_end) > 0)
				hasret = true;*/

			if (regex_match(ibytes, ibytes+ending.blen, r2e))
				hasret = true;

			//if(memcmp(ending.rgx, insn[j].bytes, ending.clen()) == 0)
			//	hasret = true;

			if (hasret || !find_bad_inst(insn[j].mnemonic)) {
            	//printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
              	//      insn[j].op_str);

				//printf("strlen = %d\n", strlen(insn[j].op_str));
				to_return.append(insn[j].address, insn[j].mnemonic, insn[j].op_str);
			}

			if (hasret || find_bad_inst(insn[j].mnemonic)) {
				//printf("In break %s\n", insn[j].mnemonic);
				break;
			}
        }
        //printf("\n\n");

        cs_free(insn, count);

    } else {
        //printf("ERROR: Failed to disassemble given code!\n");
    	cs_close(&handle);
		return empty_gadget; // gadget is empty at this point
	}

    cs_close(&handle);

	if (hasret && to_return.length() > 0)
		return to_return;

	return empty_gadget;

}

vector<string> gather_gadget_by_ending(char *code, size_t size,  unsigned long start_addr, Ending ending, int inst_count) {
	
	vector<string> to_return;
		
	int index, cindex, none_count, offset_tmp = 0;
	int align = 1;
	int x, last_match;

  	//cmatch m;
  	//regex e ("[\x00-\xff]\\{2\\}");   // matches words beginning by "sub"

	//char cReg[] = "\xc2([^\x00-\x7f]{2})";
	//char cReg[] = "\xc2([\x00-\x7f]?[^\x80-\xff]?[\x00-\x7f]?[^\x80-\xff]?[\x00-\x7f]?[^\x80-\xff]?[\x00-\x7f]?[^\x80-\xff]?)";
	//regex r2e(cReg,16+39, std::regex_constants::ECMAScript);
	//char cReg[] = "\xc2([^\x00-\x7f]{2})";
	//char cReg[] = "\xc3";
	//regex r2e(cReg, 1, std::regex_constants::ECMAScript);
	regex r2e(ending.rgx, ending.rlen, std::regex_constants::ECMAScript);

	//char *pattern = "\xc3";
	//int patlen = 1;

	Gadget new_gadget;

	cindex = 0;
	int  i = 0;
	offset_tmp = 0;
	index = 0;


	auto match_start = std::cregex_iterator(&code[0], &code[size-1], r2e);
	auto match_end = std::cregex_iterator();

	//std::cout << "Found "
      //        << std::distance(match_start, match_end)
        //      << " words:\n";

	last_match = 0;
	for (std::cregex_iterator it = match_start; it != match_end; ++it) {
        std::cmatch match = *it;
        //cout << "Found at " << match.position() << endl;

		index = match.position();
		offset_tmp += index;

		cindex = index - last_match;
		if (offset_tmp % align == 0) {
			none_count = 0;
			//disas_raw_code2((unsigned char*)&code[index], 3, start_addr);
			//printf("%d\n", cindex);
			for (x = 0; x <= cindex; x += align) {
				new_gadget = create_gadget(code, index-x, index+ending.blen, start_addr+index-x, ending);
                
				if(!new_gadget.is_empty()) {
					if (new_gadget.length() > inst_count)
						break;

					//cout << new_gadget.get_gadget() << endl;
					to_return.push_back(new_gadget.get_gadget());
					none_count = 0;
                   
				} else {
					none_count += 1;
					if (none_count == 8) //arch.maxInvalid
						break;
				}
			}
		
		}

		last_match = index;

		//std::string match_str = match.str();
        //std::cout << match_str << '\n';


    }

	return to_return;

	/*
	cindex = 0;
	i = 0;
	offset_tmp = 0;
	index = 0;


	while (index < size) {
	
		if(memcmp(&code[index], pattern, patlen) == 0){
			printf("===========Found at %d===============\n", index);

			offset_tmp += cindex;
			//printf("%d\n", offset_tmp);

			if (offset_tmp % align == 0){
			
				none_count = 0;
				printf("%d\n", cindex);

				for (x = 0; x <= cindex; x += align) {
					new_gadget = create_gadget(code, index-x, index+patlen, start_addr+index-x, pattern);	

					if(!new_gadget.is_empty()) {
						if (new_gadget.length() > inst_count)
							break;
						
						cout << new_gadget.get_gadget() << endl;
						none_count = 0;

					} else {
						none_count += 1;
						if (none_count == 8) //arch.maxInvalid
							break;
					}
				}

			}


			cindex = 0;
			index += align;

			continue;
		}

		index++;
		cindex++;
	}*/
}



bool operator<(const Ending& e1, const Ending& e2) {
	return e2.blen < e1.blen;
}


vector<string> create_gadgets(
				uint8_t *dest_buffer, 
				size_t size, 
				unsigned long target_address, 
				int inst_count, 
				int gtype) 
{

	priority_queue<Ending> pq;

	vector<string> to_return, result;

	if (gtype == 3) { //For all gadgets
    	for (int i = 0; i < myvect.size(); i++) {
        	for (int j = 0; j < myvect[i].size(); j++)
            	pq.push(myvect[i][j]);
    	}
	}else {
        for (int j = 0; j < myvect[gtype].size(); j++)
            pq.push(myvect[gtype][j]);
	}

	//int total = 0;
	while (!pq.empty()){
     	//cout << pq.top().blen << " ";
		result = gather_gadget_by_ending((char *)dest_buffer, size, target_address, pq.top(), inst_count);
		//total += result.size();
		copy(result.begin(), result.end(), back_inserter(to_return));
		result.clear();
     	pq.pop();

		//for(int i=0; i<result.size(); i++)
		//	cout << "PFV: " <<  result[i] << endl;

  	}

	return to_return;

	//printf("%d\n", total);
	//printf("%d\n", to_return.size());

	//cout << endl;

	//Ending test("\xc3", 1, 1);
//	Ending test("\xc2([\x00-\x7f]?[^\x80-\xff]?[\x00-\x7f]?[^\x80-\xff]?[\x00-\x7f]?[^\x80-\xff]?[\x00-\x7f]?[^\x80-\xff]?)", 55, 3, 1);
	//Ending test("\xc2([\x00-\x7f\x80-\xff]{2})", 14, 3, 1);
	//gather_gadget_by_ending((char *)dest_buffer, size, target_address, test, 5);
	
	//printf("%0x %ld\n", target_address, size);
	//disas_raw_code2(dest_buffer, size, target_address);
}
