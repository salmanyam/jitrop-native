#ifndef JITROP_GADGET_H
#define JITROP_GADGET_H

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <climits>
#include <string>

using namespace std;


class Ending {
public:
		char rgx [128];
		int rlen;
		int blen;

		Ending(const char *myrgx, int len, int bxlen){
			memcpy(rgx, myrgx, len);
			rlen = len;
			blen = bxlen;
		}
};


class Gadget {

private:
		int inst_count;
		string gadget;
		bool has_address;
public:
	Gadget(){
		inst_count = 0;
		gadget = "";
		has_address = false;
	}

	void append(unsigned long addr, char *mnem, char *args) {
		
		if (!has_address) {
			gadget.append(to_string(addr));
			gadget.append(": ");

			has_address = true;
		}
		
		gadget.append(mnem);

		if (strlen(args) > 0){
			gadget.append(" ");
			gadget.append(args);
		}
		gadget.append("; ");

		inst_count++;
	}

	string get_gadget(){
		return gadget; 
	}

	int length() {
		return inst_count;
	}

	bool is_empty() {
		return gadget.empty();
	}

};


vector<string> create_gadgets(
				uint8_t *dest_buffer, 
				size_t size, 
				unsigned long target_address, 
				int inst_count, 
				int gtype
);

#endif //JITROP_GADGET_H
