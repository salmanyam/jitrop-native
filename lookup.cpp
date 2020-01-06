#include <iostream>
#include <string>
#include <regex>
#include <vector>

#include "lookup.h"

using namespace std;

// trim from start
static inline std::string &ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end
static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(),
            std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

// trim from both ends
static inline std::string &trim(std::string &s) {
    return ltrim(rtrim(s));
}

vector<string> format_gadgets(vector<string> gadgets) {
	vector<string> to_return;
	string fmtted_gadget = "";
	for(int i=0; i<gadgets.size(); i++) {
		fmtted_gadget = gadgets[i].substr(gadgets[i].find(":")+2, gadgets[i].length());
		//cout << fmtted_gadget << endl;
		to_return.push_back(rtrim(fmtted_gadget));
	}

	return to_return;

}


//LoadMemFP_pattern = re.compile(r'^mov\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\];\sret;$')
  //  patterns.append(LoadMemFP_pattern)
   // gadget_names.append('Load-Memory-Footprint')

int find_gadgets(vector<string> gadgets, string pattern) {
	smatch m;
	regex rgx(pattern);

	int total = 0;

	for (int i=0; i<gadgets.size(); i++) {
		if (regex_search(gadgets[i], m, rgx))
			total += 1;
	}

	return total;
}

int find_LM_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\];\sret;$)");
}

int find_SM_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)");
}

int find_LR_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^pop\s[er|r][abcdsi\d]?[xip\d];\sret;$)");
}

int find_MR_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\sret;$)");
}

int find_AM_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^(add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\sret;$)");
}

int find_AMLD_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^(add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\];\sret;$)");
}

int find_AMST_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^(add|sub|imul|idiv)\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)");
}

int find_LOGIC_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^(shr|shl|and|or|neg)[^;]*;\sret;)");
}

int find_JMP_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^jmp\s[er|r][abcdsi\d]?[xip\d];$)");
}

int find_CALL_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^call\s[er|r][abcdsi\d]?[xip\d];$)");
}

int find_SYS_footprint(vector<string> gadgets) {
	return find_gadgets(gadgets, R"(^syscall;$)");
}

#define NO_FUNCTIONS 11
int (*find_gadgets_ptr[NO_FUNCTIONS]) (vector<string> gadgets) = {
		find_LM_footprint,
		find_SM_footprint,
		find_LR_footprint,
		find_MR_footprint,
		find_AM_footprint,
		find_AMLD_footprint,
		find_AMST_footprint,
		find_LOGIC_footprint,
		find_JMP_footprint,
		find_CALL_footprint,
		find_SYS_footprint
};

void get_min_tc_set(vector<string> gadgets, int *tc_set) {
	
	vector<string> result = format_gadgets(gadgets);

	for (int i=0; i<NO_FUNCTIONS; i++) {
		if (!tc_set[i]) {
			if(find_gadgets_ptr[i](result) > 0) {
				tc_set[i] = 1;
			}
		}
	}

	//for (int i=0; i<result.size(); i++)
	//	cout << result[i] << endl;

	result.clear();	
}
