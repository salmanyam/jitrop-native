#include <iostream>
#include <string>
#include <regex>
#include <vector>
#include <set>
#include <algorithm>

#include "lookup.h"
#include "rgx.h"

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

vector<string> delete_duplicate_gadgets(vector<string> gadgets) {
	vector<string> to_return;
	//printf("%lu\n", gadgets.size());
	for(int i=0; i<gadgets.size(); i++) {
		if ( std::find(to_return.begin(), to_return.end(), gadgets[i]) == to_return.end() ) {
			to_return.push_back(gadgets[i]);
		}
	}

	return to_return;

}

int find_gadgets(vector<string> gadgets, string pattern) {
	smatch m;
	regex rgx(pattern);

	int total = 0;

	for (int i=0; i<gadgets.size(); i++) {
		if (regex_search(gadgets[i], m, rgx)) {
			total += 1;
			//cout << gadgets[i] << endl;
		}
	}

	return total;
}

int find_gadgets_MOVTC(vector<string> gadgets, string pattern, set<string> *regset) {
	smatch m, m2;
	regex rgx(pattern);
	regex rgx2(R"([er|r][abcdsi1-9]?[xip1-9])"); //for extracting registers

	string gitem;

	int total = 0;

	for (int i=0; i<gadgets.size(); i++) {
		if (regex_search(gadgets[i], m, rgx)) {
			total += 1;
			//cout << gadgets[i] << endl;
			
			gitem = gadgets[i];
			while (regex_search(gitem, m2, rgx2)){
				//cout << m2.str() << " ";
				regset->insert(m2.str());
				gitem = m2.suffix();
			}
			//cout << endl;
		}
	}

	return total;
}


int find_gadgets_MOVTC_count(vector<string> gadgets, string pattern, set<string> *gadget_set, set<string> *regset) {
	smatch m, m2;
	regex rgx(pattern);
	regex rgx2(R"([er|r][abcdsi1-9]?[xip1-9])"); //for extracting registers

	string gitem;

	int total = 0;

	for (int i=0; i<gadgets.size(); i++) {
		if (regex_search(gadgets[i], m, rgx)) {
			total += 1;
			//cout << gadgets[i] << endl;
			gadget_set->insert(gadgets[i]);
			
			gitem = gadgets[i];
			while (regex_search(gitem, m2, rgx2)){
				//cout << m2.str() << " ";
				regset->insert(m2.str());
				gitem = m2.suffix();
			}
			//cout << endl;
		}
	}

	return total;
}





int get_gadget_size(int which) {

	jitrop_timing category = (jitrop_timing) which;

	switch(category) {
		case JITROP_TIME_TC: return TC_GADGETS; //TC set
		case JITROP_TIME_PRIORITY: return PRIORITY_GADGETS; //Priority set
		case JITROP_TIME_MOVTC: return MOVTC_GADGETS; //MOV TC set
		case JITROP_TIME_MOVTC_COUNT: return MOVTC_GADGETS; //MOV TC set
		case JITROP_TIME_PAYLOAD1: return PAYLOAD_ONE_GADGETS; //Payload one
		default: return TC_GADGETS; //TC set
	}
}


//TC gadget set, total 11
pair<string, string> TC_GADGET_SET[TC_GADGETS] = {
		make_pair("LM_footprint", LM_FT_RELAX),
		make_pair("SM_footprint", SM_FT_RELAX),
		make_pair("LR_footprint", LR_FT),
		make_pair("MR_footprint", MR_FT),
		make_pair("AM_footprint", AM_FT),
		make_pair("AMLD_footprint", AMLD_FT_RELAX),
		make_pair("AMST_footprint", AMST_FT_RELAX),
		make_pair("LOGIC_footprint", LOGIC_FT),
		make_pair("JMP_footprint", JMP_FT),
		make_pair("CALL_footprint", CALL_FT),
		make_pair("SYS_footprint", SYS_FT)
};

//ALL gadget set, total 11
pair<string, string> ALL_GADGET_SET[ALL_GADGETS] = {
		make_pair("LM_footprint", LM_FT_STRICT),
		make_pair("SM_footprint", SM_FT_STRICT),
		make_pair("LR_footprint", LR_FT),
		make_pair("MR_footprint", MR_FT),
		make_pair("AM_footprint", AM_FT),
		make_pair("AMLD_footprint", AMLD_FT_STRICT),
		make_pair("AMST_footprint", AMST_FT_STRICT),
		make_pair("LOGIC_footprint", LOGIC_FT),
		make_pair("JMP_footprint", JMP_FT),
		make_pair("CALL_footprint", CALL_FT),
		make_pair("SYS_footprint", SYS_FT),
		make_pair("SP_footprint", CP_FT),
		make_pair("CP_footprint", CP_FT),
		//make_pair("RF_footprint", RF_FT),
		make_pair("CS2_footprint", CS2_FT),
		make_pair("EP_footprint", EP_FT),

		make_pair("LM_non_footprint", LM_NONFT),
		make_pair("SM_non_footprint", SM_NONFT),
		make_pair("LR_non_footprint", LR_NONFT),
		make_pair("MR_non_footprint", MR_NONFT),
		make_pair("AM_non_footprint", AM_NONFT),
		make_pair("AMLD_non_footprint", AMLD_NONFT),
		make_pair("AMST_non_footprint", AMST_NONFT),
		make_pair("LOGIC_non_footprint", LOGIC_NONFT),
		make_pair("JMP_non_footprint", JMP_NONFT),
		make_pair("CALL_non_footprint", CALL_NONFT),
		make_pair("SYS_non_footprint", SYS_NONFT),
		make_pair("SP_non_footprint", SP_NONFT),
		make_pair("CP_non_footprint", CP_NONFT),
		//make_pair("RF_non_footprint", RF_NONFT),
		make_pair("CS2_non_footprint", CS2_NONFT)

};

// Priority gadget set, total 14
pair<string, string> PRIORITY_GADGET_SET[PRIORITY_GADGETS] = {
		make_pair("PRIORITY_gadgets_1", PRIORITY_gadgets_1),
		make_pair("PRIORITY_gadgets_2", PRIORITY_gadgets_2),
		//make_pair("PRIORITY_gadgets_3", PRIORITY_gadgets_3),
		make_pair("PRIORITY_gadgets_4", PRIORITY_gadgets_4),
		//make_pair("PRIORITY_gadgets_5", PRIORITY_gadgets_5),
		make_pair("PRIORITY_gadgets_6", PRIORITY_gadgets_6),
		make_pair("PRIORITY_gadgets_7", PRIORITY_gadgets_7),
		make_pair("PRIORITY_gadgets_8", PRIORITY_gadgets_8),
		make_pair("PRIORITY_gadgets_9", PRIORITY_gadgets_9),
		//make_pair("PRIORITY_gadgets_10", PRIORITY_gadgets_10),
		//make_pair("PRIORITY_gadgets_11", PRIORITY_gadgets_11),
		make_pair("PRIORITY_gadgets_12", PRIORITY_gadgets_12),
		make_pair("PRIORITY_gadgets_13", PRIORITY_gadgets_13),
		make_pair("PRIORITY_gadgets_14", PRIORITY_gadgets_14),
		make_pair("PRIORITY_gadgets_15", PRIORITY_gadgets_15),
		make_pair("PRIORITY_gadgets_16", PRIORITY_gadgets_16),
		make_pair("PRIORITY_gadgets_17", PRIORITY_gadgets_17)
};

// MOVTC gadget set, total 7 excluding the system gadget
pair<string, string> MOVTC_GADGET_SET[MOVTC_GADGETS] = {
		make_pair("MOVTC_MR", MOVTC_MR),
		make_pair("MOVTC_MRCONST", MOVTC_MRCONST),
		make_pair("MOVTC_ST", MOVTC_ST),
		make_pair("MOVTC_STCONSTEX", MOVTC_STCONSTEX),
		make_pair("MOVTC_STCONST", MOVTC_STCONST),
		make_pair("MOVTC_LM", MOVTC_LM),
		make_pair("MOVTC_LMEX", MOVTC_LMEX),
		make_pair("MOVTC_SYS", MOVTC_SYS)
};

//gadgets for payload one, total 10
pair<string, string> PAYLOAD_ONE_GADGET_SET[PAYLOAD_ONE_GADGETS] = {
		make_pair("GADGET_PAYLOAD_ONE_1", GADGET_PAYLOAD_ONE_1),
		make_pair("GADGET_PAYLOAD_ONE_2", GADGET_PAYLOAD_ONE_2),
		make_pair("GADGET_PAYLOAD_ONE_3", GADGET_PAYLOAD_ONE_3),
		make_pair("GADGET_PAYLOAD_ONE_4", GADGET_PAYLOAD_ONE_4),
		//make_pair("GADGET_PAYLOAD_ONE_5", GADGET_PAYLOAD_ONE_5),
		make_pair("GADGET_PAYLOAD_ONE_6", GADGET_PAYLOAD_ONE_6),
		make_pair("GADGET_PAYLOAD_ONE_7", GADGET_PAYLOAD_ONE_7),
		make_pair("GADGET_PAYLOAD_ONE_8", GADGET_PAYLOAD_ONE_8),
		make_pair("GADGET_PAYLOAD_ONE_9", GADGET_PAYLOAD_ONE_9),
		make_pair("GADGET_PAYLOAD_ONE_10", GADGET_PAYLOAD_ONE_10),
		make_pair("GADGET_PAYLOAD_ONE_11", GADGET_PAYLOAD_ONE_11)
};

void get_min_tc_set(vector<string> gadgets, int *tc_set) {
	
	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	for (int i = 0; i < TC_GADGETS; i++) {
		if (!tc_set[i]) {
			if(find_gadgets(result, TC_GADGET_SET[i].second) > 0) {
				tc_set[i] = 1;
			}
		}
	}
	result_unfmt.clear();
	result.clear();	
}

void get_priority_set(vector<string> gadgets, int *tc_set) {
	
	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	for (int i = 0; i < PRIORITY_GADGETS; i++) {
		if (!tc_set[i]) {
			//cout << "!TC_SET " << i << endl;
			if (find_gadgets(result, PRIORITY_GADGET_SET[i].second) > 0) {
				tc_set[i] = 1;
			}
		}
	}
	result_unfmt.clear();
	result.clear();	
}

void get_mov_tc_set(vector<string> gadgets, int *tc_set, set<string> *regset) {

	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	for (int i = 0; i < MOVTC_GADGETS; i++) {
		if (!tc_set[i] || regset->size() < 4) { //need four unique registers
			if(find_gadgets_MOVTC(result, MOVTC_GADGET_SET[i].second, regset) > 0) {
				tc_set[i] = 1;
			}
		}
	}
	result_unfmt.clear();
	result.clear();	
}

void get_payload_set_one(vector<string> gadgets, int *tc_set) {
	
	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	for (int i=0; i<PAYLOAD_ONE_GADGETS; i++) {
		if (!tc_set[i]) {
			//cout << i << endl;
			if(find_gadgets(result, PAYLOAD_ONE_GADGET_SET[i].second) > 0) {
				tc_set[i] = 1;
			}
		}
	}
	result_unfmt.clear();
	result.clear();	
}


void lookup_gadgets(vector<string> gadgets) {
	
	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	//printf("%lu\n", result.size());

	//cout << find_gadgets(result, LM_FT_RELAX) << endl;

	for (int i = 0; i < TC_GADGETS; i++) {
		cout << TC_GADGET_SET[i].first << " " << find_gadgets(result, TC_GADGET_SET[i].second) << endl;
	}

	//for (int i = 0; i < ALL_GADGETS; i++) {
	//	cout << ALL_GADGET_SET[i].first << " " << find_gadgets(result, ALL_GADGET_SET[i].second) << endl;
	//}

	//for (int i=0; i<result.size(); i++)
	//	cout << result[i] << endl;

	result_unfmt.clear();	
	result.clear();	
}


void lookup_priority_gadgets(vector<string> gadgets) {
	
	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	for (int i = 0; i < PRIORITY_GADGETS; i++) {
		cout << PRIORITY_GADGET_SET[i].first << " " << find_gadgets(result, PRIORITY_GADGET_SET[i].second) << endl;
	}

	result_unfmt.clear();	
	result.clear();	
}

void lookup_movtc_gadgets(vector<string> gadgets, set<string> *gadget_set, set<string> *regset) {
	
	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	for (int i = 0; i < MOVTC_GADGETS; i++) {
		cout << MOVTC_GADGET_SET[i].first << " " 
			<< find_gadgets_MOVTC_count(result, MOVTC_GADGET_SET[i].second, gadget_set, regset) << endl;
	}

	result_unfmt.clear();	
	result.clear();	
}



void get_mov_tc_count(vector<string> gadgets, int *tc_set, set<string> *gadget_set, set<string> *regset) {

	vector<string> result_unfmt = format_gadgets(gadgets);
	vector<string> result = delete_duplicate_gadgets(result_unfmt);

	int total = 0;

	for (int i = 0; i < MOVTC_GADGETS; i++) {
		//if (!tc_set[i] || regset->size() < 4) { //need four unique registers
			total = find_gadgets_MOVTC_count(result, MOVTC_GADGET_SET[i].second, gadget_set, regset);
			if( total > 0) {
				tc_set[i] += total;
			}
		//}
	}
	result_unfmt.clear();
	result.clear();
}
