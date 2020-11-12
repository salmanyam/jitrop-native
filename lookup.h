#ifndef JITROP_LOOKUP_H
#define JITROP_LOOKUP_H

#include <vector>
#include <string>
#include <set>

#define TC_GADGETS 11
#define MOVTC_GADGETS 8
#define PRIORITY_GADGETS 13
#define PAYLOAD_ONE_GADGETS 11-1

#define ALL_GADGETS 29

typedef enum {
	JITROP_TIME_TC = 1,
	JITROP_TIME_PRIORITY,
	JITROP_TIME_MOVTC,
	JITROP_TIME_MOVTC_COUNT,
	JITROP_TIME_PAYLOAD1
} jitrop_timing;


int get_gadget_size(int which);

void get_min_tc_set(std::vector<std::string> gadgets, int *tc_set);
void get_priority_set(std::vector<std::string> gadgets, int *tc_set);
void get_mov_tc_set(std::vector<std::string> gadgets, int *tc_set, std::set<std::string> *regset);
void get_mov_tc_count(std::vector<std::string> gadgets, int *tc_set, std::set<std::string> *gadget_set, std::set<std::string> *regset);
void get_payload_set_one(std::vector<std::string> gadgets, int *tc_set);

void lookup_gadgets(std::vector<std::string> gadgets);
void lookup_priority_gadgets(std::vector<std::string> gadgets);
void lookup_movtc_gadgets(std::vector<std::string> gadgets, std::set<std::string> *gadget_set, std::set<std::string> *regset);

#endif //JITROP_LOOKUP_H
