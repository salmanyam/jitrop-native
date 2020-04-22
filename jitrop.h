#ifndef JITROP_JITROP_H
#define JITROP_JITROP_H

void init_rerand_timing(int pid, unsigned long addr, int which, int cpages);
void find_tc_gadgets(int pid, unsigned long addr, bool exec_only);


#endif //JITROP_JITROP_H
