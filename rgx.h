#ifndef JITROP_RGX_H
#define JITROP_RGX_H

#include <string>


//This is the regex need for the TC gadgets with minimum footprint
//====================TC GADGET SET==================

//mov dword ptr [rax], rbx; ret;
std::string LM_FT_STRICT = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\];\sret;$)"; 
//mov dword ptr [rax + offset], rbx; ret;
std::string LM_FT_RELAX = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]);\sret;$)"; 

//mov dword ptr [rax], rbx; ret;
std::string SM_FT_STRICT = R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)";
//mov dword ptr [rax + offset], rbx; ret;
std::string SM_FT_RELAX = R"(^mov\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]),\s[er|r][abcdsi\d]?[xip\d];\sret;$)";

//pop ebx; ret;
std::string LR_FT = R"(^pop\s[er|r][abcdsi\d]?[xip\d];\sret;$)";

//mov rax, rbx; ret;
std::string MR_FT = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\sret;$)";

// add rax, rbx; ret;
std::string AM_FT = R"(^(add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\sret;$)";

//add rax, dword ptr [rbx]; ret;
std::string AMLD_FT_STRICT = R"(^(add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\];\sret;$)";
//add rax, dword ptr [rbx + offset]; ret;
std::string AMLD_FT_RELAX= R"(^(add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]);\sret;$)";

//add dword ptr [rax], rbx; ret;
std::string AMST_FT_STRICT = R"(^(add|sub|imul|idiv)\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)";
//add dword ptr [rax + offset], rbx; ret;
std::string AMST_FT_RELAX = R"(^(add|sub|imul|idiv)\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]),\s[er|r][abcdsi\d]?[xip\d];\sret;$)";

std::string LOGIC_FT = R"(^((and|or)\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d]|(shr|shl)[^;]*);\sret;$)";
//std::string LOGIC_FT = R"(^(shr|shl)[^;]*;\sret;$)";


//jmp rbx;
std::string JMP_FT = R"(^jmp\s[er|r][abcdsi\d]?[xip\d];$)";

//call rax;
std::string CALL_FT = R"(^call\s[er|r][abcdsi\d]?[xip\d];$)";

//syscall;
std::string SYS_FT = R"(^syscall;$)";

//
std::string SP_FT = R"(^(xchg|\w+)\s[e|r]sp,\s([er|r][abcdsi\d]?[xip\d]|0?x?\d*);\sret;$)";

std::string CP_FT = R"(^(mov|add|sub|push|pop|inc|dec|neg|not|mul|fmul|imul|fimul|xor|or|and|sal|shl|sar|shr|cmp|test)[^;]*;\scall\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|[er|r][abcdsi\d]?[xip\d]);\s?(ret;|.?)$)";
std::string RF_FT = R"((mov|add|sub|push|pop|inc|dec|neg|not|mul|fmul|imul|fimul|xor|or|and|sal|shl|sar|shr|cmp|test|lea)[^;]*;\scall\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|[er|r][abcdsi\d]?[xip\d]);.*jmp\s[er|r][abcdsi\d]?[xip\d];)";
std::string CS2_FT = R"(^call.*ret;$)";
std::string EP_FT = R"(^push\s[e|r]bp;.*(call|jmp)\s([er|r][abcdsi\d]?[xip\d]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s?[+-]?\s?0?x?\d*\]);$)";
//========================TC GADGET SET===================



//========================TC GADGET SET EXTENDED FOOTPRINT===================

std::string  LM_NONFT = R"(mov\s[er|r][abcdsi\d]?[xip\d],\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]);.*\sret;$)"; 
std::string  SM_NONFT = R"(mov\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]),\s[er|r][abcdsi\d]?[xip\d];.*\sret;$)";
std::string  LR_NONFT = R"(pop\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
std::string  MR_NONFT = R"(mov\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
std::string  AM_NONFT = R"((add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
std::string  AMLD_NONFT = R"((add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]);.*\sret;$)";
std::string  AMST_NONFT = R"((add|sub|imul|idiv)\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\]),\s[er|r][abcdsi\d]?[xip\d];.*\sret;$)";
std::string  LOGIC_NONFT = R"(((and|or)\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d]|(shr|shl)[^;]*);.*\sret;$)";
std::string  JMP_NONFT = R"(.*jmp\s[er|r][abcdsi\d]?[xip\d];.*)";
std::string  CALL_NONFT = R"(call\s[er|r][abcdsi\d]?[xip\d];.*)";
std::string  SYS_NONFT = R"(.*syscall;$)";
std::string  SP_NONFT = R"((xchg|\w+)\s[e|r]sp,\s([er|r][abcdsi\d]?[xip\d]|0?x?\d*);.*\sret;)";
std::string  CP_NONFT = R"(.*(mov|add|sub|push|pop|inc|dec|neg|not|mul|fmul|imul|fimul|xor|or|and|sal|shl|sar|shr|cmp|test)[^;]*;\scall\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|[er|r][abcdsi\d]?[xip\d]);.*\s?(ret;|.?)$)";
std::string  RF_NONFT = R"(.*(mov|add|sub|push|pop|inc|dec|neg|not|mul|fmul|imul|fimul|xor|or|and|sal|shl|sar|shr|cmp|test|lea)[^;]*;.*\scall\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|[er|r][abcdsi\d]?[xip\d]);.*jmp\s[er|r][abcdsi\d]?[xip\d];)";
std::string  CS2_NONFT = R"(.*call.*ret;$)";

//std::string  LM_NONFT = R"(mov\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s?[+-]?\s?0?x?[\d]*\];.*\sret;)";
//std::string  SM_NONFT = R"(mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s?[+-]?\s?0?x?[\d]*\],\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
//std::string  LR_NONFT = R"(pop\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
//std::string  MR_NONFT = R"(mov\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
//std::string  AM_NONFT = R"((add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
//std::string  AMLD_NONFT = R"((add|sub|imul|idiv)\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s?[+-]?\s?0?x?[\d]*\];.*\sret;)";
//std::string  AMST_NONFT = R"((add|sub|imul|idiv)\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s?[+-]?\s?0?x?[\d]*\],\s[er|r][abcdsi\d]?[xip\d];.*\sret;)";
//std::string  LOGIC_NONFT = R"((shr|shl|and|or)[^;]*;.*\sret;)";
//std::string  JMP_NONFT = R"(.*jmp\s[er|r][abcdsi\d]?[xip\d];.*)";
//std::string  CALL_NONFT = R"(call\s[er|r][abcdsi\d]?[xip\d];.*)";
//std::string  SYS_NONFT = R"(.*mov\s[e|r]ax,\s0x\d+;\ssyscall;$)";
//std::string  SP_NONFT = R"((xchg|\w+)\s[e|r]sp,\s([er|r][abcdsi\d]?[xip\d]|0?x?\d*);.*\sret;)";
//std::string  CP_NONFT = R"(.*(mov|add|sub|push|pop|inc|dec|neg|not|mul|fmul|imul|fimul|xor|or|and|sal|shl|sar|shr|cmp|test)[^;]*;\scall\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|[er|r][abcdsi\d]?[xip\d]);.*\s?(ret;|.?)$)";
//std::string  RF_NONFT = R"(.*(mov|add|sub|push|pop|inc|dec|neg|not|mul|fmul|imul|fimul|xor|or|and|sal|shl|sar|shr|cmp|test|lea)[^;]*;.*\scall\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|[er|r][abcdsi\d]?[xip\d]);.*jmp\s[er|r][abcdsi\d]?[xip\d];)";
//std::string  CS2_NONFT = R"(.*call.*ret;$)";




//========================PRIORITY GADGET SET=================


//PRIORITY
// This portion code is for the patterns for finding priority gadgets

std::string PRIORITY_gadgets_1 = R"(^pop\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //pop rax; ret;
std::string  PRIORITY_gadgets_2 = R"(^pop\s[er|r][abcdsi\d]?[xip\d];\spop\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //pop rbx; pop rax; ret;
//std::string PRIORITY_gadgets_3 = R"(^pop\s[er|r][abcdsi\d]?[xip\d];\spop\s[er|r][abcdsi\d]?[xip\d];\spop\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //pop rbx; pop rax; pop rcx; ret;
std::string PRIORITY_gadgets_4 = R"(^add\s[er|r][abcdsi\d]?[xip\d],\s([er|r][abcdsi\d]?[xip\d]|[0]?[x]?[0-9a-f]+);\sret;$)"; //add rax, rbx/const; ret
//std::string  PRIORITY_gadgets_5 = R"(^add\s[er|r][abcdsi\d]?[xip\d],\s[0]?[x]?[0-9a-f]+;\sret;$)"; //add rax, const; ret
std::string PRIORITY_gadgets_6 = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s((byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\]|(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d](\s\+\s[0]?[x]?[0-9a-f]+)?\]);\sret;$)"; //mov rax, [rbx]
std::string  PRIORITY_gadgets_7 = R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //mov [rax], rbx;
std::string PRIORITY_gadgets_8 = R"(^jmp\s[er|r][abcdsi\d]?[xip\d];$)"; //jmp rax;
std::string PRIORITY_gadgets_9 = R"(^(xchg|\w+)\s[e|r]sp,\s([er|r][abcdsi\d]?[xip\d]|[0]?[x]?[0-9a-f]+);\sret;$)"; //xchg rsp, rax/const; ret;
//std::string PRIORITY_gadgets_10 = R"(^neg\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //neg rax; ret;
//std::string int PRIORITY_gadgets_11 = R"(^xor\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //xor rax, rbx; ret;
std::string PRIORITY_gadgets_12 = R"(^xor\s[er|r][abcdsi\d]?[xip\d],\s([er|r][abcdsi\d]?[xip\d]|[0]?[x]?[0-9a-f]+);\sret;$)"; //xor rax, rbx/0x1; ret
std::string PRIORITY_gadgets_13 = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //mov rax, rbx; ret;
std::string PRIORITY_gadgets_14 = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s[0]?[x]?[0-9a-f]+;\sret;$)"; //mov rax, 0x1; ret
std::string PRIORITY_gadgets_15 = R"(^call\s[er|r][abcdsi\d]?[xip\d];$)"; //call rax
std::string PRIORITY_gadgets_16 = R"(^(mov\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\s)?call\s[er|r][abcdsi\d]?[xip\d];$)"; //mov rax, rbx; call rax;
std::string PRIORITY_gadgets_17 = R"(^syscall;$)"; //syscall

//======================PRIORITY GADGET SET=========================


//======================MOV TC GADGET SET==========================
std::string MOVTC_MR = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //mov rax, rbx; ret;
std::string MOVTC_MRCONST = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s[0]?[x]?[0-9a-f]+;\sret;$)"; //mov rax, 0x01; ret
std::string MOVTC_ST = R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //mov [rax], rbx;
std::string MOVTC_STCONSTEX = R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //mov [rax+offset], rbx;
std::string MOVTC_STCONST = R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[0]?[x]?[0-9a-f]+;\sret;$)"; //mov [rax], const;
std::string MOVTC_LM = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\];\sret;$)"; //mov rax, [rbx]
std::string MOVTC_LMEX = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\];\sret;$)"; //mov rax, [rbx+offset]
std::string MOVTC_SYS = R"(^syscall;$)"; //syscall; or mov rax, const; syscall
//======================MOV TC GADGET SET==========================



//======================PAYLOAD ONE GADGET SET==========================

//Pattern for payload 1
// https://www.rapid7.com/db/modules/exploit/linux/ftp/proftp_telnet_iac

/*pop eax; ret
mov eax, [eax]; ret
jmp eax
add esp, 0x24; pop ebx; pop ebp; ret
pop edx; mov ah, 0xfe; inc dword ptr [ebx+0x5d5b24c4]; ret
mov [eax+ebp*4]; ebx; ret
mov [eax], edx; add esp, 0x10; pop ebx; pop esi; pop ebp; ret
lea esi, [esp-0x4df]
ea edi, [eax+0x12]
push 0x7f
pop ecx
rep movsd
pop ebx; pop ebp; ret
jmp eax
pop ebx; pop ebp; ret
jmp eax
pop ebx; pop ebp; ret
jmp eax
pop ebx; pop ebp; ret
jmp eax
pop ebx; pop ebp; ret
jmp eax
*/

std::string  GADGET_PAYLOAD_ONE_1 = R"(^pop\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //pop eax; ret;
std::string  GADGET_PAYLOAD_ONE_2 = R"(^mov\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\];\sret;$)"; //mov eax, [eax]; ret;
std::string  GADGET_PAYLOAD_ONE_3 = R"(^jmp\s[er|r][abcdsi\d]?[xip\d];$)"; //jmp eax;
std::string  GADGET_PAYLOAD_ONE_4 = R"(^add\s[er|r][abcdsi\d]?[xip\d],\s[0]?[x]?[0-9a-f]+;\spop\s[er|r][abcdsi\d]?[xip\d];\spop\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //add esp, 0x24; pop ebx; pop ebp; ret
std::string  GADGET_PAYLOAD_ONE_5 = R"(^pop\s[er|r][abcdsi\d]?[xip\d];\smov\s[er|r][abcdsi\d]?[xip\d],\s[0]?[x]?[0-9a-f]+;\sinc\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\];\sret;$)"; //pop edx; mov ah, 0xfe; inc dword ptr [ebx+0x5d5b24c4]; ret
std::string  GADGET_PAYLOAD_ONE_6 = R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s\+\s[0]?[x]?[0-9a-f]+\],\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //mov [eax+ebp*4]; ebx; ret
std::string  GADGET_PAYLOAD_ONE_7 = R"(^mov\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\],\s[er|r][abcdsi\d]?[xip\d];\sadd\s[er|r][abcdsi\d]?[xip\d],\s[0]?[x]?[0-9a-f]+;)"; //mov [eax], edx; add esp, 0x10; pop ebx; pop esi; pop ebp; ret;
std::string  GADGET_PAYLOAD_ONE_8 = R"(^lea\s[er|r][abcdsi\d]?[xip\d],\s(byte|dword|qword)\sptr\s\[[er|r][abcdsi\d]?[xip\d]\s[\+\-]\s[0]?[x]?[0-9a-f]+\];)"; //lea esi, [esp-0x4df]
std::string  GADGET_PAYLOAD_ONE_9 = R"(^push\s[0]?[x]?[0-9a-f]+;)"; 
std::string  GADGET_PAYLOAD_ONE_10 = R"(rep movs[bdq])";
std::string  GADGET_PAYLOAD_ONE_11 = R"(^pop\s[er|r][abcdsi\d]?[xip\d];\spop\s[er|r][abcdsi\d]?[xip\d];\sret;$)"; //pop rbx; pop rax; ret;

#endif //JITROP_RGX_H
