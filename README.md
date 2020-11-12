# jitrop-native
The project collects the gadgets and records the time to obtain gadgets from a process by utilizing an attack technique called Just-In-Time Return-Oriented Programming ([JIT-ROP](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6547134)). We utilize the JIT-ROP technique to evaluate different fine-grained address space layout randomization (ASLR) schemes and measure the upper bound of effective re-randomization intervals. [Our evaluation and measurements](https://dl.acm.org/doi/pdf/10.1145/3372297.3417248) have been published in ACM CCS 2020. We implement a native version of the JIT-ROP technique. Please cite our paper if you utilize the source code of this repository.

```
@inproceedings{10.1145/3372297.3417248,
author = {Ahmed, Salman and Xiao, Ya and Snow, Kevin Z. and Tan, Gang and Monrose, Fabian and Yao, Danfeng (Daphne)},
title = {Methodologies for Quantifying (Re-)Randomization Security and Timing under JIT-ROP},
year = {2020},
isbn = {9781450370899},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3372297.3417248},
doi = {10.1145/3372297.3417248},
booktitle = {Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security},
pages = {1803–1820},
numpages = {18},
keywords = {measurement methodology, re-randomization interval, security metrics, ASLR measurement, address/code pointer impact analysis, JITROP, attack surface quantification},
location = {Virtual Event, USA},
series = {CCS '20}
}
```

We discuss how to use the native version of JIT-ROP as follows.


## Dependencies
The project uses capstone disassembler to disassemble raw data to instructions. Also, please make sure to download the build-essentials.

```
sudo apt-get install build-essential
sudo apt-get install libcapstone-dev
```

## How to build
The source code directory contains the Makefile to build the source codo. To build, just issue the ```make``` command. The ```make``` command will generate an executable named ```jitrop```.

## How to use
```
Usage: sudo ./jitrop -p <pid> -a <address> -o <operation> [-c <number of starting pointers> -executable_only]"
```
To execute the ```jitrop``` program, we need two required parameters: i) the pid of a running process, and ii) a leaked address from the process. Inside the ```nginx``` directory of this repository, we have modified the ```nginx``` program to leak the address of the ```ngx_getpid()``` function. We have compiled and built the executable program of the modified ```nginx``` program for testing.

To run the ```nginx``` server, just issue ```sudo ./nginx/sbin/nginx```. If the ```nginx``` program runs succesfully, it will output as follows.
```
The address of the function ngx_getpid() is = 0x7f06e17d1240
```
The leaked address will give us the leaked address that is necessary for running the ```jitrop``` program. In order to get the ```pid```, we need to issue the following command: ```ps aux | grep nginx```.

```
root       66983  0.0  0.0   4592   808 ?        Ts   Nov11   0:00 nginx: master process ./nginx/sbin/nginx
nobody     66984  0.0  0.0   5268  2804 ?        S    Nov11   0:00 nginx: worker process
```
If we choose the ```pid``` of the master process, then our ```pid``` will be 66983.

So, we have got the two required parameters to run the ```jitrop``` program. All the parameters of the ```jitrop``` program are described below.

```
-p <pid>: the pid of a process.

-a <address>: a leaked address from the address space of the process.

-o <operation>: what kind of output jitrop will produce.

-c <number of starting pointers> [optional]: jitrop picks a random code pointer from a code page of a process and 
starts the recursive code harvesting process from the code pointer. jitrop can do it multiple times from different 
code pages. How many times jitrop will repeat the process is specified by the -c <number of starting pointers> parameter.

-executable_only: jitrop can look for gadgets in the main executable as well as in the libraries. If we want to 
restrict jitrop to look gadgets only from the main executable, then we need to specify the -executable_only parameter.
```
The following command will output the starting addresses of all code pages from the address space of the ```nginx``` main process as well as all the number of gadgets from the Turing-complete gadget set found in the main executable of ```nginx```.

```
$ sudo ./jitrop -p 66983 -a 0x7f65f5682240

0x7f65f5682000
0x7f65f55c0000
0x7f65f5632000
0x7f65f5681000
0x7f65f5680000
0x7f65f56e2000
0x7f65f56fd000
...<truncated>...
LM_footprint 7
SM_footprint 50
LR_footprint 10
MR_footprint 10
AM_footprint 2
AMLD_footprint 8
AMST_footprint 5
LOGIC_footprint 5
JMP_footprint 4
CALL_footprint 7
SYS_footprint 1

```

## Operations
We can get several types of output from the ```jitrop``` program as follows:
```-o 1```: Operation 1 outputs the time to collect all the gadgets from the Turing-complete gadget set.  
```-o 2```: Operation 2 outputs the time to collect all the gadgets from the priority gadget set.  
```-o 3```: Operation 3 outputs the time to collect all the gadgets from the MOV TC gadget set.  
```-o 5```: Operation 5 outptus the time to collect all the gadgets from a payload gadget set.  
```-o 6```: Operation 6 outputs the number of the gadgets from the priority gadget set.  
```-o 7```: Operation 7 outputs the number of the gadgets from the MOV TC gadget set.  
```-o x```: Operation x such that ```x < 1 && x > 7``` (i.e., any numbers execept 1-7), outputs the number of the gadgets from the Turing-complete gadget set.  




## Sample commands and outputs

The following command records the time to find all the distinct gadget types from the Turing-complete gadget set by producing the following output.
```
$ sudo ./jitrop -p 66983 -a 0x7f65f5682240 -o 1

0x7f65f5682000
7f65f5682000 76 50 127 4
7f65f55c0000 116 21 264 4
7f65f5632000 125 51 441 6
7f65f5681000 55 21 517 6
7f65f5680000 40 23 581 7
...<truncated>...
7f65f56cd000 80 20 936 8
7f65f56cc000 107 15 1059 8
...<truncated>...
7f65f567c000 46 16 1423 9
7f65f56ae000 60 9 1493 9
...<truncated>...
7f65f5628000 45 8 2172 9
7f65f5627000 81 9 2262 9
7f65f5626000 45 8 2316 10
...<truncated>...
7f65f56b6000 59 9 2535 11
2535 11
```
Each line (except the last line) has the address of a code page and four numbers. The first, second, third, and fourth numbers represent the time to look for gadgets, the time to leak code pages, the time spent so far, and how many distinct types of gadgets the process collected so far. The operation 1 looks for gadgets from the Turing-complete gadget set and the total distinct types of gadget is 11. Thus process will stop looking for gadgets from the current starting pointer and restart the process from a different starting location. The last line has the summary information, i.e., the time to look for 11 types of gadgets.


The following command records the time to find all the distinct gadget types from the priority gadget set by producing the following output.
```
$ sudo ./jitrop -p 66983 -a 0x7f65f5682240 -o 2

0x7f65f5680000
7f65f5680000 40 47 87 7
7f65f56e2000 43 14 144 9
7f65f56fd000 108 24 277 11
7f65f56fc000 43 6 326 11
7f65f56cd000 78 10 415 11
7f65f56cc000 105 9 529 11
7f65f56f6000 47 5 582 11
7f65f56b0000 55 10 648 11
7f65f55c0000 115 6 769 11
7f65f56af000 44 5 818 11
7f65f56ab000 79 25 923 11
7f65f567c000 46 10 979 12
7f65f56ae000 59 4 1043 12
7f65f56ac000 50 7 1100 12
7f65f5632000 123 7 1230 12
7f65f55c1000 37 3 1271 12
7f65f55c2000 67 4 1342 12
7f65f55e4000 56 6 1404 12
7f65f55e3000 61 3 1468 12
7f65f55e2000 40 5 1514 12
7f65f55e0000 76 9 1599 13
1599 13
```

The following command prints all the gadgets from the MOV TC gadget set. To see the exact gadget, refer to our paper or the rgx.h file.
```
$ sudo ./jitrop -p 66983 -a 0x7f65f5682240 -o 7

0x7f65f5682000
0x7f65f55c0000
0x7f65f5632000
0x7f65f5681000
0x7f65f5680000
0x7f65f56e2000
...<truncated>...
MOVTC_MR 10
MOVTC_MRCONST 6
MOVTC_ST 11
MOVTC_STCONSTEX 39
MOVTC_STCONST 6
MOVTC_LM 1
MOVTC_LMEX 6
MOVTC_SYS 1

```

The following command prints all the gadgets from the priority gadget set. To see the exact gadget, refer to our paper or the rgx.h file.
```
$ sudo ./jitrop -p 66983 -a 0x7f65f5682240 -o 6

0x7f65f5682000
0x7f65f55c0000
0x7f65f5632000
0x7f65f5681000
0x7f65f5680000
0x7f65f56e2000
...<truncated>...
PRIORITY_gadgets_1 10
PRIORITY_gadgets_2 20
PRIORITY_gadgets_4 34
PRIORITY_gadgets_6 7
PRIORITY_gadgets_7 11
PRIORITY_gadgets_8 4
PRIORITY_gadgets_9 23
PRIORITY_gadgets_12 1
PRIORITY_gadgets_13 10
PRIORITY_gadgets_14 6
PRIORITY_gadgets_15 7
PRIORITY_gadgets_16 39
PRIORITY_gadgets_17 1
```

Please contact the author if you have any questions.
