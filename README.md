# jitrop-native
The project finds the gadgets from a process by utilizing the techniques described in JIT-ROP paper.

[More update and instructions are coming soon! Stay tuned!]


## Dependencies
The project uses capstone disassembler to disassemble raw data to instructions. Also, please make sure to download the build-essentials.

```
sudo apt-get install build-essential
sudo apt-get install libcapstone-dev
```

## How to use
```
Usage: sudo ./jitrop -p <pid> -a <address> -o <operation> [-c <number of starting pointers> -executable_only]"
```
