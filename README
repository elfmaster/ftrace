Ftrace V0.2 elfmaster [at] zoho.com

DESCRIPTION:

ftrace is a reverse engineering tool designed to help map out the execution flow
of ELF executables (32bit and 64bit). Instead of printing system calls or library
function calls, it prints out the local function calls as they are happening,
and attempts to retrieve the function arguments and determine whether they are
immediate or pointer type. As of version 0.2, function arguments are only shown
for 64bit executables. This program is useful when wanting to see the function flow of
a given executable during runtime without having to set incremental breakpoints
and backtraces in a debugger like gdb. Ftrace relies on symbols for seeing a functions
actual name, but the -S option will show function calls for functions without
symbols as well, displaying them as sub_<addr>. As of v0.2, complete control flow
-C feature was added which gives control flow information beyond just call instructions,
moving into other branch instructions. Only branch <imm> instructions are currently
supported, but will be adding disassembly of branch *<reg> soon.


COMPILE:

gcc ftrace.c -o ftrace

USAGE:

ftrace [-p <pid>] [-Stsve] <prog> <args>

ARCHITECTURE: 

For 32bit executables set FTRACE_ARCH=32, it defaults to 64.


OPTIONS: 

[-v] Verbose output, print symbol table info etc.

[-p] This option is used to attach to an existing process ID.

[-s] This option will show strings as they are passed through functions (As best it knows how)

[-e] This will show certain ELF info such as symbols, and lists the shared library deps.

[-t] Type detection will guess what pointer type a function argument is, if it is a pointer.
It will detect pointers that are within the range of the text segment, data segment, heap and the stack.

[-S] Show function calls that don't have a matching symbol (For stripped binaries)

[-C] Complete control flow analysis (branch instructions other than call)

EXAMPLE:


elfmaster@Ox31337:~/code/ftrace/ftrace$ ./ftrace -Cs test

[+] Function tracing begins here:
PLT_call@0x400520:__libc_start_main()
(CONTROL FLOW CHANGE [jmp]): Jump from .plt 0x40052b into .plt 0x4004d0
LOCAL_call@0x4004b0:_init()
(CONTROL FLOW CHANGE [jz]): Jump from .init 0x4004be into .init 0x4004c5
(RETURN VALUE) LOCAL_call@0x4004b0: _init() = 0
(CONTROL FLOW CHANGE [jz]): Jump from .text 0x400608 into .text 0x400625
LOCAL_call@0x400692:b(0x1,0x2,0x3)
PLT_call@0x400510:printf("%d, %d, %d\n")
(CONTROL FLOW CHANGE [jmp]): Jump from .plt 0x40051b into .plt 0x4004d0
1, 2, 3
(RETURN VALUE) PLT_call@0x400510: printf("%d, %d, %d\n") = 8
(RETURN VALUE) LOCAL_call@0x400692: b(0x1,0x2,0x3) = a
LOCAL_call@0x400646:func1("Hello",0xa)
PLT_call@0x4004e0:strcpy()
(CONTROL FLOW CHANGE [jmp]): Jump from .plt 0x4004eb into .plt 0x4004d0
(RETURN VALUE) PLT_call@0x4004e0: strcpy() = 7fffae340330
(CONTROL FLOW CHANGE [jz]): Jump from .text 0x400689 into .text 0x400690
(RETURN VALUE) LOCAL_call@0x400646: func1("Hello",0xa) = ff
LOCAL_call@0x40062c:func2(0x4007e4)
PLT_call@0x4004f0:puts()
(CONTROL FLOW CHANGE [jmp]): Jump from .plt 0x4004fb into .plt 0x4004d0
stack string
(RETURN VALUE) PLT_call@0x4004f0: puts() = d
(RETURN VALUE) LOCAL_call@0x40062c: func2(0x4007e4) = d
(CONTROL FLOW CHANGE [jz]): Jump from .text 0x400735 into .text 0x40073c
LOCAL_call@0x400570:deregister_tm_clones()
(RETURN VALUE) LOCAL_call@0x400570: deregister_tm_clones() = 7


 
BUGS:

* Semi Rare EIO ptrace error (In progress to fix)
* Memory leak with -s (In progress to fix)

FUTURE:

* Add support for function arguments on 32bit
* Add support for following fork'd children of target process
* Extend heuristics of 64bit procedure prologue calling convention for function args.
* Add dwarf2 support for .debug section to get function prototype info
* Port to FreeBSD
* Add support for indirect calls, jmps. 

