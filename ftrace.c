/*
 * ftrace (Function trace) local execution tracing 
 * <Ryan.Oneill@LeviathanSecurity.com>
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/reg.h>
#include <stdarg.h>


/*
 * For our color coding output
 */
#define WHITE "\x1B[37m"
#define RED  "\x1B[31m"
#define GREEN  "\x1B[32m"
#define YELLOW  "\x1B[33m"
#define DEFAULT_COLOR  "\x1B[0m"

#define MAX_SYMS 8192 * 2

/*
 * On 32bit systems should be set:
 * export FTRACE_ARCH=32
 */
#define FTRACE_ENV "FTRACE_ARCH"

#define MAX_ADDR_SPACE 256 
#define MAXSTR 512

#define TEXT_SPACE  0
#define DATA_SPACE  1
#define STACK_SPACE 2
#define HEAP_SPACE  3

#define CALLSTACK_DEPTH 0xf4240


struct branch_instr {
	char *mnemonic;
	uint8_t opcode;
};

	
#define BRANCH_INSTR_LEN_MAX 5

/*
 * Table for (non-call) branch instructions used 
 * in our control flow analysis.
 */
struct branch_instr branch_table[64] = {
			{"jo",  0x70}, 
			{"jno", 0x71},  {"jb", 0x72},  {"jnae", 0x72},  {"jc", 0x72},  {"jnb", 0x73},
			{"jae", 0x73},  {"jnc", 0x73}, {"jz", 0x74},    {"je", 0x74},  {"jnz", 0x75},
			{"jne", 0x75},  {"jbe", 0x76}, {"jna", 0x76},   {"jnbe", 0x77}, {"ja", 0x77},
			{"js",  0x78},  {"jns", 0x79}, {"jp", 0x7a},	{"jpe", 0x7a}, {"jnp", 0x7b},
			{"jpo", 0x7b},  {"jl", 0x7c},  {"jnge", 0x7c},  {"jnl", 0x7d}, {"jge", 0x7d},
			{"jle", 0x7e},  {"jng", 0x7e}, {"jnle", 0x7f},  {"jg", 0x7f},  {"jmp", 0xeb},
			{"jmp", 0xe9},  {"jmpf", 0xea}, {NULL, 0}
		};

struct elf_section_range {
	char *sh_name;
	unsigned long sh_addr;
	unsigned int sh_size;
};

struct { 
	int stripped;
	int callsite;
	int showret;
	int attach;
	int verbose;
	int elfinfo;
	int typeinfo; //imm vs. ptr
	int getstr;
	int arch;
	int cflow;
} opts;

struct elf64 {
	Elf64_Ehdr *ehdr;
        Elf64_Phdr *phdr;
        Elf64_Shdr *shdr;
        Elf64_Sym  *sym;
        Elf64_Dyn  *dyn;

	char *StringTable;
	char *SymStringTable;
};

struct elf32 {
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr;
	Elf32_Sym  *sym;
	Elf32_Dyn  *dyn;
	
	char *StringTable;
	char *SymStringTable;
	
};

struct address_space {
	unsigned long svaddr;
	unsigned long evaddr;
	unsigned int size;
	int count;
};

struct syms {
	char *name;
	unsigned long value;
};

typedef struct breakpoint {
	unsigned long vaddr;
	long orig_code;
} breakpoint_t;

typedef struct calldata {
		char *symname;
		char *string;
		unsigned long vaddr;
		unsigned long retaddr;
	//	unsigned int depth;
		breakpoint_t breakpoint;
} calldata_t;

typedef struct callstack {
	calldata_t *calldata;
	unsigned int depth; 
} callstack_t;

struct call_list {
	char *callstring;
	struct call_list *next;
};

#define MAX_SHDRS 256

struct handle {
	char *path;
	char **args;
	uint8_t *map;
	struct elf32 *elf32;
	struct elf64 *elf64;
	struct elf_section_range sh_range[MAX_SHDRS];
	struct syms lsyms[MAX_SYMS]; //local syms
	struct syms dsyms[MAX_SYMS]; //dynamic syms
	char *libnames[256];
	int lsc; //lsyms count
	int dsc; // dsyms count
	int lnc; //libnames count
	int shdr_count;
	int pid;
};

int global_pid;

void load_elf_section_range(struct handle *);
void get_address_space(struct address_space *, int, char *);
void MapElf32(struct handle *);
void MapElf64(struct handle *);
void *HeapAlloc(unsigned int);
char *xstrdup(const char *);
char *get_section_by_range(struct handle *, unsigned long);

void set_breakpoint(callstack_t *callstack)
{
	int status;
  	long orig = ptrace(PTRACE_PEEKTEXT, global_pid, callstack->calldata[callstack->depth].retaddr);
	long trap;
	
	trap = (orig & ~0xff) | 0xcc;
	if (opts.verbose)
		printf("[+] Setting breakpoint on 0x%lx\n", callstack->calldata[callstack->depth].retaddr);

	ptrace(PTRACE_POKETEXT, global_pid, callstack->calldata[callstack->depth].retaddr, trap);
	callstack->calldata[callstack->depth].breakpoint.orig_code = orig;
	callstack->calldata[callstack->depth].breakpoint.vaddr = callstack->calldata[callstack->depth].retaddr;

}

void remove_breakpoint(callstack_t *callstack)
{
	int status;
	if (opts.verbose)
		printf("[+] Removing breakpoint from 0x%lx\n", callstack->calldata[callstack->depth].retaddr);
	
	ptrace(PTRACE_POKETEXT, global_pid, 
	callstack->calldata[callstack->depth].retaddr, callstack->calldata[callstack->depth].breakpoint.orig_code);
}

/*
 * Simple array implementation of stack
 * to keep track of function depth and return values
 */

void callstack_init(callstack_t *callstack)
{
	callstack->calldata = (calldata_t *)HeapAlloc(sizeof(calldata_t) * CALLSTACK_DEPTH);
	callstack->depth = -1; // 0 is first element

}

void callstack_push(callstack_t *callstack, calldata_t *calldata)
{
	memcpy(&callstack->calldata[++callstack->depth], calldata, sizeof(calldata_t));
	set_breakpoint(callstack);
}

calldata_t * callstack_pop(callstack_t *callstack)
{
	if (callstack->depth == -1) 
		return NULL;
	
	remove_breakpoint(callstack);
	return (&callstack->calldata[callstack->depth--]);
}

/* View the top of the stack without popping */
calldata_t * callstack_peek(callstack_t *callstack)
{
	if (callstack->depth == -1)
		return NULL;
	
	return &callstack->calldata[callstack->depth];

}

struct call_list * add_call_string(struct call_list **head, const char *string)
{
	struct call_list *tmp = (struct call_list *)HeapAlloc(sizeof(struct call_list));
	
	tmp->callstring = (char *)xstrdup(string);
	tmp->next = *head; 
	*head = tmp;
	
	return *head;

}

void clear_call_list(struct call_list **head)
{
	struct call_list *tmp;
	
	if (!head)
		return;

	while (*head != NULL) {
		tmp = (*head)->next;
		free (*head);
		*head = tmp;
	}
}

struct branch_instr * search_branch_instr(uint8_t instr)
{
	int i;
	struct branch_instr *p, *ret;
	
	for (i = 0, p = branch_table; p->mnemonic != NULL; p++, i++) {
		if (instr == p->opcode)
			return p;
	}
	
	return NULL;
}

void print_call_list(struct call_list **head)
{
	if (!head)
		return;
	
	while (*head != NULL) {
		fprintf(stdout, "%s", (*head)->callstring);
		head = &(*head)->next;
	}

}

/*
 * A couple of commonly used utility
 * functions for mem allocation
 * malloc, strdup wrappers.
 */

void * HeapAlloc(unsigned int len)
{
	uint8_t *mem = malloc(len);
	if (!mem) {
		perror("malloc");
		exit(-1);
	}
	return mem;
}

char * xstrdup(const char *s)
{
	char *p = strdup(s);
	if (p == NULL) {
		perror("strdup");
		exit(-1);
	}
	return p;
}
	
char * xfmtstrdup(char *fmt, ...)
{
	char *s, buf[512];
	va_list va;
        
	va_start (va, fmt);
	vsnprintf (buf, sizeof(buf), fmt, va);
	s = xstrdup(buf);
	
	return s;
}
	


/*
 * ptrace functions
 */


int pid_read(int pid, void *dst, const void *src, size_t len)
{

        int sz = len / sizeof(void *);
        int rem = len % sizeof(void *);
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;
        long word;
	
        while (sz-- != 0) {
                word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
                if (word == -1 && errno) 
                       	return -1;
         
	       *(long *)d = word;
                s += sizeof(long);
                d += sizeof(long);
        }
        
        return 0;
}


/*
 * Get global/local and dynamic
 * symbol/function information.
 */
int BuildSyms(struct handle *h)
{
	unsigned int i, j, k;
	char *SymStrTable;
	Elf32_Ehdr *ehdr32;
	Elf32_Shdr *shdr32;
	Elf32_Sym  *symtab32;
	Elf64_Ehdr *ehdr64;
	Elf64_Shdr *shdr64;
	Elf64_Sym  *symtab64;
	int st_type;
	
	h->lsc = 0;
	h->dsc = 0;

	switch(opts.arch) {
		case 32:
			ehdr32 = h->elf32->ehdr;
			shdr32 = h->elf32->shdr;
		
			for (i = 0; i < ehdr32->e_shnum; i++) {
				if (shdr32[i].sh_type == SHT_SYMTAB || shdr32[i].sh_type == SHT_DYNSYM) {
					 
				 	SymStrTable = (char *)&h->map[shdr32[shdr32[i].sh_link].sh_offset]; 
                       			symtab32 = (Elf32_Sym *)&h->map[shdr32[i].sh_offset];
					
                        		for (j = 0; j < shdr32[i].sh_size / sizeof(Elf32_Sym); j++, symtab32++) {
						
						st_type = ELF32_ST_TYPE(symtab32->st_info);
						if (st_type != STT_FUNC)
							continue;

						switch(shdr32[i].sh_type) {
							case SHT_SYMTAB:
								h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab32->st_name]);
								h->lsyms[h->lsc].value = symtab32->st_value;
								h->lsc++;
								break;
							case SHT_DYNSYM:
								h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab32->st_name]);
								h->lsyms[h->lsc].value = symtab32->st_value;
								h->dsc++;
								break;
						}
                        		}
                		}
			}
			
		        h->elf32->StringTable = (char *)&h->map[shdr32[ehdr32->e_shstrndx].sh_offset];
                        for (i = 0; i < ehdr32->e_shnum; i++) {
                                if (!strcmp(&h->elf32->StringTable[shdr32[i].sh_name], ".plt")) {
                                        for (k = 0, j = 0; j < shdr32[i].sh_size; j += 16) {
                                                if (j >= 16) {
                                                        h->dsyms[k++].value = shdr32[i].sh_addr + j;
                                                }
                                        }
                                        break;
                                }
                        } 
			break;
		case 64:
		    	ehdr64 = h->elf64->ehdr;
                        shdr64 = h->elf64->shdr;
		
                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                if (shdr64[i].sh_type == SHT_SYMTAB || shdr64[i].sh_type == SHT_DYNSYM) {

                                        SymStrTable = (char *)&h->map[shdr64[shdr64[i].sh_link].sh_offset];
                                        symtab64 = (Elf64_Sym *)&h->map[shdr64[i].sh_offset];

                                        for (j = 0; j < shdr64[i].sh_size / sizeof(Elf64_Sym); j++, symtab64++) {
						
					  	st_type = ELF64_ST_TYPE(symtab64->st_info);
						if (st_type != STT_FUNC)
							continue;

                                                switch(shdr64[i].sh_type) {
                                                        case SHT_SYMTAB:
                                                                h->lsyms[h->lsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
                                                                h->lsyms[h->lsc].value = symtab64->st_value;
                                                                h->lsc++;
                                                                break;
                                                        case SHT_DYNSYM:	
                                                                h->dsyms[h->dsc].name = xstrdup(&SymStrTable[symtab64->st_name]);
                                                                h->dsyms[h->dsc].value = symtab64->st_value;
                                                                h->dsc++;
                                                                break;
                                                }
                                        }
                                }
                        }
                        h->elf64->StringTable = (char *)&h->map[shdr64[ehdr64->e_shstrndx].sh_offset];
                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                if (!strcmp(&h->elf64->StringTable[shdr64[i].sh_name], ".plt")) {
                                        for (k = 0, j = 0; j < shdr64[i].sh_size; j += 16) {
                                                if (j >= 16) {
							h->dsyms[k++].value = shdr64[i].sh_addr + j;
                                                }
                                        }
					break;
                                }
                        }
			break;
		}

		return 0;

}

void locate_dynamic_segment(struct handle *h)
{
        int i;
        
	switch (opts.arch) {
		case 32:
        		h->elf32->dyn = NULL;
        		for (i = 0; i < h->elf32->ehdr->e_phnum; i++) {
                		if (h->elf32->phdr[i].p_type == PT_DYNAMIC) {
                        		h->elf32->dyn = (Elf32_Dyn *)&h->map[h->elf32->phdr[i].p_offset];
                        		break;
                		}
       			}				
			break;
		case 64:
		  	h->elf64->dyn = NULL;
                        for (i = 0; i < h->elf64->ehdr->e_phnum; i++) {
                                if (h->elf64->phdr[i].p_type == PT_DYNAMIC) {
                                        h->elf64->dyn = (Elf64_Dyn *)&h->map[h->elf64->phdr[i].p_offset];
                                        break;
                                }
                        } 
			break;
	}

}

uint8_t *get_section_data(struct handle *h, const char *section_name)
{
	
        char *StringTable;
	int i;

	switch (opts.arch) {
		case 32:
			StringTable = h->elf32->StringTable;
			for (i = 0; i < h->elf32->ehdr->e_shnum; i++) {
				if (!strcmp(&StringTable[h->elf32->shdr[i].sh_name], section_name)) {
					return &h->map[h->elf32->shdr[i].sh_offset];
				}
			}
			break;
		case 64:
		 	StringTable = h->elf64->StringTable;
                        for (i = 0; i < h->elf64->ehdr->e_shnum; i++) {
                                if (!strcmp(&StringTable[h->elf64->shdr[i].sh_name], section_name)) {
                                        return &h->map[h->elf64->shdr[i].sh_offset];
                                }
                        }
			break;
	}
	
    return NULL;
}

char *get_dt_strtab_name(struct handle *h, int xset)
{
        static char *dyn_strtbl;

        if (!dyn_strtbl && !(dyn_strtbl = get_section_data(h, ".dynstr"))) 
                printf("[!] Could not locate .dynstr section\n");
  
        return dyn_strtbl + xset;
}

void parse_dynamic_dt_needed(struct handle *h)
{
        char *symstr;
        int i, n_entries;
	Elf32_Dyn *dyn32;
	Elf64_Dyn *dyn64;

        locate_dynamic_segment(h);
        h->lnc = 0;

	switch(opts.arch) {
		case 32:
        		dyn32 = h->elf32->dyn;
        		for (i = 0; dyn32[i].d_tag != DT_NULL; i++) {
                		if (dyn32[i].d_tag == DT_NEEDED) {
                        		symstr = get_dt_strtab_name(h, dyn32[i].d_un.d_val);
                        		h->libnames[h->lnc++] = (char *)xstrdup(symstr);
                		}
      			}
			break;
		case 64:
			dyn64 = h->elf64->dyn;
			for (i = 0; dyn64[i].d_tag != DT_NULL; i++) {
                                if (dyn64[i].d_tag == DT_NEEDED) {
                                        symstr = get_dt_strtab_name(h, dyn64[i].d_un.d_val);
                                        h->libnames[h->lnc++] = (char *)xstrdup(symstr);
                                }
                        }
			break;
		}
}

/*
 * This function attempts to get an ascii string
 * from a pointer location.
 */
#ifdef __x86_64__
char *getstr(unsigned long addr, int pid)
{	
	int i, j, c;
	uint8_t buf[sizeof(long)];
	char *string = (char *)HeapAlloc(256);
	unsigned long vaddr;
	
	string[0] = '"';
	for (c = 1, i = 0; i < 256; i += sizeof(long)) {
		vaddr = addr + i;

		if (pid_read(pid, buf, (void *)vaddr, sizeof(long)) == -1) {
			fprintf(stderr, "pid_read() failed: %s <0x%lx>\n", strerror(errno), vaddr);
			exit(-1);
		}
 
		for (j = 0; j < sizeof(long); j++) {

			if (buf[j] == '\n') {
				string[c++] = '\\';
				string[c++] = 'n';
				continue;
			}
			if (buf[j] == '\t') {
				string[c++] = '\\';
				string[c++] = 't';
				continue;
			}

			if (buf[j] != '\0' && isascii(buf[j]))
				string[c++] = buf[j];
			else
				goto out;
		}
	}
	
out:
	string[c++] = '"';
	string[c] = '\0';

	return string;	

}
#endif

#ifdef __x86_64__
char *getargs(struct user_regs_struct *reg, int pid, struct address_space *addrspace)
{
	unsigned char buf[12];
	int i, c, in_ptr_range = 0, j;
	char *args[256], *p;
	char tmp[512], *s;
	long val;
	char *string = (char *)HeapAlloc(MAXSTR);
	unsigned int maxstr = MAXSTR;
	unsigned int b;

	
	/* x86_64 supported only at this point--
	 * We are essentially parsing this
	 * calling convention here:
	     	mov    %rsp,%rbp
 	    	mov    $0x6,%r9d
  	  	mov    $0x5,%r8d
  	       	mov    $0x4,%ecx
  	       	mov    $0x3,%edx
  	       	mov    $0x2,%esi
 	       	mov    $0x1,%edi
  	     	callq  400144 <func>
	*/
	

	for (c = 0, in_ptr_range = 0, i = 0; i < 35; i += 5) {
		
		val = reg->rip - i;
		if (pid_read(pid, buf, (void *)val, 8) == -1) {
			fprintf(stderr, "pid_read() failed [%d]: %s <0x%llx>\n", pid, strerror(errno), reg->rip);
			exit(-1);
		}
		
		in_ptr_range = 0;
		if (buf[0] == 0x48 && buf[1] == 0x89 && buf[2] == 0xe5) // mov %rsp, %rbp
			break;
		switch((unsigned char)buf[0]) {
			case 0xbf:
				if (opts.typeinfo || opts.getstr) {
					for (j = 0; j < 4; j++) {
						if (reg->rdi >= addrspace[j].svaddr && reg->rdi <= addrspace[j].evaddr) {
							in_ptr_range++;
							switch(j) {
								case TEXT_SPACE:
									if (opts.getstr) {
										s = getstr((unsigned long)reg->rdi, pid);
										if (s) {
											snprintf(tmp, sizeof(tmp), "%s", s);
											args[c++] = xstrdup(tmp);
											break;
										}
									}
									sprintf(tmp, "(text_ptr *)0x%llx", reg->rdi);
									break;
								case DATA_SPACE:
							        	if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rdi, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
									sprintf(tmp, "(data_ptr *)0x%llx", reg->rdi);
									break;
								case HEAP_SPACE:
							       		if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rdi, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }

									sprintf(tmp, "(heap_ptr *)0x%llx", reg->rdi);
									break;
								case STACK_SPACE:
									 if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rdi, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
									sprintf(tmp, "(stack_ptr *)0x%llx", reg->rdi);
									break;
							}
						}
					}
					if (!in_ptr_range) {
						sprintf(tmp, "0x%llx",reg->rdi);
					}	
					if (!s)
						args[c++] = xstrdup(tmp);
					break;
				}
				sprintf(tmp, "0x%llx", reg->rdi);
				args[c++] = xstrdup(tmp);
				break;
			case 0xbe:
			        if (opts.typeinfo) {
                                        for (j = 0; j < 4; j++) {
                                                if (reg->rsi >= addrspace[j].svaddr && reg->rsi <= addrspace[j].evaddr) {
                                                        in_ptr_range++;
                                                        switch(j) {
                                                                case TEXT_SPACE:
                                                                        if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rsi, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }

                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                                case DATA_SPACE:
									 if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rsi, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }

                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                                case HEAP_SPACE:
									 if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rsi, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }

                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                                case STACK_SPACE:
									 if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rsi, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }

                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->rsi);
                                                                        break;
                                                        }
                                                }
                                        }
                                        if (!in_ptr_range) {
                                                sprintf(tmp, "0x%llx", reg->rsi);
                                        }
					if (!s)
						args[c++] = xstrdup(tmp);
					break;
                                }

				sprintf(tmp, "0x%llx", reg->rsi);
				args[c++] = xstrdup(tmp);
				break;
			case 0xba:
	                         if (opts.typeinfo) {
                                        for (j = 0; j < 4; j++) {
                                                if (reg->rdx >= addrspace[j].svaddr && reg->rdx <= addrspace[j].evaddr) {
                                                        in_ptr_range++;
                                                        switch(j) {
                                                                case TEXT_SPACE:
                                                                        if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rdx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }

                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                                case DATA_SPACE:
							        	if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rdx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                                case HEAP_SPACE:
			                                        	if (opts.getstr) {				
                                                                                s = getstr((unsigned long)reg->rdx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                                case STACK_SPACE:
									if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rdx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->rdx);
                                                                        break;
                                                        }
                                                }
                                        }
                                        if (!in_ptr_range) {
                                                sprintf(tmp, "0x%llx", reg->rdx);
                                        }
					if (!s)
						args[c++] = xstrdup(tmp);
					break;
                                }

				sprintf(tmp, "0x%llx", reg->rdx);
				args[c++] = xstrdup(tmp);
				break;
			case 0xb9:
                        	if (opts.typeinfo) {
                                        for (j = 0; j < 4; j++) {
                                                if (reg->rcx >= addrspace[j].svaddr && reg->rcx <= addrspace[j].evaddr) {
                                                        in_ptr_range++;
                                                        switch(j) {
                                                                case TEXT_SPACE:
									if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rcx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                                case DATA_SPACE:
									if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rcx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                                case HEAP_SPACE:
									if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rcx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }
                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                                case STACK_SPACE:
							        	if (opts.getstr) {
                                                                                s = getstr((unsigned long)reg->rcx, pid);
                                                                                if (s) {
                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        args[c++] = xstrdup(tmp);
                                                                                        break;
                                                                                }
                                                                        }

                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->rcx);
                                                                        break;
                                                        }
                                                }
                                        }
                                        if (!in_ptr_range) {
                                                sprintf(tmp, "0x%llx", reg->rcx);
                                        }
					if (!s)
						args[c++] = xstrdup(tmp);
					break;
                                }

				sprintf(tmp, "0x%llx", reg->rcx);
				args[c++] = xstrdup(tmp);
				break;
			case 0x41:
				switch((unsigned char)buf[1]) {
					case 0xb8:
				        	if (opts.typeinfo) {
                                        		for (j = 0; j < 4; j++) {
                                                		if (reg->r8 >= addrspace[j].svaddr && reg->r8 <= addrspace[j].evaddr) {
                                                        		in_ptr_range++;
                                                        		switch(j) {
                                                                		case TEXT_SPACE:
 			                                                        	if (opts.getstr) {
                                                                                		s = getstr((unsigned long)reg->r8, pid);
                                                                                		if (s) {
                                                                                        		snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                        		args[c++] = xstrdup(tmp);
                                                                                        		break;
                                                                                		}
                                                                        		}
                                                                        		sprintf(tmp, "(text_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                                		case DATA_SPACE:
											if (opts.getstr) {
                                                                                                s = getstr((unsigned long)reg->r8, pid);
                                                                                                if (s) {
                                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                                        args[c++] = xstrdup(tmp);
                                                                                                        break;
                                                                                                }
                                                                                        }
                                                                        		sprintf(tmp, "(data_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                                		case HEAP_SPACE:
                                                                                        if (opts.getstr) {
                                                                                                s = getstr((unsigned long)reg->r8, pid);
                                                                                                if (s) {
                                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                                        args[c++] = xstrdup(tmp);
                                                                                                        break;
                                                                                                }
                                                                                        }
                                                                        		sprintf(tmp, "(heap_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                                		case STACK_SPACE:
											if (opts.getstr) {
                                                                                                s = getstr((unsigned long)reg->r8, pid);
                                                                                                if (s) {
                                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                                        args[c++] = xstrdup(tmp);
                                                                                                        break;
                                                                                                }
                                                                                        }
                                                                        		sprintf(tmp, "(stack_ptr *)0x%llx", reg->r8);
                                                                        		break;
                                                        		}
                                                		}
                                        		}
                                        		if (!in_ptr_range) {
                                                		sprintf(tmp, "0x%llx", reg->r8);
                                        		}
							if (!s)
								args[c++] = xstrdup(tmp);
							break;
                                		}
						
						sprintf(tmp, "0x%llx", reg->r8);
						args[c++] = xstrdup(tmp);
						break;
					case 0xb9:
					        if (opts.typeinfo) {
                                                        for (j = 0; j < 4; j++) {
                                                                if (reg->r9 >= addrspace[j].svaddr && reg->r9 <= addrspace[j].evaddr) {
                                                                        in_ptr_range++;
                                                                        switch(j) {
                                                                                case TEXT_SPACE:
											if (opts.getstr) {
                                                                                                s = getstr((unsigned long)reg->r9, pid);
                                                                                                if (s) {
                                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                                        args[c++] = xstrdup(tmp);
                                                                                                        break;
                                                                                                }
                                                                                        }
                                                                                        sprintf(tmp, "(text_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                                case DATA_SPACE:
											if (opts.getstr) {
                                                                                                s = getstr((unsigned long)reg->r9, pid);
                                                                                                if (s) {
                                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                                        args[c++] = xstrdup(tmp);
                                                                                                        break;
                                                                                                }
                                                                                        }
                                                                                        sprintf(tmp, "(data_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                                case HEAP_SPACE:
											  if (opts.getstr) {
                                                                                                s = getstr((unsigned long)reg->r9, pid);
                                                                                                if (s) {
                                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                                        args[c++] = xstrdup(tmp);
                                                                                                        break;
                                                                                                }
                                                                                        }
                                                                                        sprintf(tmp, "(heap_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                                case STACK_SPACE:
											  if (opts.getstr) {
                                                                                                s = getstr((unsigned long)reg->r9, pid);
                                                                                                if (s) {
                                                                                                        snprintf(tmp, sizeof(tmp), "%s", s);
                                                                                                        args[c++] = xstrdup(tmp);
                                                                                                        break;
                                                                                                }
                                                                                        }
                                                                                        sprintf(tmp, "(stack_ptr *)0x%llx", reg->r9);
                                                                                        break;
                                                                        }       
                                                                }
                                                        }
                                                        if (!in_ptr_range) {
                                                                sprintf(tmp, "0x%llx", reg->r9);
                                                        }
							if (!s)
								args[c++] = xstrdup(tmp);
							break;       
                                                }

						sprintf(tmp, "0x%llx", reg->r9);
						args[c++] = xstrdup(tmp);
						break;
				}
		}
	}

	/*
	 * XXX pre-allocation for strcpy/strcat, tested with super long function name
	 */
	if (c == 0)
		return NULL;
	
	for (b = 0, i = 0; i < c; i++) 
		b += strlen(args[i]) + 1; // len + ','
	if (b > maxstr + 2) { // maxstr + 2 braces
		string = realloc((char *)string, maxstr + (b - (maxstr + 2)) + 1);
		maxstr += (b - maxstr) + 3;
	}
	
	string[0] = '(';
        strcpy((char *)&string[1], args[0]);
        strcat(string, ",");
        
        for (i = 1; i < c; i++) {
                strcat(string, args[i]);
                strcat(string, ",");
        }
                
        if ((p = strrchr(string, ','))) 
                *p = '\0';
        strcat(string, ")");
        return string;

}
#endif

int distance(unsigned long a, unsigned long b)
{
	return ((a > b) ? (a - b) : (b - a));
}

/*
 * Our main handler function to parse ELF info
 * read instructions, parse them, and print
 * function calls and stack args.
 */
void examine_process(struct handle *h)
{
	
	int symmatch = 0, cflow_change = 0;
	int i, count, status, in_routine = 0; 
	struct user_regs_struct pt_reg;
	long esp, eax, ebx, edx, ecx, esi, edi, eip;
	uint8_t buf[8];
	unsigned long vaddr;
	unsigned int offset;
	char *argstr = NULL, subname[255], output[512], *sh_src, *sh_dst;
	long ret = 0, event;
	unsigned long retaddr, cip, current_ip;
	struct call_list *call_list = NULL;
	struct branch_instr *branch;
	struct address_space *addrspace = (struct address_space *)HeapAlloc(sizeof(struct address_space) * MAX_ADDR_SPACE); 

	callstack_t callstack;
	calldata_t calldata;
	calldata_t *calldp;

	global_pid = h->pid;
	/*
	 * Allocate ELF structure for
	 * specified Arch, and map in 
	 * the executable file for the
	 * file we are examining.
	 */
	switch(opts.arch) {
		case 32:
			h->elf32 = HeapAlloc(sizeof(struct elf32));
			h->elf64 = NULL;
			MapElf32(h);
			break;
		case 64:
			h->elf64 = HeapAlloc(sizeof(struct elf64));
			h->elf32 = NULL;
			MapElf64(h);
			break;
	}

	/*
	 * Build ELF Symbol information
	 */
	BuildSyms(h);
	
	/* 
	 * Retrieve the program address space layout
	 * to aid in our pointer/type prediction
	 */
	get_address_space((struct address_space *)addrspace, h->pid, h->path);

	if (opts.elfinfo) {
		printf("[+] Printing Symbol Information:\n\n");
		for (i = 0; i < h->lsc; i++) {
			if (h->lsyms[i].name == NULL)
				printf("UNKNOWN: 0x%lx\n", h->lsyms[i].value);
			else
				printf("%s 0x%lx\n", h->lsyms[i].name, h->lsyms[i].value);
		}
		for (i = 0; i < h->dsc; i++) {
			if (h->lsyms[i].name == NULL)
				printf("UNKNOWN: 0x%lx\n", h->lsyms[i].value);
			else
				printf("%s 0x%lx\n", h->dsyms[i].name, h->dsyms[i].value);
		}
		
		printf("\n[+] Printing shared library dependencies:\n\n");
		
		parse_dynamic_dt_needed(h);
		for (i = 0; i < h->lnc; i++) {
			printf("[%d]\t%s\n", i + 1, h->libnames[i]);
		}
	}
	
	if (opts.verbose ) {
	 	printf("[+] Printing the address space layout\n");
                printf("0x%lx-0x%lx %s [text]\n", addrspace[TEXT_SPACE].svaddr, addrspace[TEXT_SPACE].evaddr, h->path);
                printf("0x%lx-0x%lx %s [data]\n", addrspace[DATA_SPACE].svaddr, addrspace[DATA_SPACE].evaddr, h->path);
                printf("0x%lx-0x%lx %s [heap]\n", addrspace[HEAP_SPACE].svaddr, addrspace[HEAP_SPACE].evaddr, h->path);
                printf("0x%lx-0x%lx %s [stack]\n",addrspace[STACK_SPACE].svaddr, addrspace[STACK_SPACE].evaddr, h->path);
	}

	/*
	 * Initiate our call frame stack
	 */
	callstack_init(&callstack);

	printf("\n[+] Function tracing begins here:\n");
        for (;;) {

                ptrace (PTRACE_SINGLESTEP, h->pid, NULL, NULL);
                wait (&status);
                count++;
	//	ptrace(PTRACE_GETREGS, h->pid, NULL, &pt_reg);
					
                if (WIFEXITED (status))
                	break;
		
                ptrace (PTRACE_GETREGS, h->pid, NULL, &pt_reg);
#ifdef __x86_64__
		esp = pt_reg.rsp;
		eip = pt_reg.rip;
		eax = pt_reg.rax;
		ebx = pt_reg.rbx;
		ecx = pt_reg.rcx;
		edx = pt_reg.rdx;
		esi = pt_reg.rsi;
		edi = pt_reg.rdi;
#else
		esp = pt_reg.esp;
		eip = pt_reg.eip;
		eax = pt_reg.eax;
		ebx = pt_reg.ebx;
		ecx = pt_reg.ecx;
		edx = pt_reg.edx;
		esi = pt_reg.esi;
		edi = pt_reg.edi;
#endif
		if (pid_read(h->pid, buf, (void *)eip, 8) < 0) {
			fprintf(stderr, "pid_read() failed: %s <0x%lx>\n", strerror(errno), eip);
			exit(-1);
		}
		
		
		if (opts.cflow) {	
			
			/*
			 * If eip is outside of our binary and in say a shared
			 * object then we don't look at the control flow.
			 */
			if (eip < addrspace[TEXT_SPACE].svaddr || eip > addrspace[TEXT_SPACE].evaddr)
				continue;
			
			if (branch = search_branch_instr(buf[0])) {
				
				ptrace(PTRACE_SINGLESTEP, h->pid, NULL, NULL);
				wait(&status);

				ptrace(PTRACE_GETREGS, h->pid, NULL, &pt_reg);
#ifdef __x86_64__
				current_ip = pt_reg.rip;
#else
				current_ip = pt_reg.eip;
#endif
				
				if (distance(current_ip, eip) > BRANCH_INSTR_LEN_MAX) {
					cflow_change = 1;
					sh_src = get_section_by_range(h, eip);
					sh_dst = get_section_by_range(h, current_ip);
					printf("%s(CONTROL FLOW CHANGE [%s]):%s Jump from %s 0x%lx into %s 0x%lx\n", YELLOW, branch->mnemonic, WHITE,
					!sh_src?"<unknown section>":sh_src, eip, 
					!sh_dst?"<unknown section>":sh_src, current_ip);
				} 

				if (cflow_change) {
					cflow_change = 0;
					continue;
				}

			}
		}

		/*
		 * Did we hit a breakpoint (Return address?)
		 * if so, then we check eax to get the return
		 * value, and pop the call data from the stack,
		 * which will remove the breakpoint as well.
		 */
		if (buf[0] == 0xcc) {
			calldp = callstack_peek(&callstack);
                        if (calldp != NULL) {
                                if (calldp->retaddr == eip) {
					snprintf(output, sizeof(output), "%s(RETURN VALUE) %s%s = %lx\n", RED, WHITE, calldp->string, eax);
					
					/*
					 * Pop call stack and remove the
					 * breakpoint at its return address.
					 */
					fprintf(stdout, "%s", output);
                                        calldp = callstack_pop(&callstack);
					free(calldp->string);
					free(calldp->symname);
				}
			}
		}
		
		
		/*
		 * As we catch each immediate call
		 * instruction, we use callstack_push()
		 * to push the call data onto our stack
		 * and set a breakpoint at the return
		 * address of the function call so that we
		 * can get the retrun value with the code above.
		 */
		if (buf[0] == 0xe8) {
			
			offset = buf[1] + (buf[2] << 8) + (buf[3] << 16) + (buf[4] << 24);
			vaddr = eip + offset + 5; 
			vaddr &= 0xffffffff;

			for (i = 0; i < h->lsc; i++) {
				if (vaddr == h->lsyms[i].value) {
#ifdef __x86_64__
					argstr = getargs(&pt_reg, h->pid, addrspace);
#endif
					if (argstr == NULL)
						printf("%sLOCAL_call@0x%lx:%s%s()\n", GREEN, h->lsyms[i].value,  WHITE, !h->lsyms[i].name?"<unknown>":h->lsyms[i].name);
					else
						printf("%sLOCAL_call@0x%lx:%s%s%s\n", GREEN, h->lsyms[i].value, WHITE,  h->lsyms[i].name, argstr);

					calldata.symname = xstrdup(h->lsyms[i].name);
					calldata.vaddr = h->lsyms[i].value;
					calldata.retaddr = eip + 5;
					if (argstr == NULL) 
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: %s()", h->lsyms[i].value, !h->lsyms[i].name?"<unknown>":h->lsyms[i].name);
					else
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: %s%s", h->lsyms[i].value, h->lsyms[i].name, argstr);
					
					if (opts.verbose)
						printf("Return address for %s: 0x%lx\n", calldata.symname, calldata.retaddr);
					callstack_push(&callstack, &calldata);
					symmatch = 1;
				}
				
			}
			for (i = 0; i < h->dsc; i++) {
				if (vaddr == h->dsyms[i].value) {
#ifdef __x86_64__
					argstr = getargs(&pt_reg, h->pid, addrspace);
#endif
					if (argstr == NULL)
                                                printf("%sPLT_call@0x%lx:%s%s()\n", GREEN, h->dsyms[i].value, WHITE, !h->dsyms[i].name?"<unknown>":h->dsyms[i].name);
                                        else
                                                printf("%sPLT_call@0x%lx:%s%s%s\n", GREEN, h->dsyms[i].value, WHITE, h->dsyms[i].name, argstr);



					calldata.symname = xstrdup(h->dsyms[i].name);
                                        calldata.vaddr = h->dsyms[i].value;
                                        calldata.retaddr = eip + 5;
					if (argstr == NULL)
						calldata.string = xfmtstrdup("PLT_call@0x%lx: %s()", h->dsyms[i].value, !h->dsyms[i].name?"<unknown>":h->dsyms[i].name);
					else
						calldata.string = xfmtstrdup("PLT_call@0x%lx: %s%s", h->dsyms[i].value, h->dsyms[i].name, argstr);
					if (opts.verbose)
						printf("Return address for %s: 0x%lx\n", calldata.symname, calldata.retaddr);
                                        callstack_push(&callstack, &calldata);
                                        symmatch = 1;
				}
			}
			
			if (opts.stripped) {
				if (symmatch) {
					symmatch = 0;
				} else {
#ifdef __x86_64__
					argstr = getargs(&pt_reg, h->pid, addrspace);
#endif
					if (argstr == NULL)
						printf("%sLOCAL_call@0x%lx:%ssub_%lx()\n", GREEN, vaddr, WHITE, vaddr);
					else
						printf("%sLOCAL_call@0x%lx:%ssub_%lx%s\n", GREEN, vaddr, WHITE, vaddr, argstr);

					snprintf(subname, sizeof(subname) - 1, "sub_%lx%s", vaddr, argstr == NULL ? "()" : argstr);
					calldata.symname = xstrdup(subname);
                                        calldata.vaddr = vaddr;
                                        calldata.retaddr = eip + 5;
					if (argstr == NULL)
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: sub_%lx()", vaddr, vaddr);
					else
						calldata.string = xfmtstrdup("LOCAL_call@0x%lx: sub_%lx%s", vaddr, vaddr, argstr);
                                        callstack_push(&callstack, &calldata);
                                        symmatch = 1;

				}
			}

			if (argstr) {
				free(argstr);
				argstr = NULL;
			}

 
		}
		
				
	}

}

void MapElf32(struct handle *h)
{
	int fd;
	struct stat st;
	
	if ((fd = open(h->path, O_RDONLY)) < 0) {
		fprintf(stderr, "Unable to open %s: %s\n", h->path, strerror(errno));
		exit(-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(-1);
	}

	h->map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (h->map == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}

	h->elf32->ehdr = (Elf32_Ehdr *)h->map;
	h->elf32->shdr = (Elf32_Shdr *)(h->map + h->elf32->ehdr->e_shoff);
	h->elf32->phdr = (Elf32_Phdr *)(h->map + h->elf32->ehdr->e_phoff);
	
	h->elf32->StringTable = (char *)&h->map[h->elf32->shdr[h->elf32->ehdr->e_shstrndx].sh_offset];

 	if (h->elf32->ehdr->e_shnum > 0 && h->elf32->ehdr->e_shstrndx != SHN_UNDEF)
                load_elf_section_range(h);
}

/*
 * Parse /proc/<pid>/maps to get address space layout
 * of executable text/data, heap, stack.
 */
void get_address_space(struct address_space *addrspace, int pid, char *path)
{
	char tmp[64], buf[256];
        char *p, addrstr[32];
	FILE *fd;
        int i, lc;
	
        snprintf(tmp, 64, "/proc/%d/maps", pid);

        if ((fd = fopen(tmp, "r")) == NULL) {
                fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
                exit(-1);
        }
	
        for (lc = 0, p = buf; fgets(buf, sizeof(buf), fd) != NULL; lc++) {
		/*
		 * Get executable text and data
	 	 * segment addresses.
		 */
		if ((char *)strchr(buf, '/') && lc == 0) {
			for (i = 0; *p != '-'; i++, p++) 
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[TEXT_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[TEXT_SPACE].evaddr = strtoul(addrstr, NULL, 16);
			addrspace[TEXT_SPACE].size = addrspace[TEXT_SPACE].evaddr - addrspace[TEXT_SPACE].svaddr;
		}
		
		if ((char *)strchr(buf, '/') && strstr(buf, path) && strstr(buf, "rw-p")) {
			for (i = 0, p = buf; *p != '-'; i++, p++)
				addrstr[i] = *p;				
			addrstr[i] = '\0';
			addrspace[DATA_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[DATA_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[DATA_SPACE].size = addrspace[DATA_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
		}
		/*
		 * Get the heap segment address layout
	 	 */
		if (strstr(buf, "[heap]")) {
			for (i = 0, p = buf; *p != '-'; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[HEAP_SPACE].svaddr = strtoul(addrstr, NULL, 16);
			for (p = p + 1, i = 0; *p != 0x20; i++, p++)
				addrstr[i] = *p;
			addrstr[i] = '\0';
			addrspace[HEAP_SPACE].evaddr = strtoul(addrstr, NULL, 16);
			addrspace[HEAP_SPACE].size = addrspace[HEAP_SPACE].evaddr - addrspace[DATA_SPACE].svaddr;
		}
		/*
		 * Get the stack segment layout
		 */
		if (strstr(buf, "[stack]")) {
			 for (i = 0, p = buf; *p != '-'; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].svaddr = strtoul(addrstr, NULL, 16);
                        for (p = p + 1, i = 0; *p != 0x20; i++, p++)
                                addrstr[i] = *p;
                        addrstr[i] = '\0';
                        addrspace[STACK_SPACE].evaddr = strtoul(addrstr, NULL, 16);
                        addrspace[STACK_SPACE].size = addrspace[STACK_SPACE].evaddr - addrspace[STACK_SPACE].svaddr;
                }
	 }
}

char * get_path(int pid)
{
	char tmp[64], buf[256];
	char path[256], *ret, *p;
	FILE *fd;
	int i;
	
	snprintf(tmp, 64, "/proc/%d/maps", pid);
	
	if ((fd = fopen(tmp, "r")) == NULL) {
		fprintf(stderr, "Unable to open %s: %s\n", tmp, strerror(errno));
		exit(-1);
	}
	
	if (fgets(buf, sizeof(buf), fd) == NULL)
		return NULL;
	p = strchr(buf, '/');
	if (!p)
		return NULL;
	for (i = 0; *p != '\n' && *p != '\0'; p++, i++)
		path[i] = *p;
	path[i] = '\0';
	ret = (char *)HeapAlloc(i + 1);
	strcpy(ret, path);
	if (strstr(ret, ".so")) {
		fprintf(stderr, "Process ID: %d appears to be a shared library; file must be an executable. (path: %s)\n",pid, ret);
		exit(-1);
	}
	return ret;
}

int validate_em_type(char *path)
{
	int fd;
	uint8_t *mem, *p;
	unsigned int value;
	Elf64_Ehdr *ehdr64;
	Elf32_Ehdr *ehdr32;

	if ((fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Could not open %s: %s\n", path, strerror(errno));
		exit(-1);
	}
	
	mem = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(-1);
	}
	
	switch (opts.arch) {
		case 32:
			ehdr32 = (Elf32_Ehdr *)mem;
			if (ehdr32->e_machine != EM_386)
				return 0;
			break;
		case 64:
			ehdr64 = (Elf64_Ehdr *)mem;
			if (ehdr64->e_machine != EM_X86_64 && ehdr64->e_machine != EM_IA_64)
				return 0;
			break;
	}
	return 1;
}

	
void load_elf_section_range(struct handle *h)
{
	
	Elf32_Ehdr *ehdr32;
	Elf32_Shdr *shdr32;
	Elf64_Ehdr *ehdr64;
	Elf64_Shdr *shdr64;

	char *StringTable;
	int i;

	h->shdr_count = 0;
	switch(opts.arch) {
		case 32:
			StringTable = h->elf32->StringTable;
			ehdr32 = h->elf32->ehdr;
			shdr32 = h->elf32->shdr;
			
			for (i = 0; i < ehdr32->e_shnum; i++) {
				h->sh_range[i].sh_name = xstrdup(&StringTable[shdr32[i].sh_name]);
				h->sh_range[i].sh_addr = shdr32[i].sh_addr;
				h->sh_range[i].sh_size = shdr32[i].sh_size;
				if (h->shdr_count == MAX_SHDRS)
					break;
				h->shdr_count++;
			}
			break;
		case 64:
		  	StringTable = h->elf64->StringTable;
                        ehdr64 = h->elf64->ehdr;
                        shdr64 = h->elf64->shdr;

                        for (i = 0; i < ehdr64->e_shnum; i++) {
                                h->sh_range[i].sh_name = xstrdup(&StringTable[shdr64[i].sh_name]);
                                h->sh_range[i].sh_addr = shdr64[i].sh_addr;
                                h->sh_range[i].sh_size = shdr64[i].sh_size;
				if (h->shdr_count == MAX_SHDRS)
					break;
				h->shdr_count++;
                        }
                        break;
		
	}
	
}
	
char * get_section_by_range(struct handle *h, unsigned long vaddr)
{
	int i;

	for (i = 0; i < h->shdr_count; i++) {
		if (vaddr >= h->sh_range[i].sh_addr && vaddr <= h->sh_range[i].sh_addr + h->sh_range[i].sh_size)
			return h->sh_range[i].sh_name;
	}
	
	return NULL;
}
	


void MapElf64(struct handle *h)
{
	int fd;
        struct stat st;

        if ((fd = open(h->path, O_RDONLY)) < 0) {
                fprintf(stderr, "Unable to open %s: %s\n", h->path, strerror(errno));
                exit(-1);
        }

        if (fstat(fd, &st) < 0) {
                perror("fstat");
                exit(-1);
        }

        h->map = (uint8_t *)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (h->map == MAP_FAILED) {
                perror("mmap");
                exit(-1);
        }

        h->elf64->ehdr = (Elf64_Ehdr *)h->map;
        h->elf64->shdr = (Elf64_Shdr *)(h->map + h->elf64->ehdr->e_shoff);
        h->elf64->phdr = (Elf64_Phdr *)(h->map + h->elf64->ehdr->e_phoff);

        h->elf64->StringTable = (char *)&h->map[h->elf64->shdr[h->elf64->ehdr->e_shstrndx].sh_offset];
	
	if (h->elf64->ehdr->e_shnum > 0 && h->elf64->ehdr->e_shstrndx != SHN_UNDEF)
		load_elf_section_range(h);

}
void sighandle(int sig)
{
	fprintf(stdout, "Caught signal ctrl-C, detaching...\n");
	ptrace(PTRACE_DETACH, global_pid, NULL, NULL);
	exit(0);
}


int main(int argc, char **argv, char **envp)
{
	int opt, i, pid, status, skip_getopt = 0;
	struct handle handle;
	char **p, *arch;
	
        struct sigaction act;
        sigset_t set;
        act.sa_handler = sighandle;
        sigemptyset (&act.sa_mask);
        act.sa_flags = 0;
        sigaction (SIGINT, &act, NULL);
        sigemptyset (&set);
        sigaddset (&set, SIGINT);

	if (argc < 2) {
usage:
		printf("Usage: %s [-p <pid>] [-Sstve] <prog>\n", argv[0]);
		printf("[-p] Trace by PID\n");
		printf("[-t] Type detection of function args\n");
		printf("[-s] Print string values\n");
	//	printf("[-r] Show return values\n");
		printf("[-v] Verbose output\n");
		printf("[-e] Misc. ELF info. (Symbols,Dependencies)\n");
		printf("[-S] Show function calls with stripped symbols\n");
		printf("[-C] Complete control flow analysis\n");
		exit(0);
	}
	
	if (argc == 2 && argv[1][0] == '-')
		goto usage;

	memset(&opts, 0, sizeof(opts));
	
	opts.arch = 64; // default
	arch = getenv(FTRACE_ENV);
	if (arch != NULL) {
		switch(atoi(arch)) {
			case 32:
				opts.arch = 32;
				break;
			case 64:
				opts.arch = 64;
				break;
			default:
				fprintf(stderr, "Unknown architecture: %s\n", arch);
				break;
		}
	}
	
	if (argv[1][0] != '-') {
		
		handle.path = xstrdup(argv[1]);
		handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1);
		
		for (i = 0, p = &argv[1]; i != argc - 1; p++, i++) {
			*(handle.args + i) = xstrdup(*p);
		}
		*(handle.args + i) = NULL;
		skip_getopt = 1;
			
	} else {
		handle.path = xstrdup(argv[2]);
		handle.args = (char **)HeapAlloc(sizeof(char *) * argc - 1);
		
		for (i = 0, p = &argv[2]; i != argc - 2; p++, i++) {
			*(handle.args + i) = xstrdup(*p);
		}
		*(handle.args + i) = NULL;
	}

		
	if (skip_getopt)
		goto begin;

	while ((opt = getopt(argc, argv, "CSrhtvep:s")) != -1) {
		switch(opt) {
			case 'S':
				opts.stripped++;
				break;
			case 'r':
				opts.showret++;
				break;
			case 'v':
				opts.verbose++;
				break;
			case 'e':
				opts.elfinfo++;
				break;
			case 't':
				opts.typeinfo++;
				break;
			case 'p':
				opts.attach++;
				handle.pid = atoi(optarg);
				break;
			case 's':
				opts.getstr++;
				break;
			case 'C':
				opts.cflow++;
				break;
			case 'h':
				goto usage;
			default:
				printf("Unknown option\n");
				exit(0);
		}
	} 
	
begin:
	if (opts.verbose) {
		switch(opts.arch) {
			case 32:
				printf("[+] 32bit ELF mode enabled!\n");
				break;
			case 64:
				printf("[+] 64bit ELF mode enabled!\n");
				break;
		}
		if (opts.typeinfo) 
			printf("[+] Pointer type prediction enabled\n");
	}
	
	if (opts.arch == 32 && opts.typeinfo) {
		printf("[!] Option -t may not be used on 32bit executables\n");
		exit(0);
	}
	
	if (opts.arch == 32 && opts.getstr) {
		printf("[!] Option -s may not be used on 32bit executables\n");
		exit(0);
	}

	if (opts.getstr && opts.typeinfo) {
		printf("[!] Options -t and -s may not be used together\n");
		exit(0);
	}

	/*
	 * We are not attaching, but rather executing
	 * in this first instance
	 */
	if (!opts.attach) {
		
		if (!validate_em_type(handle.path)) {
			printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
			exit(-1);
		}
	
		if ((pid = fork()) < 0) {
			perror("fork");
			exit(-1);
		}
		
		if (pid == 0) {
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
              			perror("PTRACE_TRACEME");
              			exit(-1);
			}
			ptrace(PTRACE_SETOPTIONS, 0, 0, PTRACE_O_TRACEEXIT);
		  	execve(handle.path, handle.args, envp);
			exit(0);
		}
		waitpid(0, &status, WNOHANG);
		handle.pid = pid;
		global_pid = pid;
		examine_process(&handle);
		goto done;
	}

	/*  
	 * In this second instance we trace an
	 * existing process id.
	 */
	if (ptrace(PTRACE_ATTACH, handle.pid, NULL, NULL) == -1) {
		perror("PTRACE_ATTACH");
		exit(-1);
	}
	handle.path = get_path(handle.pid);
        if (!validate_em_type(handle.path)) {
        	printf("[!] ELF Architecture is set to %d, the target %s is not the same architecture\n", opts.arch, handle.path);
        	exit(-1);
       	}

	waitpid(handle.pid, &status, WUNTRACED);
	global_pid = handle.pid;
	examine_process(&handle);

	
done:
	printf("%s\n", WHITE);
	ptrace(PTRACE_DETACH, handle.pid, NULL, NULL);
	exit(0);

}
	


