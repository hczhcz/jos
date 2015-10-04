// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display the backtrace information", mon_backtrace },
	{ "time", "Run the command and display its time usage", mon_time }
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

// Lab1 only
// read the pointer to the retaddr on the stack
static uint32_t
read_pretaddr() {
    uint32_t pretaddr;
    __asm __volatile("leal 4(%%ebp), %0" : "=r" (pretaddr));
    return pretaddr;
}

void
do_overflow(void)
{
    cprintf("Overflow success\n");
}

void
start_overflow(void)
{
    char str[256] = {'2'};
    char *pret_addr;
    char *old_addr;
    unsigned char pos;
    int i;

	for (i = 1; i < 256; ++i)
		str[i] = '3';

	pret_addr = (char *) read_pretaddr();
	old_addr = *(char **) pret_addr;
	cprintf("%x ", do_overflow);
	cprintf("%x ", old_addr);

#define PUT_OVERFLOW_CHAR(value, offset) \
	do { \
		pos = (value); \
		str[pos] = 0; \
		cprintf("%s%n", str, pret_addr + (offset)); \
		str[pos] = pos ? '3' : '2'; \
	} while (0)

	PUT_OVERFLOW_CHAR((uint32_t) do_overflow      , 0);
	PUT_OVERFLOW_CHAR((uint32_t) do_overflow >>  8, 1);
	PUT_OVERFLOW_CHAR((uint32_t) do_overflow >> 16, 2);
	PUT_OVERFLOW_CHAR((uint32_t) do_overflow >> 24, 3);
	PUT_OVERFLOW_CHAR((uint32_t) old_addr      , 4);
	PUT_OVERFLOW_CHAR((uint32_t) old_addr >>  8, 5);
	PUT_OVERFLOW_CHAR((uint32_t) old_addr >> 16, 6);
	PUT_OVERFLOW_CHAR((uint32_t) old_addr >> 24, 7);
}

void
overflow_me(void)
{
	start_overflow();
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// TODO: lab1
	overflow_me();
	// cprintf("Backtrace success\n");

	cprintf("Stack backtrace:\n");

	uint32_t eip, ebp, arg;
	struct Eipdebuginfo info;
	int i;

	eip = read_eip();
	__asm __volatile("movl %%ebp, %0" : "=r" (ebp));

	for (; ebp; ebp = ((uint32_t *) ebp)[0], eip = ((uint32_t *) ebp)[1]) {
		debuginfo_eip(eip, &info);
		cprintf("  eip %08x  ebp %08x  args", eip, ebp);
		//for (i = 0; i < info.eip_fn_narg; ++i) {
		for (i = 0; i < 5; ++i) {
			cprintf(" %08x", ((uint32_t *) ebp)[i + 2]);
		}
		cprintf("\n\t%s:%d: ", info.eip_file, info.eip_line);
		for (i = 0; i < info.eip_fn_namelen; ++i)
			cputchar(info.eip_fn_name[i]);
		cprintf("%+d\n", eip - info.eip_fn_addr);
	}

	return 0;
}

int
mon_time(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[1], commands[i].name) == 0) {
			uint32_t time_lo;
			uint32_t time_hi;
			uint32_t time_lo_2;
			uint32_t time_hi_2;

			register int ret;

			__asm __volatile(
				"rdtsc\n"
				"movl %%eax, %0\n"
				"movl %%edx, %1\n"
				: "=a" (time_lo), "=d" (time_hi)
			);
			ret = commands[i].func(argc - 1, argv + 1, tf);
			__asm __volatile(
				"rdtsc\n"
				"movl %%eax, %0\n"
				"movl %%edx, %1\n"
				: "=a" (time_lo_2), "=d" (time_hi_2)
			);
			// cprintf("%x %x %x %x ", time_hi, time_lo, time_hi_2, time_lo_2);
			uint64_t time_full = (uint64_t) time_lo ^ ((uint64_t) time_hi << 32);
			uint64_t time_full_2 = (uint64_t) time_lo_2 ^ ((uint64_t) time_hi_2 << 32);
			cprintf("%s cycles: %lld\n", argv[1], time_full_2 - time_full);
		}
	}

	return 42;
}

/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
