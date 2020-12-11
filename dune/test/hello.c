#include <stdio.h>
#include <stdlib.h>

#include "libdune/dune.h"
#include "libdune/cpu-x86.h"

static void recover(void)
{
	printf("hello: recovered from divide by zero\n");
	exit(0);
}

static void divide_by_zero_handler(struct dune_tf *tf)
{
	printf("hello: caught divide by zero!\n");
	tf->rip = (uintptr_t) &recover;
}


static unsigned long long get_dr6(void)
{
unsigned long long value;

asm volatile("mov %%dr6,%0" : "=r" (value));
return value;
} 

static unsigned long long get_dr0(void)
{
unsigned long long value;

asm volatile("mov %%dr0,%0" : "=r" (value));
return value;
} 

static unsigned long long get_dr1(void)
{
unsigned long long value;

asm volatile("mov %%dr1,%0" : "=r" (value));
return value;
} 

static unsigned long long get_dr2(void)
{
unsigned long long value;

asm volatile("mov %%dr2,%0" : "=r" (value));
return value;
} 

static unsigned long long get_dr3(void)
{
unsigned long long value;

asm volatile("mov %%dr3,%0" : "=r" (value));
return value;
} 


static unsigned long long get_dr7(void)
{
unsigned long long value;

asm volatile("mov %%dr7,%0" : "=r" (value));
return value;
} 













int main(int argc, char *argv[])
{
	volatile int ret;


	unsigned long long dr6;
unsigned long long dr0;
unsigned long long dr1;
unsigned long long dr2;
unsigned long long dr3;

unsigned long long dr7;

	printf("hello: not running dune yet\n");

	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}
	printf("hello: now printing from dune mode\n");

	dr6=get_dr6();
dr0=get_dr0();
dr1=get_dr1();
dr2=get_dr2();
dr3=get_dr3();
dr7=get_dr7();

	printf("dr0 is %lx\n", dr0);

	printf("dr3 is %lx\n", dr3);

	printf("dr1 is %lx\n", dr1);

	printf("dr7 is %lx\n", dr7);


	//dune_register_intr_handler(T_DIVIDE, divide_by_zero_handler);

	//ret = 1 / ret; /* divide by zero */

	//printf("hello: we won't reach this call\n");

	return 0;
}

