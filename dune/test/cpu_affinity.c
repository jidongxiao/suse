#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "../libdune/dune.h"
#include "../libdune/cpu-x86.h"


void do_someWork(int a ,int b){

	volatile int c;
	printf("Inside do_somework(), current CPU set, current cpu is  = %d\n", sched_getcpu());
	for(int i=0;i<100000;i++){
		c =c+a+b;
		//printf("C is %d\n",c);
		sleep(.1);	
	}
}

int main(int argc, char *argv[])
{


	cpu_set_t mask;
	
    	printf(" First: current cpu is  = %d\n", sched_getcpu());	


	CPU_ZERO(&mask);
	CPU_SET(1, &mask);
	if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        	perror("sched_setaffinity");
        	assert(false);
    	}
    	printf(" After cpu is set to 1==> current cpu is  = %d\n", sched_getcpu());
    
        volatile int ret;
	printf("hello: not running dune yet\n");
	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}

	printf("hello: now printing from dune mode\n");
	do_someWork(1,2);
	printf(" After dune ==> current cpu is  = %d\n", sched_getcpu());


    return 0;
}
