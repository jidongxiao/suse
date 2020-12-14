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





void print_affinity() {
    cpu_set_t mask;
    long nproc, i;

    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_getaffinity");
        assert(false);
    }
    nproc = sysconf(_SC_NPROCESSORS_ONLN);
    printf("sched_getaffinity = ");
    for (i = 0; i < nproc; i++) {
        printf("%d ", CPU_ISSET(i, &mask));
    }
    printf("\n");
}


void do_someWork(int a ,int b){

	volatile int c;
	printf("Inside do_somework(), current CPU set, current cpu is  = %d\n", sched_getcpu());
	for(int i=0;i<100000;i++){
		c =c+a+b;
		//printf("C is %d\n",c);
		sleep(1);	
	}
}


int main(void) {
    cpu_set_t mask;
	
    printf(" First: current cpu is  = %d\n", sched_getcpu());	
    print_affinity();

//    printf("sched_getcpu = %d\n", sched_getcpu());
    CPU_ZERO(&mask);
    CPU_SET(1, &mask);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_setaffinity");
        assert(false);
    }
    printf(" After cpu is set to 1==> current cpu is  = %d\n", sched_getcpu());
    print_affinity();

//   printf("sched_getcpu = %d\n", sched_getcpu());
    do_someWork(1,2);
    printf("After do_somework(), current CPU set, current cpu is  = %d\n", sched_getcpu());
    print_affinity();

}
