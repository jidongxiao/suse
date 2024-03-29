#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <immintrin.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <x86intrin.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/resource.h>


#include "libdune/dune.h"
#include "libdune/cpu-x86.h"

#define idcache 0

// return CR0 current value
u64 get_cr0(void){
    u64 cr0;
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "mov %%eax, %0\n\t"
    : "=m" (cr0)
    : /* no input */
    : "%rax"
    );
    return cr0;
}



int set_no_fill_mode(int idcacheNum){

    long nproc,i;
    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu
    switch (idcacheNum) {
        case 0:
            // enable no-fill mode for cpu 0-3
            printf("Inside cache set 1\n");
            for (i = 0; i < nproc; i++) {

                // avoiding cpu1
                if(i!=1){
                    cpu_set_t mask;
                    CPU_ZERO(&mask);
                    CPU_SET(i, &mask); // setting cpu affinity

                    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                        perror("sched_getaffinity");
                        assert(false);
                    }

                    printf("\n\nSet no-fill mode[cpu%ld]: sched_getcpu() is %d\n", i, sched_getcpu());
                    printf("Set no-fill mode: before cr0 is = 0x%8.8X\n", get_cr0());

                    // clear bit 30
                    __asm__ __volatile__ (
                        "wbinvd\n"
                        "mov %%cr0, %%rax\n\t"
                        "or $(1<<30), %%eax\n\t"
                        "mov %%rax, %%cr0\n\t"
                        "wbinvd\n"
                        ::
                        :"%rax"
                    );
                    printf("Set no-fill mode[cpu%ld]: After cr0 is =0x%8.8X\n\n", i,get_cr0());

                }
            }

            // set CPU affinity to CPU 1:
            cpu_set_t mask;
            CPU_ZERO(&mask);
            CPU_SET(1, &mask); // setting cpu affinity to CPU 1

            if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                perror("sched_getaffinity");
                assert(false);
            }
            printf("\n\n set-no fill mode:  sched_getcpu() is %d\n", sched_getcpu());

            break;

        case 1:
            // enable no fill-mode for cpu 4-7
            printf("no-fill mode for cpu 4-7 is not setup yet.\n");
            break;

        default:
            printf("Error while setting no-fill mode\n");
            return 0;
    }

    return 1;
}

int clear_no_fill_mode(int idcacheNum){

    long nproc,i;
    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu

    switch (idcacheNum) {
        case 0:
            // disenable no-fill mode for cpu 0-7
            printf("Inside clearing cache set 1\n");
        
            for (i = 0; i < nproc; i++) {
                // avoiding cpu1
                if(i!=1){
                    cpu_set_t mask;
                    CPU_ZERO(&mask);
                    CPU_SET(i, &mask); // setting cpu affinity

                    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                        perror("sched_getaffinity");
                        assert(false);
                    }

                    printf("\n\nExit no-fill mode[cpu%ld]: sched_getcpu() is %d\n",i, sched_getcpu());
                    printf("Exit no-fill mode: before cr0 is = 0x%8.8X\n", get_cr0());

                    // clear bit 30
                    __asm__ __volatile__ (
                    "mov %%cr0, %%rax\n\t"
                    "and $~(1<<30), %%eax\n\t"
                    "mov %%rax, %%cr0\n\t"
                    ::
                    :"%rax"
                    );
                    printf("After clear no-fill mode[cpu%ld] cr0 is =0x%8.8X\n\n", i, get_cr0());

                }
            }
            break;

        case 1:
            // enable no fill-mode for cpu 4-7
            printf("no-fill mode for cpu 4-7 is not setup yet.\n");
            break;

        default:
            printf("Error while setting no-fill mode\n");
            return 0;
    }
    return 1;
}




// set high priority to this process
void set_realtime_priority() {
    int ret;

    // We'll operate on the currently running thread.
    pthread_t this_thread = pthread_self();

    struct sched_param params;

    // We'll set the priority to the maximum.
    params.sched_priority = sched_get_priority_max(SCHED_FIFO);
    printf("Trying to set thread realtime priority = %d\n", params.sched_priority );

    // Attempt to set thread real-time priority to the SCHED_FIFO policy
    ret = pthread_setschedparam(this_thread, SCHED_FIFO, &params);
    if (ret != 0) {
        // Print the error
        printf("Unsuccessful in setting thread realtime priority\n");
        return;
    }

    // Now verify the change in thread priority
    int policy = 0;
    ret = pthread_getschedparam(this_thread, &policy, &params);
    if (ret != 0) {
        printf("Couldn't retrieve real-time scheduling parameters\n");
        return;
    }

    // Check the correct policy was applied
    if(policy != SCHED_FIFO) {
        printf("Scheduling is NOT SCHED_FIFO!\n");
    } else {
        printf("SCHED_FIFO OK\n");
    }

    // Print thread scheduling priority
    printf("Thread priority is  = %d\n", params.sched_priority );
}

void fillL1(unsigned char *p, int num){
    int i;
    unsigned char *buf = p;
    //volatile unsigned char *buf = p;
    for(i=0;i<num;++i){
//*
        asm volatile(
        "movq $0,(%0)\n"
        :
        :"r"(buf)
        :
        );
//*/
        //__builtin_prefetch(buf,0,3);
        *buf += 0;

        buf += 64;
    }
    printf("Inside fillL1, num is %d\n", num);
}


int main(int argc, char *argv[])
{
	volatile int ret;

	//set_realtime_priority();
	setpriority(PRIO_PROCESS, 0, -20);

	printf("\n\n Before dune sched_getcpu() is %d\n", sched_getcpu());

	volatile int a;
	a= 4;

	printf("hello: not running dune yet\n");	
	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}
	printf("hello: now printing from dune mode\n");
	printf("\n\n After dune sched_getcpu() is %d\n", sched_getcpu());
	
	asm("lfence; mfence" ::: "memory");
	asm volatile("wbinvd":::"memory");

	asm volatile("cli": : :"memory");

	// Local: set_no_fill_mode() return 1 on success
    	if(!set_no_fill_mode(idcache)){
       		printf("Setting Other CPUs to no-fill mode failed\n");
       		exit(0);
    	}
	printf("\n\n After no-fill mode current cpu: sched_getcpu() is %d\n", sched_getcpu());

	asm("lfence; mfence" ::: "memory");
	asm volatile("wbinvd":::"memory");

	//load function into cahce
	__builtin_prefetch(&a,0,3);

	// do something
	a=10;
	

	// change following instruction to invd
	printf("Running invd\n");
	asm("lfence; mfence" ::: "memory");
	asm volatile("invd":::"memory");
	printf("Running invd: done\n");

    	//asm("lfence; mfence" ::: "memory");
    	//asm volatile("wbinvd":::"memory");

	clear_no_fill_mode(idcache);

    	//asm("lfence; mfence" ::: "memory");
    	//asm volatile("wbinvd":::"memory");

	asm volatile("sti": : :"memory");
	
	printf("a is %d\n", a);



	printf("hello:\n");

	//sleep(15);
	return 0;
}

