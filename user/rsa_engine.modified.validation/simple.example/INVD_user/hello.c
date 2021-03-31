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


#include "libdune/dune.h"
#include "libdune/cpu-x86.h"

#define idcache 0
#define KEY_LEN 128
#define CACHE_STACK_SIZE 9000 // most likely will be changed, depending on the size of the structure
#define CACHE_LINE_SIZE 64

//#define change "hello"
unsigned char change[]="hello";

// Secure CRYPTO structure
static struct CACHE_CRYPTO_ENV{
    unsigned char in[KEY_LEN]; // in --> encrypted msg
    //unsigned char masterKey[128/8]; // for 128 bit master key
    unsigned char out[KEY_LEN] __attribute__ ((aligned(CACHE_LINE_SIZE)));
    unsigned char cachestack[CACHE_STACK_SIZE];
    //unsigned long privateKeyID;

}cacheCryptoEnv __attribute__((aligned(64)));
#define cacheCryptoEnvSize (sizeof(cacheCryptoEnv)/64)



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

void fillL1(struct CACHE_CRYPTO_ENV *p, int num){
    int i;
    struct CACHE_CRYPTO_ENV *buf = p;
    //volatile unsigned char *buf = p;
    for(i=0;i<num;++i){
/*
        asm volatile(
        "movq $0,(%0)\n"
        :
        :"r"(buf)
        :
        );
*/
        __builtin_prefetch(buf,0,3);
        //*buf += 0;

        buf += 64;
    }
    printf("Inside fillL1, num is %d\n", num);
}

int decryptFunction (struct CACHE_CRYPTO_ENV *env){
    int ret;

    strcpy(env->in,change);
    strcpy(env->out,change);

    printf( "decryption func: env.in fixed is %s\n", env->in);
    printf("decryption func: env.out fixed is %s\n", env->out);

    return ret;

}

int stackswitch( void *env, int (*f)(struct CACHE_CRYPTO_ENV *), unsigned char *stackBottom){

    printf("\t\t\t\n\n");
    printf("******************   **************************** ***************\n");
    printf("******************   Inside stack_switch function ***************\n");
    printf("******************   **************************** ***************\n");
    printf("\t\t\t\n\n");


    //printf("Inside stackswitch, msg is:  %s\n", ((struct CACHE_CRYPTO_ENV *)env)->in);


    //creating the original stack switch function
    asm volatile(

    //prologue
    "pushq %%rbp \t\n"
    "movq %%rsp, %%rbp \t\n" // can't modify rbp without clobber register.


    // create space for stackswitch function parameter. rax now point to the stack bottom
    // ok, So, 16(%%rbp) --> point to the *stackbottom. When we move 16(%%rbp)--> rax, rax is now point to stack bottom.
    "movq 16(%%rbp), %%rax\t\n"

    //save system rbp on the new stack.
    // creating new stack. Setting rbp.
    "movq %%rbp, (%%rax)\t\n"

    //save system rsp on the new stack
    // setting rsp to the new stack
    "movq %%rbp, -8(%%rax)\t\n"

    //rbx now point to the old rbp
    // rbx --> point to the original stack rbp
    "movq %%rbp, %%rbx\t\n"

    // Create new stack frame
    "movq %%rax, %%rbp\t\n"
    "movq %%rax, %%rsp\t\n"

    // pointing to rsp, from previous line, movq %%rbp, -8(%%rax)
    //"sub $8, %%rsp\t\n"
    "subq $40, %%rsp\t\n"

    // create parameter for decryption function
    //"pushq 32(%%rbx)\t\n"
    "movq 32(%%rbx), %%rdx\t\n"
    "movq %%rdx, %%rdi\t\n"

    //call wbinvd, only for validation
    "lfence\n"
    "mfence\n"
    "wbinvd\n"

    //call decryption function
    "call 24(%%rbx)\t\n"

    // returning to the original stack
    "movq %%rbp, %%rbx\t\n"
    "movq (%%rbx), %%rbp\t\n"
    "mov -8(%%rbx), %%rsp\t\n"

    "leave\t\n"
    //"ret \t\n"

    :
    :
    :"rax","rbx","rbp"
    );

    // cleaning the cacheStack buffer
    struct CACHE_CRYPTO_ENV *p =env;


    // clearing the full env
    //memset(&p, 0, sizeof (p));
    //clear_env(p->masterKey, sizeof (p->masterKey));
    //clear_env(p->cachestack, sizeof (p->cachestack));
    //clear_env(p->encryptPrivateKey, sizeof (p->encryptPrivateKey));

    //exit no-fill mode
    //clear_no_fill_mode(idcache);

    // restore Interrupts
    //asm volatile("sti": : :"memory");

    printf("\t\t\t\n\n");
    printf("******************   **************** ***************\n");
    printf("******************   Stack Switch end ***************\n");
    printf("******************   **************** ***************\n");
    printf("\t\t\t\n\n");

    return 1;
}

int main(int argc, char *argv[])
{
	volatile int ret;
    int result;
	set_realtime_priority();


    struct CACHE_CRYPTO_ENV env;

    //Initializing, set up canary words
    char word[] ="0xabcd";
    memcpy(env.in, word, sizeof (word));
    memcpy(env.out, word, sizeof (word));

    printf("env.in fixed is %s\n", env.in);
    printf("env.out fixed is %s\n", env.out);

    //dune
	printf("hello: not running dune yet\n");
	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}
	printf("hello: now printing from dune mode\n");


	
	asm("lfence; mfence" ::: "memory");
	asm volatile("wbinvd":::"memory");



	asm volatile("cli": : :"memory");

/*
	// Local: set_no_fill_mode() return 1 on success
    if(!set_no_fill_mode(idcache)){
       printf("Setting Other CPUs to no-fill mode failed\n");
       exit(0);
    }
*/

	asm("lfence; mfence" ::: "memory");
	asm volatile("wbinvd":::"memory");

	//load function into cahce
    // fill cache with the structure
    asm("lfence; mfence" ::: "memory");
    fillL1(&env, cacheCryptoEnvSize);




    result=stackswitch(&env, decryptFunction, env.cachestack+CACHE_STACK_SIZE-8);
	

	// change following instruction to invd
	printf("Running invd\n");
	//asm("lfence; mfence" ::: "memory");
	//asm volatile("invd":::"memory");
	printf("Running invd: done\n");

    asm("lfence; mfence" ::: "memory");
    asm volatile("wbinvd":::"memory");

	//clear_no_fill_mode(idcache);

    asm("lfence; mfence" ::: "memory");
    asm volatile("wbinvd":::"memory");

	asm volatile("sti": : :"memory");


	printf("hello: %d\n", result);

	//sleep(15);
	return 0;
}

