#define _GNU_SOURCE
#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */
#include <linux/sched.h>
#include <linux/cpuset.h>


u64 get_cr0(void){
    u64 cr0;
    __asm__ (
    "mov %%cr0, %%rax\n\t"
    "mov %%eax, %0\n\t"
    : "=m" (cr0)
    : /* no input */
    : "%rax"
    );

    return cr0;
}

// set bit 30 of cr0
int set_no_fill_mode(void){

    cpu_set_t mask;
    long nproc, i;

    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_getaffinity");
        assert(false);
    }

    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu

    for (i = 0; i < nproc; i++) {
        // avoiding cpu1, because we want to run our decryption inside this cpu
        if(i!=1){
            CPU_SET(i, &mask); // setting cpu affinity

            printf("\n\nsched_getcpu() is %d\n", sched_getcpu());
            printf("Before no-fill mode cr0 is = 0x%8.8X\n", get_cr0());

            // setting bit 30
            __asm__ __volatile__ (
            "mov %%cr0, %%rax\n\t"
            "or $(1<<30), %%eax\n\t"
            "mov %%rax, %%cr0\n\t"
            ::
            :"%rax"
            );
            printf("After no-fill mode activate cr0 is = 0x%8.8X\n\n", get_cr0());

        }
    }

    return 1;
}

// clear bit 30 if cr0
int clear_no_fill_mode(void){

    cpu_set_t mask;
    long nproc, i;

    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_getaffinity");
        assert(false);
    }

    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu

    for (i = 0; i < nproc; i++) {
        // avoiding cpu1, because we want to run our decryption inside this cpu
        if(i!=1){
            CPU_SET(i, &mask); // setting cpu affinity

            printf("\n\nExit no-fill mode: sched_getcpu() is %d\n", sched_getcpu());
            printf("Exit no-fill mode: before cr0 is = 0x%8.8X\n", get_cr0());

            // clear bit 30
            __asm__ __volatile__ (
            "mov %%cr0, %%rax\n\t"
            "and $~(1<<30), %%eax\n\t"
            "mov %%rax, %%cr0\n\t"
            ::
            :"%rax"
            );
            printf("After clear no-fill mode cr0 is =0x%8.8X\n\n", get_cr0());

        }
    }

    return 1;
}

static int __init hello_start(void)
{
    printk(KERN_INFO "Loading hello module...\n");

    u64 cr0=get_cr0();
    printk(KERN_INFO "Original cr0 = 0x%8.8X\n\n\n\n", get_cr0());

    int i=&set_no_fill_mode;
    int j=&clear_no_fill_mode;




    return 0;
}

static void __exit hello_end(void)
{
    printk(KERN_INFO "Goodbye Mr.\n");

}

module_init(hello_start);
module_exit(hello_end);
