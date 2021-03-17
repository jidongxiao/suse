#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/slab.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shariful");
MODULE_DESCRIPTION("Device Driver to enable/disable kernel preemption & interrupt");

void disCache(void *p){
/*
    asm volatile(	"wbinvd\n"
                     "mov	%%cr0,%%rax\n"
                     "or	$0x40000000,%%eax\n"
                     "mov	%%rax,%%cr0\n"
                     "wbinvd\n":::"%rax"
    );

*/

    __asm__ __volatile__ (
            "wbinvd\n"
            "mov %%cr0, %%rax\n\t"
            "or $(1<<30), %%eax\n\t"
            "mov %%rax, %%cr0\n\t"
            "wbinvd\n"
            ::
            :"%rax"
    );

    printk(KERN_INFO "cpuid %d --> cache disable\n", get_cpu());

}

void disCache_nofill(void *p){
/*
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "or $(1<<30), %%eax\n\t"
    "mov %%rax, %%cr0\n\t"
    ::
    :"%rax"
    );
*/
    printk(KERN_INFO "cpuid %d --> cache disable\n", get_cpu());

}
void enaCache(void *p){
/*
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "and $~(1<<30), %%eax\n\t"
    "invd\n\t"
    "mov %%rax, %%cr0\n\t"

    ::
    :"%rax"
    );
*/


    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "and $~(1<<30), %%eax\n\t"
    "mov %%rax, %%cr0\n\t"
    ::
    :"%rax"
    );

    printk(KERN_INFO "cpuid %d --> cache enable\n", get_cpu());

}

static int __init deviceDriver_init(void)
{
 
	unsigned long flags;
	int LEN=10;
 	int STEP=1;
	int VALUE=1;
  	int arr[LEN];
	unsigned long dummy;
	int i;

    printk(KERN_ALERT "invd Driver loaded\n");
    printk(KERN_INFO "Current CPU is %d\n", get_cpu());

    // Disable cache in all the CPU core except current core
    //disCache(NULL);
    smp_call_function(disCache,NULL,1);


    wbinvd();
    //asm volatile("cpuid\n":::);
    //local_irq_disable();
    
    __asm__ __volatile__(

	        //"wbinvd\n"
            "loop:"
    	    "movq %%rdx, (%%rbx);"
    	    "leaq (%%rbx, %%rcx, 8), %%rbx;"
    	    "cmpq %%rbx, %%rax;"
    	    "jg loop;"

	        //"invd\n"
    	    : "=b"(dummy) //output
    	    : "b" (arr),
       	      "a" (arr+LEN),
              "c" (STEP),
              "d" (VALUE)
    	    : "cc", "memory"
	);

	//local_irq_enable();
    asm volatile("invd\n":::);
    //printk(KERN_INFO "invd execute\n");

    // enable cache in all the CPU core

    //enaCache(NULL);
    smp_call_function(enaCache,NULL,1);
    printk(KERN_ALERT "invd executed, Current CPU is %d\n", get_cpu());

    return 0; 
}

static void __exit deviceDriver_cleanup(void){
        printk(KERN_ALERT "Removing invd_driver.\n");
}

module_init(deviceDriver_init);
module_exit(deviceDriver_cleanup);

