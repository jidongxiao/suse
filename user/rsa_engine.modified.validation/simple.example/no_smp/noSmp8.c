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


static int __init deviceDriver_init(void)
{
 
	unsigned long flags;
	int LEN=10;
 	int STEP=1;
	int VALUE=1;
  	int arr[LEN];
	unsigned long dummy;
	int i;

    printk(KERN_INFO "invd Driver loaded\n");

    //wbinvd();
    //asm volatile("cpuid\n":::);
    //local_irq_disable();
    
    __asm__ __volatile__(

	        "wbinvd\n"
    	    "loop:"
    	    "movq %%rdx, (%%rbx);"
    	    "leaq (%%rbx, %%rcx, 8), %%rbx;"
    	    "cmpq %%rbx, %%rax;"
    	    "jg loop;"

	        "invd\n"
    	    : "=b"(dummy) //output
    	    : "b" (arr),
       	      "a" (arr+LEN),
              "c" (STEP),
              "d" (VALUE)
    	    : "cc", "memory"
	);

	//local_irq_enable();
	
    //asm volatile("invd\n":::);
    
    printk(KERN_INFO "invd execute\n");	
    
    return 0; 
}

static void __exit deviceDriver_cleanup(void){
        printk(KERN_INFO "Removing invd_driver.\n");
}

module_init(deviceDriver_init);
module_exit(deviceDriver_cleanup);

