#include <linux/module.h>     /* Needed by all modules */
#include <linux/kernel.h>     /* Needed for KERN_INFO */
#include <linux/init.h>       /* Needed for the macros */



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

static int __init hello_start(void)
{
    printk(KERN_INFO "Loading hello module...\n");
    printk(KERN_INFO "Hello world\n");
    
    //u64 cr0=get_cr0();
    printk(KERN_INFO "cr0 = 0x%8.8X\n", get_cr0());


	__asm__ (
    	"mov %%cr0, %%rax\n\t"
    	"or $0x40000000, %%eax\n\t"
    	"mov %%rax, %%cr0\n\t"
    	:: 
    	:"%rax"
    	);


    printk(KERN_INFO "cr0 after change = 0x%8.8X\n", get_cr0());



    return 0;
}

static void __exit hello_end(void)
{
    printk(KERN_INFO "Goodbye Mr.\n");

	__asm__ (
    	"mov %%cr0, %%rax\n\t"
    	"and $~(0x40000000), %%eax\n\t"
    	"mov %%rax, %%cr0\n\t"
    	:: 
    	:"%rax"
    	);

}

module_init(hello_start);
module_exit(hello_end);
