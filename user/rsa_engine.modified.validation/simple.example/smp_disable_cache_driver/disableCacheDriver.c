#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/slab.h>

#define BUF_SIZE 3


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shariful");
MODULE_DESCRIPTION("Device Driver to enable/disable kernel preemption & interrupt");


static struct proc_dir_entry *ent;
static char message[BUF_SIZE];


void disCache(void *p){

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

void enaCache(void *p){
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "and $~(1<<30), %%eax\n\t"
    "mov %%rax, %%cr0\n\t"
    ::
    :"%rax"
    );

    printk(KERN_INFO "cpuid %d --> cache enable\n", get_cpu());

}


void disable_func(void){

    unsigned long flags;
    int LEN=10;
    int STEP=1;
    int VALUE=1;
    int arr[LEN];
    unsigned long dummy;
    int i;

    printk(KERN_INFO "CPU set to 1\n");
    // Disable cache in all the CPU core except current core
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
    printk(KERN_INFO "invd execute\n");

    // enable cache in all the CPU core
    smp_call_function(enaCache,NULL,1);
    printk(KERN_ALERT "invd executed, Current CPU is %d\n", get_cpu());

}


void disable_cache_func(void){
    smp_call_function(disCache,NULL,1);
}


void enable_cache_func(void){

    asm volatile("invd\n":::);
    printk(KERN_INFO "invd execute\n");

    // enable cache in all the CPU core
    smp_call_function(enaCache,NULL,1);
    printk(KERN_ALERT "invd executed, Current CPU is %d\n", get_cpu());
}


static ssize_t mread(struct file *file, char __user *ubuf, size_t count, loff_t *ppos){
    char __user *ptr;

    if(count>BUF_SIZE){
        printk(KERN_INFO "count size should be less then buffer size\n");
        return -1;
    }
    copy_to_user(ubuf, message,count);

    return count;
}



// look into the original function signature in Linux source code
static ssize_t mwrite(struct file *file, const char __user *ubuf, size_t count, loff_t *offset){
    int rv,id;
    char __user *p = ubuf;
    unsigned long flags;

    if(count> BUF_SIZE)
        return -EFAULT;

    rv=copy_from_user(message, p, count);

    if(message[0]=='0'){
        // run INVD & enable Cache
        if(smp_call_function_single(1,enable_cache_func,(void *)(uintptr_t) 1,1))
            printk(KERN_ALERT "Error\n");



    }else{

        printk(KERN_INFO "mwrite: Current Cpu %d \n", get_cpu());
        //disable_func();


        /*
        * smp_call_function_single - Run a function on a specific CPU
        * @func: The function to run. This must be fast and non-blocking.
        * @info: An arbitrary pointer to pass to the function.
        * @wait: If true, wait until function has completed on other CPUs.
        *
        * Returns 0 on success, else a negative status code.
        * int smp_call_function_single(int cpu, smp_call_func_t func, void *info, int wait)
        */

        //if(smp_call_function_single(1,disable_func,(void *)(uintptr_t) 1,1))
        if(smp_call_function_single(1,disable_cache_func,(void *)(uintptr_t) 1,1))
            printk(KERN_ALERT "Error\n");
    }
    return count;

}


// for driver function, call this mread/mwrite function from userspace
static struct file_operations fops={
        .owner = THIS_MODULE,
        .read = mread,
        .write = mwrite,
};

static int __init deviceDriver_init(void)
{
    ent= proc_create("disableCacheDriver", 0660, NULL, &fops);
    message[2]='\0';

    printk(KERN_ALERT "disableCacheDriver Driver created\n");
    printk(KERN_INFO "Current CPU is %d\n", get_cpu());

    return 0; 
}

static void __exit deviceDriver_cleanup(void){
    proc_remove(ent);
    printk(KERN_ALERT "Removing disableCacheDriver.\n");
}

module_init(deviceDriver_init);
module_exit(deviceDriver_cleanup);

