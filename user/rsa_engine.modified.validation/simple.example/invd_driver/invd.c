#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/random.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shariful");
MODULE_DESCRIPTION("Device Driver to enable/disable kernel preemption & interrupt");

#define BUF_SIZE 3


typedef struct _ProtectedMem{
    //uint8_t padding1[64];
    uint8_t master_key[128];
    unsigned char heapStack[9000];
    //uint8_t padding[64];
}ProtectedMem;


asmlinkage void disCache(void *);
asmlinkage void enaCache(void *);
asmlinkage void disCache_nofill(void *);
asmlinkage void fillL1(unsigned char *p, int num);


void fillL1(unsigned char *p, int num){
	int i;
	unsigned char *buf = p;
	//for(i=0;i<num;++i){
	for(i=0;i<320;++i){
		asm volatile(	"movl $0,(%0);\n" \
				::"r"(buf) : );
		buf += 64;
	
	}
	printk(KERN_INFO "Inside fillL1, num is %d\n", num);
}


void disCache(void *p){
	asm volatile(	"wbinvd\n"
		"mov	%%cr0,%%rax\n"
		"or	$0x40000000,%%eax\n"
		"mov	%%rax,%%cr0\n"
		"wbinvd\n":::"%rax"
	);
printk(KERN_INFO "cpuid %d --> cache disable\n", get_cpu());
}

void disCache_nofill(void *p){
	__asm__ __volatile__ (
                    "mov %%cr0, %%rax\n\t"
                    "or $(1<<30), %%eax\n\t"
                    "mov %%rax, %%cr0\n\t"
                    ::
                    :"%rax"
                    );

printk(KERN_INFO "cpuid %d --> cache disable\n", get_cpu());
}
void enaCache(void *p){

	__asm__ __volatile__ (
                    "mov %%cr0, %%rax\n\t"
                    "and $~(1<<30), %%eax\n\t"
                    "invd\n\t"
		    "mov %%rax, %%cr0\n\t"
		 
                    ::
                    :"%rax"
                    );

    printk(KERN_INFO "cpuid %d --> cache enable\n", get_cpu());
}




// the entry will be created into a /proc directory
// the directory will hold the new deviceDriver
static struct proc_dir_entry *ent;
static char message[BUF_SIZE];


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
        // disable local interrupts
	    //id=get_cpu();
        local_irq_save(flags);
        printk(KERN_INFO " local_irq_save() called, Disable local interrupts\n");
    }else{
        
	    printk(KERN_INFO "Current Cpu %d \n", get_cpu());
	    smp_call_function(disCache,NULL,1);
    	//ProtectedMem pm;

		unsigned char pm[] = "hi there. hi there. hi there. hi there. hi there. hi there. hi there. hi there. hi there. \
					hi there. hi there. hi there. hi there. hi there. hi there. hi there. ";

		unsigned char *pm_ptr = &pm;
		printk(KERN_INFO " size of pm is %ld\n", sizeof(pm));

		//fillL1(pm_ptr,(int)sizeof (pm));

	    //asm volatile ("wbinvd" : : : "memory");
	    wbinvd();
  
	    //unsigned char randArray[RandArraySize];
            

	    // enabling the following line casuse system stall and un-responsive
	    //asm volatile("invd\n":::);
    	printk(KERN_INFO " 'invd' called, deleting cache\n");

	    smp_call_function(enaCache,NULL,1);
            //local_irq_restore(flags);
    }

    return count;

}


static struct file_operations fops={
        .owner = THIS_MODULE,
        .read = mread,
        .write = mwrite,
};



static int __init deviceDriver_init(void)
{
    int ret =0;
    unsigned long flags;

    printk(KERN_INFO "invd Driver loaded\n");
    ent= proc_create("invd", 0660, NULL, &fops);

// message [0] should contain the user request 0/1. message[1] should contain id, where id=get_cpu/put_cpu. message [2] should contain '\0'
    message[2]='\0';

    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit deviceDriver_cleanup(void)
{
    proc_remove(ent);
    printk(KERN_INFO "Removing invd_driver.\n");
}

module_init(deviceDriver_init);
module_exit(deviceDriver_cleanup);

