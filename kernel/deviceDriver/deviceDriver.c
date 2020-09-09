#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shariful");
MODULE_DESCRIPTION("Device Driver to enable/disable kernel preemption & interrupt");

#define BUF_SIZE 3

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
        local_irq_restore(flags);
        //put_cpu;
        printk(KERN_INFO " local_irq_restore() called, Enable local interrupts\n");
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

    printk(KERN_INFO "Device Driver loaded\n");
    ent= proc_create("deviceDriver", 0660, NULL, &fops);

// message [0] should contain the user request 0/1. message[1] should contain id, where id=get_cpu/put_cpu. message [2] should contain '\0'
    message[2]='\0';

    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit deviceDriver_cleanup(void)
{
    proc_remove(ent);
    printk(KERN_INFO "Removing deviceDriver.\n");
}

module_init(deviceDriver_init);
module_exit(deviceDriver_cleanup);

