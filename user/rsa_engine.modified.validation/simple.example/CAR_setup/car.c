#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <asm/io.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/cpumask.h>
#include <linux/tty.h>
#include <stdarg.h>
#include <linux/vt_kern.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/ioport.h>
#include <linux/io.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <asm/mtrr.h>
#include <asm/pat.h>
//#include <uapi/asm/mtrr.h>
#include <linux/stop_machine.h>
//#include <linux/ioport.h>
#include <linux/proc_fs.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shariful");
MODULE_DESCRIPTION("Device Driver to enable/disable kernel preemption & interrupt");

// all the MTRRs
#define IA32_MTRRCAP	0xFE
#define IA32_MTRR_DEF_TYPE	0x2FF
#define IA32_MTRR_PHYSBASED0	0x200	//0~9
#define IA32_MTRR_PHYSMASK0	0x201
#define IA32_MTRR_FIX64K_00000	0x250

#define IA32_MTRR_FIX16K_80000	0x258
#define IA32_MTRR_FIX16K_a0000	0x259

#define IA32_MTRR_FIX4K_C0000	0x268
#define IA32_MTRR_FIX4K_C8000	0x269
#define IA32_MTRR_FIX4K_D0000	0x26a
#define IA32_MTRR_FIX4K_D8000	0x26b
#define IA32_MTRR_FIX4K_E0000	0x26c
#define IA32_MTRR_FIX4K_E8000	0x26d
#define IA32_MTRR_FIX4K_F0000	0x26e
#define IA32_MTRR_FIX4K_F8000	0x26f

#define BUF_SIZE 3
#define gl_order	(1)
#define gl_pageNum	(1<<gl_order)

//#define heapStackSize	(4096*gl_pageNum)
#define heapStackSize (0x15D0)
//#define heapStackSize (0x1f5c)

typedef struct _ProtectedMem{
    unsigned char in[10];
    unsigned char heapStack[heapStackSize];
    //uint8_t padding[64];
}ProtectedMem,*ProtectedMem_PTR;

#define RandArraySize (sizeof(ProtectedMem)/64)




unsigned long phy_addr = 0xc0000;
struct resource *resres = NULL;

//#define heapStackSize	(4096*1)
uint8_t *heapStack;
uint8_t *heapStackTop;
//uint8_t heapStack[heapStackSize];
//uint8_t *heapStackTop = heapStack + heapStackSize - 4;

//asmlinkage void disCache(void *);
//asmlinkage void enaCache(void *);
//asmlinkage void disCache_nofill(void *);
asmlinkage void fillL1(unsigned char *p, int num);
asmlinkage unsigned long long mtrr_fun(void);
asmlinkage unsigned long long mtrr_cap_fun(void);
asmlinkage unsigned long long mtrr_def_fun(void);
asmlinkage unsigned long long mtrr_fixed_fun(unsigned int index);
asmlinkage unsigned int set_fix(unsigned int value,unsigned int value2);
asmlinkage void run_invd(void);
asmlinkage int safeCall1(void *,void *, void *);

static struct proc_dir_entry *ent;
static char message[BUF_SIZE];

static DEFINE_RAW_SPINLOCK(gl_mtrr_lock);



struct mtrr_data{
    unsigned int reg;
    unsigned int value_h;
    unsigned int value_l;
};



void fillL1(unsigned char *p, int num){
	int i;
	unsigned char *buf = p;
        for(i=0;i<num;++i){

//	for(i=0;i<320;++i){
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
asmlinkage void doAll_fun(ProtectedMem *para){
    printk(KERN_INFO "Inside doAll_fun\n");
    int r = 0;
    if(!para)
        return;
    printk(KERN_ALERT "pm-->in is %s\n", *(para->in));
    printk(KERN_INFO "Inside doAll_fun\n");
    return;
}

//void test_func(uint8_t* heapStackTop_new ){
void test_func(void ){
    printk( KERN_INFO "inside test_func\n");
    ProtectedMem pm;

    memset(&pm, 0, sizeof (ProtectedMem));
    memcpy(pm.in, "Hello", sizeof ("Hello"));
    printk(KERN_INFO "pm.in is --> %s",pm.in);
    fillL1(&pm,RandArraySize);

    printk(KERN_INFO "test_func: heapStackTop: 0x%p\n",heapStackTop);

    //smp_call_function(disCache_nofill,NULL,1);
    //safeCall1(&pm,doAll_fun,heapStackTop);
    wbinvd();
    safeCall1(&pm,doAll_fun,pm.heapStack+heapStackSize-8);
    //asm volatile("invd\n":::);
    smp_call_function(enaCache,NULL,1);



}


static unsigned int deftype_lo,deftype_hi,cr4;
static void prepare_set(void) __acquires(gl_mtrr_lock){
                unsigned long cr0;

                raw_spin_lock(&gl_mtrr_lock);

                // check original mtrr_def)type value
                unsigned long long mtrr_def = mtrr_def_fun();      // reading IA32_MTRR_DEF_TYPE msr
                printk( KERN_INFO "inside prepare_set: mtrr_def: %llx\n",mtrr_def);


                /* Enter the no-fill (CD=1, NW=0) cache mode and flush caches. */
                cr0 = read_cr0() | X86_CR0_CD;
                native_write_cr0(cr0);
                wbinvd();
                printk(KERN_ALERT "cpuid %d, cache disable & flashed\n", smp_processor_id());

                /* Save value of CR4 and clear Page Global Enable (bit 7) */
                if (cpu_has_pge) {
                    cr4 = native_read_cr4();
                    native_write_cr4(cr4 & ~X86_CR4_PGE);
                    printk(KERN_ALERT "Save CR4\n");
                }

                /* Flush all TLBs via a mov %cr3, %reg; mov %reg, %cr3 */
                __flush_tlb();

                /* Save MTRR state */
                rdmsr(MSR_MTRRdefType, deftype_lo, deftype_hi);

                /* Disable MTRRs, and set the default type to uncached */
                //mtrr_wrmsr(MSR_MTRRdefType, deftype_lo & ~0xcff, deftype_hi);


                asm volatile("wrmsr" : : "c" (MSR_MTRRdefType), "a"(deftype_lo & ~0xcff), "d" (deftype_hi) : "memory");
                //asm volatile("wrmsr" : : "c" (MSR_MTRRdefType), "a"(IA32_MTRR_DEF_TYPE & (1<<(11))), "d" (deftype_hi) : "memory");



                // check if mtrris disable
                unsigned long long mtrr_disable = mtrr_def_fun();      // reading IA32_MTRR_DEF_TYPE msr
                printk( KERN_INFO "inside prepare_set: After Mtrr disable mtrr_def: %llx\n",mtrr_disable);

                wbinvd();
        }

static void post_set(void) __releases(set_atomicity_lock){

        /* Intel (P6) standard MTRRs */
        //mtrr_wrmsr(MSR_MTRRdefType, deftype_lo, deftype_hi);
        asm volatile("wrmsr" : : "c" (MSR_MTRRdefType), "a"(deftype_lo), "d" (deftype_hi) : "memory");

        // check if mtrr is enable/ set to default
        unsigned long long mtrr_enable = mtrr_def_fun();      // reading IA32_MTRR_DEF_TYPE msr
        printk( KERN_INFO "inside post_set: After Mtrr Enable mtrr_def: %llx\n",mtrr_enable);

        /* Flush TLBs (no need to flush caches - they are disabled) */
        __flush_tlb();

        /* Enable caches */
        write_cr0(read_cr0() & 0xbfffffff);
        printk(KERN_ALERT "cache Enable \n");

        /* Restore value of CR4 */
        if (cpu_has_pge)
            native_write_cr4(cr4);

        raw_spin_unlock(&gl_mtrr_lock);
        printk(KERN_ALERT "CR4 value restored\n");
}



static int gl_mtrr_handle(struct mtrr_data *data){
    unsigned long flags;

    local_irq_save(flags);
    prepare_set();

    asm volatile("wrmsr" : : "c" (data->reg), "a"(data->value_l), "d" (data->value_h) : "memory");
//		mtrr_wrmsr(MTRRphysBase_MSR(reg), vr->base_lo, vr->base_hi);
//		mtrr_wrmsr(MTRRphysMask_MSR(reg), vr->mask_lo, vr->mask_hi);

    post_set();
    local_irq_restore(flags);
    return 0;
}




static void gl_set_mtrr(unsigned int reg,unsigned int value_h,unsigned int value_l){
    struct mtrr_data data = {
            .reg = reg,
            .value_h = value_h,
            .value_l = value_l
    };
    stop_machine(gl_mtrr_handle,&data,cpu_online_mask);
    printk(KERN_ALERT "handeling mtrr setup\n");

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
        // disable local interrupts
        //id=get_cpu();
        local_irq_save(flags);
        printk(KERN_INFO " local_irq_save() called, Disable local interrupts\n");
    }else{

        printk(KERN_INFO "Current Cpu %d \n", get_cpu());
        test_func();
    }

    return count;

}


static struct file_operations fops={
        .owner = THIS_MODULE,
        .read = mread,
        .write = mwrite,
};







//extern cpumask_t allowed;
cpumask_t saved_cpu_mask, allowed;

static int __init car_init(void){
    printk(KERN_INFO "car module loaded\n");



    int ret =0;
    unsigned long flags;
    ent= proc_create("car", 0660, NULL, &fops);
    message[2]='\0';
    printk(KERN_ALERT "ent Driver created\n");




    ProtectedMem *protectedMem;
    heapStackTop = protectedMem->heapStack + heapStackSize - 8;
    printk(KERN_INFO "heapStackTop: 0x%p",heapStackTop);
    printk(KERN_INFO "heapStack: 0x%p",protectedMem->heapStack);


    //smp_call_function(disCache_nofill,NULL,1);
    //smp_call_function(enaCache,NULL,1);


    unsigned long long mtrr_r;


    saved_cpu_mask = current->cpus_allowed;
    printk( KERN_INFO "allowed_mask: 0x%lx\n",cpumask_bits(&allowed)[0]);
    printk(KERN_INFO "current mask: 0x%lx\t current cpu: %d\n",cpumask_bits(&(current->cpus_allowed))[0],smp_processor_id());
//    gl_set_mtrr(IA32_MTRR_FIX4K_F0000 ,0x06060606,0x06060606);
//    gl_set_mtrr(IA32_MTRR_FIX4K_F8000 ,0x06060606,0x06060606);
//    gl_set_mtrr(IA32_MTRR_FIX4K_C0000 ,0x06060606,0x06060606);
//    gl_set_mtrr(IA32_MTRR_FIX4K_C8000 ,0x06060606,0x06060606);

    // check if MTRRs is available, return %rdx value of cpuid.eax=01H
    mtrr_r = mtrr_fun();
    printk( KERN_INFO "mtrr_r: 0x%llx\n",mtrr_r);
///*

    //if((mtrr_r>>32) & (1 << (12))){
    if((mtrr_r) & (1 << (12))){
        unsigned long long mtrr_cap,fix,u;
        printk( KERN_INFO "support mtrr\n");
        mtrr_cap = mtrr_cap_fun();                         // reading IA32_MTRRCAP msr
        printk( KERN_INFO "mtrr_cap: %llx\n",mtrr_cap);
        unsigned long long mtrr_def = mtrr_def_fun();      // reading IA32_MTRR_DEF_TYPE msr
        printk( KERN_INFO "mtrr_def: %llx\n",mtrr_def);

        //on_each_cpu(mtrr_def_set_fun,NULL,1);
        unsigned int index = IA32_MTRR_FIX4K_F0000;//IA32_MTRR_FIX16K_a0000	IA32_MTRR_FIX4K_F0000	IA32_MTRR_FIX4K_C0000
        fix = mtrr_fixed_fun(index);

        printk( KERN_INFO "before: fix %x: %llx\n",index,fix);

        gl_set_mtrr(IA32_MTRR_FIX4K_F0000 ,0x06060606,0x06060606);
        gl_set_mtrr(IA32_MTRR_FIX4K_F8000 ,0x06060606,0x06060606);
        gl_set_mtrr(IA32_MTRR_FIX4K_C0000 ,0x06060606,0x06060606);
        gl_set_mtrr(IA32_MTRR_FIX4K_C8000 ,0x06060606,0x06060606);

        //on_each_cpu(set_fix,0x00000006,1);
		//set_fix(0x06060606,0x06060606);
        fix = mtrr_fixed_fun(index);

	    printk( KERN_INFO "after: fix %x: %llx\n",index,fix);  // testing only one if the value has changed or not

        //resres = request_mem_region(phy_addr,heapStackSize,"test");	//fee01000	fec00400	fed94000	fee00000	fed92000

        heapStack =ioremap_prot(phy_addr,heapStackSize,_PAGE_CACHE_MODE_WB);//_PAGE_CACHE_UC_MINUS	f7c20000	f0000	d68c2000	d7800000 fe2c0000 7d0
        //heapStack =ioremap_prot(phy_addr,heapStackSize,0); // 0 is for 	_PAGE_CACHE_MODE_WB
        //heapStack = (void *)__get_free_pages(GFP_KERNEL,gl_order);

        if(!heapStack)
            return -ERESTARTSYS;
        //heapStack = __va(phy_addr);
        //set_memory_wb((unsigned long)heapStack, gl_pageNum);
        //heapStackTop = heapStack + heapStackSize - 8;

        heapStackTop = heapStack + heapStackSize - 8;
        printk(KERN_INFO "After setup: heapStackTop: 0x%p",heapStackTop);

        // check if I can run invd
        //wbinvd();
        //asm volatile("invd\n":::);
        //smp_call_function(disCache,NULL,1);
        //run_invd();
        //smp_call_function(enaCache,NULL,1);
        //printk( KERN_ALERT "invd run\n");



    }else{
        printk( KERN_ALERT "do not support mtrr\n");
    }


  //  */
/*
    int mtrr_add_r =  mtrr_add(0xf7c20000, 4096, MTRR_TYPE_WRBACK,0);
    //int mtrr_add_r = arch_phys_wc_add(0xf7c20000, 4096);
    printk( KERN_ALERT "mtrr_add_r: 0x%x\n",mtrr_add_r);
    set_cpus_allowed_ptr(current,&saved_cpu_mask);
*/

/*
    int mtrr_add_r = memremap(0xf7c20000, 4096, MEMREMAP_WB);
    printk( KERN_ALERT "mtrr_add_r: 0x%x\n",mtrr_add_r);
    set_cpus_allowed_ptr(current,&saved_cpu_mask);
*/
    //test function to simulate the IO call
    //test_func(heapStack);





    return 0;
}

static void __exit car_cleanup(void){
    proc_remove(ent);
    printk(KERN_INFO "Removing Car module.\n");
}

module_init(car_init);
module_exit(car_cleanup);

