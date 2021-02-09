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
#include <asm/io.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <asm/mtrr.h>
//#include <uapi/asm/mtrr.h>
#include <linux/stop_machine.h>

#include "file_CCK.h"

#include "cacheCryptoMain.h"
#include "ioc.h"
#include "aes.h"

MODULE_AUTHOR("<rabbitlennon>");
MODULE_DESCRIPTION("isoToken driver");
MODULE_LICENSE("GPL");

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

/*
static int mass(int a,int b,int c){
	int i,j,t = 2;
	for(i=0;i<0x4FFFF;++i){
		t+=34;
		t*=34;
		t/=a;
		for(j=0;j<0xFFF;++j){
			t*=b;
			t/=c;
		}
		t += (i+a);
	}
	return t;

}
*/
#include <linux/random.h>
unsigned char randArray[RandArraySize];
void exchange(unsigned char *p1,unsigned char *p2){
	unsigned char t = *p1;
	*p1 = *p2;
	*p2 = t;
}

static inline void gl_clflush(volatile void *__p)
{
	asm volatile("clflush %0" : "+m" (*(volatile char __force *)__p));
}
//????????????????up is not understand???????????????????????????????????????????????????????????????????///


asmlinkage unsigned int gl_clflush_cache_range(void *vaddr, unsigned int size)
{
	void *vend = vaddr + size - 1;

	mb();

	for (; vaddr < vend; vaddr += boot_cpu_data.x86_clflush_size)
		gl_clflush(vaddr);
	/*
	 * Flush any possible final partial cacheline:
	 */
	gl_clflush(vend);

	mb();
	return 0;
}


void disCache(void *p){
	asm volatile(	"wbinvd\n"
		"movl	%%cr0,%%eax\n"
		"orl	$0x40000000,%%eax\n"
		"movl	%%eax,%%cr0\n"
		"wbinvd\n":::"eax"
	);
}
void disCache_nofill(void *p){
	asm volatile(
		"movl	%%cr0,%%eax\n"
		"orl	$0x40000000,%%eax\n"
		"movl	%%eax,%%cr0\n":::"eax"
	);
}
void enaCache(void *p){
	asm volatile(	"movl	%%cr0,%%eax\n"
		"andl	$0x9FFFFFFF,%%eax\n"
		"movl	%%eax,%%cr0\n":::"eax"
	);
}

asmlinkage unsigned int gl_clflush_cache_range(void *, unsigned int );
asmlinkage unsigned int set_fix(unsigned int ,unsigned int );
asmlinkage unsigned long long mtrr_fixed_fun(unsigned int );
asmlinkage unsigned long long mtrr_def_set_fun(void);
asmlinkage unsigned long long mtrr_def_fun(void);
asmlinkage unsigned long long mtrr_cap_fun(void);
asmlinkage unsigned long long mtrr_fun(void);
asmlinkage int safeCall1(void *,void *, void *);
asmlinkage int invd_t(unsigned char *);
asmlinkage int enter_no_fill(void);
asmlinkage int exit_no_fill(void);
asmlinkage unsigned int getCR0(void);
//asmlinkage void disCache(void *);
//asmlinkage void enaCache(void *);
asmlinkage int prepareMemAndDisCache(unsigned char *,unsigned int );
asmlinkage unsigned int readAddr(unsigned char *);
asmlinkage unsigned int readAddrInv(unsigned char *);
asmlinkage unsigned int readCompare(unsigned char *,unsigned int *,unsigned int *,unsigned int *);
asmlinkage void flushMemTest(unsigned char *,int );
asmlinkage unsigned int testStackSpeed(unsigned int *);
asmlinkage unsigned int readMem(unsigned char *,int);
asmlinkage unsigned int writeMem(unsigned char *,int);


asmlinkage void tresor_get_key(u8 *);

//need to be in cache
//ProtectedMem protectedMem;

static DEFINE_RAW_SPINLOCK(gl_mtrr_lock);
/*
void tresor_prolog(unsigned long *irq_flags)
{
	unsigned int i,id = smp_processor_id();
	cpumask_t tmpMask;

	cpumask_clear(&tmpMask);
	cpumask_set_cpu(id,&tmpMask);
	set_cpus_allowed_ptr(current,&tmpMask);
	P_DEBUG("now on %d\n",id);

	cpumask_clear(&tmpMask);
	for(i=0;i<4;++i){
		if(i != id)
			cpumask_set_cpu(i,&tmpMask);
	}
	P_DEBUG("disable on: 0x%lx\n",cpumask_bits(&tmpMask)[0]);
	//on_each_cpu_mask(&tmpMask,disCache,NULL,1);
	//smp_call_function_many(&tmpMask,disCache,NULL,1);
	smp_call_function(disCache, NULL, 1);
	
	preempt_disable();
	local_irq_save(*irq_flags);
}
*/
#define CPUNUM 4
//DEFINE_PER_CPU(ProtectedMem,env);
ProtectedMem env[CPUNUM];
DEFINE_SEMAPHORE(mutex01);
DEFINE_SEMAPHORE(mutex23);
#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>
#include <linux/bug.h>


int tresor_prolog(unsigned long *irq_flags,ProtectedMem **pm)
{
	unsigned int id,onID;
	cpumask_t tmpMask;
	int r;

	r = down_interruptible(&mutex01);
	if(r == -EINTR)
		return -1;

	id = get_cpu();
	*pm = env + id;


	smp_call_function(disCache_nofill,NULL,1);
	local_irq_save(*irq_flags);
	return id;
}


/*
 * Epilog: leave atomic section
 */
void tresor_epilog(unsigned long *irq_flags,ProtectedMem *pm)
{
	unsigned int id,onID;
	cpumask_t tmpMask;
	local_irq_restore(*irq_flags);

	smp_call_function(enaCache,NULL,1);

	put_cpu();

	up(&mutex01);

	
}


/*
int tresor_prolog(unsigned long *irq_flags,ProtectedMem **pm)
{
	unsigned int id,onID;
	cpumask_t tmpMask;
	int r;
	id = get_cpu();
	//id = smp_processor_id();
	//cpumask_clear(&tmpMask);
	//cpumask_set_cpu(id,&tmpMask);
	//set_cpus_allowed_ptr(current,&tmpMask);

	if(id == 0 || id == 1)
		r = down_interruptible(&mutex01);
		//r = down_killable(&mutex01);
	else
		r = down_interruptible(&mutex23);
		//r = down_killable(&mutex23);
	if(r == -EINTR){
		put_cpu();
		return -1;
	}

//	if(id != get_cpu()){
//		if(id == 0 || id==1)
//			up(&mutex01);
//		else
//			up(&mutex23);
//		put_cpu();
//		return -1;
//	}
	switch(id){
		case 0:
			onID = 1;
			break;
		case 1:
			onID = 0;
			break;
		case 2:
			onID = 3;
			break;
		case 3:
			onID = 2;
			break;
		default:
			break;

	}
	*pm = env + id;
	cpumask_clear(&tmpMask);
	cpumask_set_cpu(onID,&tmpMask);

	//smp_call_function_many(&tmpMask,disCache_nofill,NULL,1);
	smp_call_function_many(&tmpMask,disCache,NULL,1);
	//*pm = &(get_cpu_var(env));
	//id = smp_processor_id(); 
	
	//memset(*pm,0,sizeof(ProtectedMem));
	
	//mb();
//	preempt_disable();
//	spin_lock_irqsave(&gl_mtrr_lock1,*irq_flags);
	
	local_irq_save(*irq_flags);
	return id;
}


void tresor_epilog(unsigned long *irq_flags,ProtectedMem *pm)
{
	unsigned int id,onID;
	cpumask_t tmpMask;
	local_irq_restore(*irq_flags);
	id = smp_processor_id();
	cpumask_clear(&tmpMask);
	switch(id){
		case 0:
			onID = 1;
			break;
		case 1:
			onID = 0;
			break;
		case 2:
			onID = 3;
			break;
		case 3:
			onID = 2;
			break;
		default:
			break;

	}

	cpumask_set_cpu(onID,&tmpMask);
	smp_call_function_many(&tmpMask,enaCache,NULL,1);
	//memset(pm,0,sizeof(ProtectedMem));
	//put_cpu_var(env);
	if(id == 0 || id == 1)
		up(&mutex01);
	else 
		up(&mutex23);

	put_cpu();
	//preempt_enable();

	//on_each_cpu(enaCache,NULL,1);
	
}

*/

//function declaration///////////////////////////
static int isoToken_open(struct inode *, struct file *);
static int isoToken_release(struct inode *, struct file *);

static void __init init_isoToken__dev(void);
static long isoToken_ioctl(struct file *, unsigned int, unsigned long);
static ssize_t isoToken_read(struct file *, char __user *, size_t ,loff_t *);
static ssize_t isoToken_write(struct file *, const char __user *, size_t ,loff_t *);



//global variants////////////////////////////////
char *module_name = "isoToken";
char *readMes = "read from isoToken is not supported\n";
RSA_KEY keys_kernel[MAX_KEYS];	//encrypt
//int keyNum_kernel = 0;




//uint8_t *heapStackTop;
//static uint8_t master_key[MASTER_KEY_SIZE];
//PRI_KEY priKey[MAX_KEYS];
//uint8_t signIn[MAX_MOD] = {0};
//uint8_t signOut[MAX_MOD] = {0};
//Sign_Para signPara;

//#define heapStackSize	(4096*1)
//uint8_t *heapStack;
//uint8_t *heapStackTop;
//uint8_t heapStack[heapStackSize];
//uint8_t *heapStackTop = heapStack + heapStackSize - 4;





static const struct file_operations isoToken_fops = {
	.owner = THIS_MODULE,
	.open = isoToken_open,
	.release = isoToken_release,
	.read = isoToken_read,
	.write = isoToken_write,
	.unlocked_ioctl = isoToken_ioctl,
};

static struct IsoToken_dev isoToken_dev;
static struct miscdevice innerDev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "isoToken",
	.fops = &isoToken_fops,
};



static void __init init_isoToken__dev(void){
	//rsa_context *rsa = NULL;

	isoToken_dev.master_key_present = 0;	//from loading
	isoToken_dev.keyPresent = 0;		//read from loading
	isoToken_dev.cdev = &innerDev;
	//formRandArray();
	memset(env,0,sizeof(env));
	//wbinvd();
	//memset((unsigned char *)&protectedMem,0,sizeof(protectedMem));
	
	//signPara.in = signIn;
	//signPara.out = signOut;

/*
	priKey[0].key_id[0] = 1;priKey[0].key_id[1] = 1;priKey[0].key_id[2] = 1;



	
	rsa = &(priKey[0].rsa);

	rsa_init( rsa, RSA_PKCS_V15, 0 );

	rsa->len = KEY_LEN;
	mpi_read_string( &rsa->N , 16, RSA_N  );
	mpi_read_string( &rsa->E , 16, RSA_E  );
	mpi_read_string( &rsa->D , 16, RSA_D  );
	mpi_read_string( &rsa->P , 16, RSA_P  );
	mpi_read_string( &rsa->Q , 16, RSA_Q  );
	mpi_read_string( &rsa->DP, 16, RSA_DP );
	mpi_read_string( &rsa->DQ, 16, RSA_DQ );
	mpi_read_string( &rsa->QP, 16, RSA_QP );
*/


}

static int isoToken_open(struct inode *inode, struct file *filp)
{
	//isoToken_dev.ppriKey = priKey;
	isoToken_dev.msg = readMes;
	filp->private_data = (void *)&isoToken_dev;
	return 0;
}

static int isoToken_release(struct inode *inode, struct file *filp){
	return 0;
}
extern cpumask_t allowed;
//cpumask_t saved_cpu_mask;
struct mtrr_data{
	unsigned int reg;
	unsigned int value_h;
	unsigned int value_l;
};
//static DEFINE_RAW_SPINLOCK(gl_mtrr_lock);
static unsigned int deftype_lo,deftype_hi,cr4;
static void prepare_set(void) __acquires(gl_mtrr_lock)
{
	unsigned long cr0;

	/*
	 * Note that this is not ideal
	 * since the cache is only flushed/disabled for this CPU while the
	 * MTRRs are changed, but changing this requires more invasive
	 * changes to the way the kernel boots
	 */

	raw_spin_lock(&gl_mtrr_lock);

	/* Enter the no-fill (CD=1, NW=0) cache mode and flush caches. */
	cr0 = read_cr0() | X86_CR0_CD;
	write_cr0(cr0);
	wbinvd();

	/* Save value of CR4 and clear Page Global Enable (bit 7) */
	if (cpu_has_pge) {
		cr4 = read_cr4();
		write_cr4(cr4 & ~X86_CR4_PGE);
	}

	/* Flush all TLBs via a mov %cr3, %reg; mov %reg, %cr3 */
	__flush_tlb();

	/* Save MTRR state */
	rdmsr(MSR_MTRRdefType, deftype_lo, deftype_hi);

	/* Disable MTRRs, and set the default type to uncached */
	//mtrr_wrmsr(MSR_MTRRdefType, deftype_lo & ~0xcff, deftype_hi);
	asm volatile("wrmsr" : : "c" (MSR_MTRRdefType), "a"(deftype_lo & ~0xcff), "d" (deftype_hi) : "memory");
	wbinvd();
}

static void post_set(void) __releases(set_atomicity_lock)
{
	/* Flush TLBs (no need to flush caches - they are disabled) */
	__flush_tlb();

	/* Intel (P6) standard MTRRs */
	//mtrr_wrmsr(MSR_MTRRdefType, deftype_lo, deftype_hi);
	asm volatile("wrmsr" : : "c" (MSR_MTRRdefType), "a"(deftype_lo), "d" (deftype_hi) : "memory");
	/* Enable caches */
	write_cr0(read_cr0() & 0xbfffffff);

	/* Restore value of CR4 */
	if (cpu_has_pge)
		write_cr4(cr4);
	raw_spin_unlock(&gl_mtrr_lock);
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

}
struct resource *resres = NULL;
unsigned long phy_addr = 0xc0000;


int readFromFile(char *fileName){
    int i,ret = 0;
    struct file *fp;
    unsigned long long offset = 0;
    int keyN = 0;
    fp = file_open(fileName, O_RDWR, 0);
    if(!fp){
        P_DEBUG("file %s does not exist\n",fileName);
        goto err;
    }
    file_read(fp,offset,(unsigned char *)&keyN,sizeof(keyN));
    offset += sizeof(keyN);
    //fread(&keyN,sizeof(keyN),1,fp);
    for(i=0;i<keyN;++i){
        //fread((unsigned char *)(keys_kernel + i),sizeof(RSA_KEY),1,fp);
	file_read(fp,offset,(unsigned char *)(keys_kernel + i),sizeof(RSA_KEY));
	offset += sizeof(RSA_KEY);
    }
    file_close(fp);
    ret = keyN;
err:
    return ret;
}


int __init init_isoToken(void)
{
	int rc;
	mm_segment_t ofs;
	unsigned long long mtrr_r;

	init_isoToken__dev();
	rc = misc_register(isoToken_dev.cdev);
	if (unlikely(rc)){
		printk( KERN_ALERT "registration of /dev/%s failed\n",module_name);
		return rc;
	}
	printk( KERN_ALERT "dirver %s loaded\n",module_name );

	//heapStackTop = protectedMem.heapStack + heapStackSize - 4;
	//P_DEBUG("heapStackTop: 0x%p",heapStackTop);
	//P_DEBUG("heapStack: 0x%p",protectedMem.heapStack);
/*
	//saved_cpu_mask = current->cpus_allowed;

	//printk( KERN_ALERT"allowed_mask: 0x%lx\n",cpumask_bits(&allowed)[0]);

	//printk(KERN_ALERT "current mask: 0x%lx\t current cpu: %d\n",cpumask_bits(&(current->cpus_allowed))[0],smp_processor_id());
	gl_set_mtrr(IA32_MTRR_FIX4K_F0000 ,0x06060606,0x06060606);
	gl_set_mtrr(IA32_MTRR_FIX4K_F8000 ,0x06060606,0x06060606);
	gl_set_mtrr(IA32_MTRR_FIX4K_C0000 ,0x06060606,0x06060606);
	gl_set_mtrr(IA32_MTRR_FIX4K_C8000 ,0x06060606,0x06060606);
	mtrr_r = mtrr_fun();
	printk( KERN_ALERT "mtrr_r: 0x%llx\n",mtrr_r);
	if((mtrr_r>>32) & (1 << (12))){
		unsigned long long mtrr_cap,fix,u;
		printk( KERN_ALERT "support mtrr\n");
		mtrr_cap = mtrr_cap_fun();
		printk( KERN_ALERT "mtrr_cap: %llx\n",mtrr_cap);
		unsigned long long mtrr_def = mtrr_def_fun();
		printk( KERN_ALERT "mtrr_def: %llx\n",mtrr_def);
		//on_each_cpu(mtrr_def_set_fun,NULL,1);
		unsigned int index = IA32_MTRR_FIX4K_F0000;//IA32_MTRR_FIX16K_a0000	IA32_MTRR_FIX4K_F0000	IA32_MTRR_FIX4K_C0000
		fix = mtrr_fixed_fun(index);
		
		printk( KERN_ALERT "before: fix %x: %llx\n",index,fix);
	//	on_each_cpu(set_fix,0x00000006,1);
//		set_fix(0x06060606,0x06060606);
		fix = mtrr_fixed_fun(index);
		printk( KERN_ALERT "after: fix %x: %llx\n",index,fix);

		//resres = request_mem_region(phy_addr,heapStackSize,"test");	//fee01000	fec00400	fed94000	fee00000	fed92000
		//heapStack =ioremap_prot(phy_addr,heapStackSize,_PAGE_CACHE_WB);//_PAGE_CACHE_UC_MINUS	f7c20000	f0000	d68c2000	d7800000 fe2c0000 7d0
		//heapStack = (void *)__get_free_pages(GFP_KERNEL,gl_order);
		//if(!heapStack)
		//	return -ERESTARTSYS;
		//heapStack = __va(phy_addr);
		//set_memory_wb((unsigned long)heapStack, gl_pageNum);
		//heapStackTop = heapStack + heapStackSize - 4;

	}
	else 
		printk( KERN_ALERT "do not support mtrr\n");

*/
	//int mtrr_add_r = 	mtrr_add(0xf7c20000, 4096, MTRR_TYPE_WRBACK,0);
	//printk( KERN_ALERT "mtrr_add_r: 0x%x\n",mtrr_add_r);
	//set_cpus_allowed_ptr(current,&saved_cpu_mask);
	return 0;
}


static ssize_t isoToken_read(struct file *filp, char __user *buf, size_t count,loff_t *f_pos){
	char *msgEnd = readMes + strlen(readMes);
	char **currentp;
	int sent;
	//if (down_interruptible(&((struct IsoToken_dev *)(filp->private_data))->sem))
	//	return -ERESTARTSYS;

	currentp = &(((struct IsoToken_dev *)(filp->private_data))->msg);
	if(((struct IsoToken_dev *)(filp->private_data))->msg  == (msgEnd - 1) ){
		//up((&((struct IsoToken_dev *)(filp->private_data))->sem));
		return 0;
	}
	sent = count < (msgEnd - *currentp) ? count : (msgEnd - *currentp);
	if(copy_to_user(buf,readMes,sent)){
		P_DEBUG("error\n");
		return -EFAULT;
	}
	P_DEBUG("sent:%d\n",sent);
	(*currentp) += sent;
	//up((&((struct IsoToken_dev *)(filp->private_data))->sem));
	return sent;

}
static ssize_t isoToken_write(struct file *filp, const char __user *buf, size_t count,loff_t *f_pos){
	return count;
}

asmlinkage void sign(pSign_Para para,rsa_context *rsa){
	//flushMemTest(heapStack,heapStackSize);
	//unsigned int spValue;
	//unsigned int timeUsed = testStackSpeed(&spValue);
	//P_DEBUG("test Time: %x %d\tsp: %x\n",timeUsed,timeUsed,spValue);
	//P_DEBUG("para->index: %x\n",para->index);
	
	//para->index  = 0;
	//if( rsa_pkcs1_encrypt( &(priKey[para->index].rsa), &myrand, NULL, RSA_PRIVATE, PT_LEN, para->in, para->out ) != 0 )
	if(rsa_private( rsa, para->in, para->out ))
		;//P_DEBUG("sign error\n");
	else
		;//P_DEBUG("sign OK\n");

	

}

/*
asmlinkage static void sign(unsigned int *p){
	*p = 0x12345678;
		P_DEBUG("sign OK\n");

	

}
*/

typedef struct _AES_SETKEY_PARA{
	aes_context *ctx;
	unsigned char *key;
	int ret;
}AES_SETKEY_PARA;

typedef struct _USEKEY_PARA{
	rsa_context *rsa;
	unsigned char *keyLabel;
	int num;
	unsigned char *key;
	int ret;
}USEKEY_PARA;


asmlinkage int aes_setkey_dec_safe(AES_SETKEY_PARA *para){
	para->ret = aes_setkey_dec(para->ctx,para->key,AES_KEY_SIZE_BITS);
	return para->ret;
}
//( aes_context *ctx, const unsigned char *key, unsigned int keysize )
asmlinkage int useKey(ProtectedMem *pm,int num){
    int i,j,ret = 1;
    unsigned char *key = pm->master_key;
    //aes_context aes;
    rsa_context *rsa = &(pm->rsa);
    unsigned char plain[sizeof(RSA_KEY_NO_LABEL)];
    RSA_KEY_NO_LABEL_PTR rsa_no_label;
    //AES_SETKEY_PARA aes_para;
//unsigned int esp;

    rsa_init(rsa,RSA_PKCS_V15, 0);

    for(i=0;i<num;++i){
        if(!strcmp(pm->signPara.label,(char *)(keys_kernel + i)))
            break;
    }
    if(i == num)
        goto err;
    
    //aes_para.ctx = &(protectedMem.aes);
    //aes_para.key = key;
    if(aes_setkey_dec(&(pm->aes),key,AES_KEY_SIZE_BITS)){
    //if(aes_setkey_dec_safe(&aes_para)){
    //safeCall1(&aes_para,aes_setkey_dec_safe,heapStackTop);
    //if(aes_para.ret){
        //P_DEBUG("set Key err\n");
        goto err;
    }



    if(mpi_read_binary(&rsa->N,keys_kernel[i].N,sizeof(keys_kernel[i].N)))
        goto err;

    if(mpi_read_binary(&rsa->E,keys_kernel[i].E,sizeof(keys_kernel[i].E)))
        goto err;


    for(j=0;j<sizeof(plain)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&(pm->aes),AES_DECRYPT,(unsigned char *)(keys_kernel + i) + 2 * (4 + MAX_MPI_IN_BYTE) + LABEL_SIZE + AES_BLOCK_SIZE*j,plain+AES_BLOCK_SIZE*j);
    }
    rsa_no_label = (RSA_KEY_NO_LABEL_PTR)plain;
    //if(mpi_read_binary(&rsa->N,rsa_no_label->N,sizeof(rsa_no_label->N)))
    //    goto err;

    //if(mpi_read_binary(&rsa->E,rsa_no_label->E,sizeof(rsa_no_label->E)))
    //    goto err;

    if(mpi_read_binary(&rsa->D,rsa_no_label->D,sizeof(rsa_no_label->D)))
        goto err;

    if(mpi_read_binary(&rsa->P,rsa_no_label->P,sizeof(rsa_no_label->P)))
        goto err;

    if(mpi_read_binary(&rsa->Q,rsa_no_label->Q,sizeof(rsa_no_label->Q)))
        goto err;

    if(mpi_read_binary(&rsa->DP,rsa_no_label->DP,sizeof(rsa_no_label->DP)))
        goto err;

    if(mpi_read_binary(&rsa->DQ,rsa_no_label->DQ,sizeof(rsa_no_label->DQ)))
        goto err;

    if(mpi_read_binary(&rsa->QP,rsa_no_label->QP,sizeof(rsa_no_label->QP)))
        goto err;

    rsa->len = keys_kernel[i].sizeofN;
    ret = 0;

//asm volatile("movl %%esp,%0\n" : "=r"(esp)::);
//printk( KERN_DEBUG "esp: usekey 0x%x id: %d\n",esp,smp_processor_id());
err:
    return ret;
}

//asmlinkage int useKey_safe(USEKEY_PARA *para){
//	para->ret = useKey(para->rsa,para->keyLabel,para->num,para->key);
//	return para->ret;
//}

typedef struct _DoAll{
	ProtectedMem *pm;
	unsigned int num;
}DoAll,*DoALL_PTR;
unsigned char mkt[16] = { \
0x52,0x47,0x99,0x32, \
0x4f,0x20,0x6d,0xf0, \
0x1f,0x5b,0x30,0x31, \
0x0c,0xe3,0x50,0x1a \
};

asmlinkage void doAll_fun(DoAll *para){
	int r = 0;
	if(!para)	
		return;
	//asm volatile("wbinvd\n":::);
	//wbinvd();
	//mb();
	//tresor_get_key(para->pm->master_key);
	memcpy(para->pm->master_key,mkt,16);
	//P_DEBUG("MK: %x %x %x\n",protectedMem.master_key[0],protectedMem.master_key[1],protectedMem.master_key[2]);

	r = useKey(para->pm,para->num);//isoToken_dev_p->keyPresent
	if(r){
		P_DEBUG("usekey err\n");
		return;
	}
	//P_DEBUG("rsa key size: %d",para->pm->rsa.len);
	//sign(&(para->pm->signPara),&(para->pm->rsa));
	rsa_private( &(para->pm->rsa), para->pm->signPara.in,  para->pm->signPara.out );
	//asm volatile("wbinvd\n":::);
	//gl_clflush_cache_range(para->pm->signPara.out,MAX_MPI_IN_BYTE);
	return;
}

int getPub(GetPubPara *para,int num){
	int i,j,ret = 1;


	for(i=0;i<num;++i){
		if(!strcmp(para->label,(char *)(keys_kernel + i)))
	   		 break;
	}
	if(i == num)
		goto err;

	memcpy(para->N,keys_kernel[i].N,sizeof(keys_kernel[i].N));
	memcpy(para->E,keys_kernel[i].E,sizeof(keys_kernel[i].E));
	ret = 0;
err:
	return ret;
}

//int checkCache(unsigned char *p, int num,int *avg,int *max,int *line){
int checkCache(unsigned char *p, int num){
	unsigned long long r1,r2;
	int total,i,r = 0;
	unsigned char *buf = p;
//	total =0;
//	*max = 0;
	for(i=0;i<num;++i){
		buf = p + randArray[i]*64;
		r1 = get_cycles();
		asm volatile("movl (%0),%%eax;\n" \
				::"r"(buf) : "%eax");
//				"inc %%eax;\n"     
		r2 = get_cycles();
		if(r2 - r1 > 100)
			r = 1;
//		if((r2-r1) > (*max)){
//			*max = r2-r1;
//			*line = randArray[i];
//		}
//		total += (r2-r1);
		//if(i==0)	
		//	*avg = r2 - r1;
	}
//	*avg = total/num;
	return r;
}


void fillL1(unsigned char *p, int num){
	int i;
	unsigned char *buf = p;
	for(i=0;i<num;++i){
		asm volatile(	"movl $0,(%0);\n" \
				::"r"(buf) : );
		buf += 64;
	}
}
int checkErr(ProtectedMem *pm){
	unsigned char *p = pm->master_key;
	//for(;p<(unsigned char *)&(pm->signPara)-52;++p)
	for(;p<(unsigned char *)&(pm->signPara)-152;++p)
		if(*p != 0)
			return 1;
	return 0;
}


static long isoToken_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct IsoToken_dev *isoToken_dev_p = NULL;
	unsigned int sound;
	int count,ticks;

	sound = 0x020f00f0;

	ticks = HZ * ((sound >> 16) & 0xffff) / 1000;
	count = ticks ? (sound & 0xffff) : 0;
	if (count)
		count = PIT_TICK_RATE / count;



	isoToken_dev_p = (struct IsoToken_dev *)(filp->private_data);
	switch(cmd){
		case IsoToken_IOC_SET_MASTER_KEY:{
				int seconds = 8;
				unsigned long flags;
				ProtectedMem *pm;
				get_user(seconds,(int *)arg);
				printk( KERN_DEBUG "delaying %d seconds\n",seconds);
				tresor_prolog(&flags,&pm);
				mdelay(1000*seconds);
				tresor_epilog(&flags,pm);
				//if(copy_from_user(protectedMem.master_key,m_u,MASTER_KEY_SIZE)){
				//	P_DEBUG("error\n");
				//	goto err;		
				//}
				//P_DEBUG("%d %d %d\n",protectedMem.master_key[0],protectedMem.master_key[1],protectedMem.master_key[2]);				
				break;
			}
		
		case IsoToken_IOC_GET_PRIVATE_KEY_ID_NUM:{				

				isoToken_dev_p->master_key_present = 0;	//from loading

				isoToken_dev_p->keyPresent = readFromFile("/EncRsaKey.key");
				//keyNum_kernel = readFromFile("/EncRsaKey.key");
				P_DEBUG("%d keys in file\n",isoToken_dev_p->keyPresent);

				put_user(isoToken_dev_p->keyPresent,(int *)arg);
				//P_DEBUG( "addr for arg: 0x%p\t phy: 0x%p\n",arg,virt_to_phys(arg));
				break;
			}
		


		case IsoToken_IOC_GET_PRIVATE_KEY_ID:{
				uint8_t *m_u = (uint8_t *)arg;
				int i = 0;
				
//enter isoToken
				for(;i<isoToken_dev_p->keyPresent;++i){
					//if(copy_to_user(m_u + i*KEY_ID_LEN,priKey[i].key_id,KEY_ID_LEN))
						goto err;				
					
				}
				break;
			}
		case IsoToken_IOC_GET_PUBKEY:{
				GetPubPara *m_u = (GetPubPara *)arg;
				GetPubPara m_k;
				if(copy_from_user((unsigned char *)(m_k.label),(unsigned char *)(m_u->label),LABEL_SIZE)){
					P_DEBUG("error\n");
					goto err;
				}
				m_k.label[LABEL_SIZE -1]  =0;
				P_DEBUG("getPub: %s\n",m_k.label);
				if(getPub(&m_k,isoToken_dev_p->keyPresent))
					goto err;
				if(copy_to_user(m_u->N,m_k.N,MAX_MPI_IN_BYTE))
					goto err;
				if(copy_to_user(m_u->E,m_k.E,MAX_MPI_IN_BYTE))
					goto err;
				break;
			}
		case IsoToken_IOC_SIGN:{
				pSign_Para m_u = (pSign_Para)arg;
				int check,index,i,r,tries,avg,avg1,avg2,max,max1,max2,line,line1,line2;
				unsigned long flags;
				//unsigned long beg,end;
				//unsigned long long r1,r2,r3,r4,r6,r5,r7,r8,r9,r10;
				//unsigned int cr0,timeA,timeB,timeC,retret,id;
				int id;
				ProtectedMem *pm;
				DoAll doall;

				unsigned char in[MAX_MPI_IN_BYTE];
				char label[LABEL_SIZE] = {0};
				char labelsmall[LABEL_SIZE] = {'s','m','a','l','l',0};

				
				//memset(&protectedMem,0,sizeof(protectedMem));	
				if(copy_from_user((unsigned char *)label,(unsigned char *)(m_u->label),LABEL_SIZE)){
					P_DEBUG("error\n");
					goto noirqerr;
				}
				label[LABEL_SIZE -1]  =0;
				//printk( KERN_DEBUG "using key: %s\n",label);

				if(copy_from_user(in,m_u->in,MAX_MPI_IN_BYTE)){//protectedMem.signPara.rsa.len
					P_DEBUG("error\n");
					goto noirqerr;
				}
				tries = 0;
				id = tresor_prolog(&flags,&pm);
				if(id == -1)
					goto err;
				//access data
		again:
				//wbinvd();
				//checkCache(pm,(sizeof(ProtectedMem)+63)/64,&avg1);
				//memset(pm,0,sizeof(ProtectedMem)); //repalce with more efficient method later
				//access code
				//memcpy(pm->signPara.label,labelsmall,LABEL_SIZE);
				//memcpy(pm->signPara.label,label,LABEL_SIZE);
				//memcpy(pm->signPara.in,in,MAX_MPI_IN_BYTE);
				//pm->signPara.in[0] = 0;
				//pm->signPara.in[1] = 0;
				doall.pm = pm;
				doall.num = isoToken_dev_p->keyPresent;

				//fillL1(pm,RandArraySize);
				//asm volatile("sfence\n" :::);
				//fillL1(pm,RandArraySize);
				//checkCache(pm,RandArraySize,&avg2,&max2,&line2);
			//	r1 = get_cycles();
			//	safeCall1(&doall,doAll_fun,pm->heapStack + heapStackSize - 4);
			//	r2 = get_cycles();
				memcpy(pm->signPara.label,label,LABEL_SIZE);
				memcpy(pm->signPara.in,in,MAX_MPI_IN_BYTE);
				//mb();

				//safeCall1(&doall,doAll_fun,pm->heapStack + heapStackSize - 4);
				//memset(pm,0,sizeof(ProtectedMem)); //repalce with more efficient method later
				//writeMem(pm,(sizeof(ProtectedMem)+3)/4);
				//memcpy(pm->signPara.label,label,LABEL_SIZE);
				//memcpy(pm->signPara.in,in,MAX_MPI_IN_BYTE);
				//safeCall1(&doall,doAll_fun,pm->heapStack + heapStackSize - 4);
				//fillL1(pm,RandArraySize);
				//mb();
				//asm volatile("sfence\n" :::);
				//smb();
				//lmb();
				//disCache_nofill(NULL);
				//doall.pm = pm;
				//mb();

				//if(checkCache(pm,RandArraySize)){
					//enaCache(NULL);
					//tresor_epilog(&flags,pm);
				//	tries++;
				//	goto again;	
					
				//}

				//poi = pm;
				//for(poi=pm;poi<pm+sizeof(ProtectedMem);poi+=4){
					//r7 = get_cycles();
					//asm volatile("movl %%eax,(%0);\n" ::"r"(poi) : );
					//r8 = get_cycles();
					//r9 = get_cycles();

					//readMem(poi,1);
					//r10 = get_cycles();
				//	printk( KERN_DEBUG "line: lld\t",r6-r5);
				//}
				//printk(KERN_DEBUG "\n");
				
				//r5 = get_cycles();
				//memset(pm,0,sizeof(ProtectedMem)); //repalce with more efficient method later
				//readMem(pm,(sizeof(ProtectedMem)+3)/4);
				//r6 = get_cycles();
				//memcpy(pm->signPara.in,in,MAX_MPI_IN_BYTE);
//doall.num = isoToken_dev_p->keyPresent;
			//	r3 = get_cycles();
				safeCall1(&doall,doAll_fun,pm->heapStack + heapStackSize - 4);
			//	r4 = get_cycles();
				

				//wbinvd();
				//memcpy(pm->signPara.label,label,LABEL_SIZE);
				//memcpy(pm->signPara.in,in,MAX_MPI_IN_BYTE);
				//r5 = get_cycles();
				//safeCall1(&doall,doAll_fun,pm->heapStack + heapStackSize - 4);
				//r6 = get_cycles();
//clear
				//checkCache(pm,RandArraySize,&avg1,&max1,&line1);
				//enaCache(NULL);


				//asm volatile("invd\n":::);
	irqerr:	
				memcpy(in,pm->signPara.out,MAX_MPI_IN_BYTE);
				//check = checkErr(pm);


				tresor_epilog(&flags,pm);
				//printk( KERN_DEBUG "1st: %lld 2nd: %lld 3rd: %lld 4th: %lld 5th: %lld\n tries: %d avg: %d avg1: %d avg2: %d max: %d max1: %d max2: %d line: %d line1: %d line2: %d\n",r2-r1,r4-r3,r6-r5,r8-r7,r10-r9,tries,avg,avg1,avg2,max,max1,max2,line,line1,line2);
				copy_to_user(m_u->out,in,MAX_MPI_IN_BYTE);
				//if(check)
				//	printk( KERN_DEBUG "LEAK!\n");
				//copy_to_user(m_u->out,pm->signPara.out,MAX_MPI_IN_BYTE);
				//tresor_epilog(&flags,pm);

				//mb();
				//memset((unsigned char *)&protectedMem,0,sizeof(protectedMem));
			        //printk( KERN_DEBUG "cpu: 0x%x\t\n",smp_processor_id());
//exit isoToken
				//kd_mksound(count, ticks);
noirqerr:
				//raw_spin_unlock(&gl_mtrr_lock);
				//set_cpus_allowed_ptr(current,&saved_cpu_mask);
				break;
			}
		default:
			goto err;
	}


	return 0;

	
err:
	//set_cpus_allowed_ptr(current,&saved_cpu_mask);
	return -ENOTTY;
}


void __exit cleanup_isoToken(void)
{	
	misc_deregister(isoToken_dev.cdev);
	printk( KERN_ALERT "dirver %s unloaded\n",module_name );
}



module_init(init_isoToken);
module_exit(cleanup_isoToken);
