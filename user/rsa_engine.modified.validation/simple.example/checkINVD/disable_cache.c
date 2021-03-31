#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
//#include <linux/proc_fs.h>
//#include <linux/uaccess.h>
//#include <linux/random.h>
//#include <linux/slab.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shariful");
MODULE_DESCRIPTION("Device Driver to enable/disable kernel preemption & interrupt");

//*
#define KEY_LEN 128
#define CACHE_STACK_SIZE 9000 // most likely will be changed, depending on the size of the structure
#define CACHE_LINE_SIZE 64


asmlinkage int safeCall1(void *,void *, void *);

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

    printk(KERN_INFO "cpuid %d --> cache disable\n", smp_processor_id());

}


void enaCache(void *p){
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "and $~(1<<30), %%eax\n\t"
    "mov %%rax, %%cr0\n\t"
    ::
    :"%rax"
    );

    printk(KERN_INFO "cpuid %d --> cache enable\n", smp_processor_id());

}


void fillL1(unsigned char *p, int num){
    int i;
    //unsigned char *buf = p;
    volatile unsigned char *buf=p;
    
    for(i=0;i<num;++i){

        asm volatile(
        "movq $0,(%0)\n"
        :
        :"r"(buf)
        :
        );

	//__builtin_prefetch(buf,1,1);
	//__builtin_prefetch(buf,0,3);
	//*buf += 0;

	buf += 64;
    }
    printk(KERN_INFO "Inside fillL1, num is %d\n", num);
}


int decryptFunction (struct CACHE_CRYPTO_ENV *env){
	int ret;
	//printk(KERN_INFO "Inside decryption function\n");

	// wbinvd?
	//native_wbinvd();

	//memcpy(env->out, change, sizeof (change));
	//memcpy(env->in, change, sizeof (change));
	strcpy(env->in,change);
	strcpy(env->out,change);

    printk(KERN_INFO "decryption func: env.in fixed is %s\n", env->in);
    printk(KERN_INFO "decryption func: env.out fixed is %s\n", env->out);

	return ret;

}


static int __init deviceDriver_init(void)
{
 
	unsigned long flags;
	int result;
	//printk(KERN_ALERT "invd Driver loaded\n");
    	//printk(KERN_INFO "Current CPU is %d\n", get_cpu());

	struct CACHE_CRYPTO_ENV env;

	//Initializing, set up canary words
	char word[] ="0xabcd";
	//memcpy(env.masterKey, word, sizeof(word) );
	//memcpy(env.cachestack, word, sizeof (word));
	memcpy(env.in, word, sizeof (word));
	memcpy(env.out, word, sizeof (word));
	
	//printk(KERN_INFO "env.masterkey fixed is %s\n", env.masterKey);
	//printk(KERN_INFO "env.cacheStack fixed is %s\n", env.cachestack);
	printk(KERN_INFO "env.in fixed is %s\n", env.in);
	printk(KERN_INFO "env.out fixed is %s\n", env.out);

	// preemptdisable
	preempt_disable();

	// enter no-fill mode & run wbinvd on the other cores
	// except current core
	smp_call_function(disCache,NULL,1);
	//on_each_cpu(disCache,NULL,1);

	// disable interrupts
	local_irq_save(flags);

	// fill cache with the structure
	asm("lfence; mfence" ::: "memory");
	fillL1(&env, cacheCryptoEnvSize);
	//asm("lfence; mfence" ::: "memory");
	//fillL1(&env, cacheCryptoEnvSize);
	//asm("lfence; mfence" ::: "memory");
	//fillL1(&env, cacheCryptoEnvSize);
	
	// call stack switch function
	result=safeCall1(&env, decryptFunction, env.cachestack+CACHE_STACK_SIZE-8);
	//result=decryptFunction(&env);

	 

	// enable cache
	// calling invd
	asm volatile("invd\n":::"memory");
	//printk(KERN_INFO "invd execute\n");

	//exit no-fill mode
	smp_call_function(enaCache,NULL,1);
	//on_each_cpu(enaCache,NULL,1);  	

    
  	// restore interrupts
	local_irq_restore(flags);

	// enable preemption
	preempt_enable();

	printk(KERN_INFO "After: env.in is %s\n", env.in);
	printk(KERN_INFO "After: env.out is %s\n", env.out);
	//printk(KERN_INFO "After: IN canary is %s\n", env.in);
   
    	
    	//printk(KERN_ALERT "invd executed, Current CPU is %d\n", get_cpu());

    	return 0; 
}

 static void __exit deviceDriver_cleanup(void){
        printk(KERN_ALERT "Removing invd_driver.\n");
}

module_init(deviceDriver_init);
module_exit(deviceDriver_cleanup);

//*/


// for stackOverflow
/*
static struct CACHE_ENV{
    unsigned char in[128];
    unsigned char out[128];
}cacheEnv __attribute__((aligned(64)));

#define cacheEnvSize (sizeof(cacheEnv)/64)


//#define change "Hello"
unsigned char change[]="hello";


void disCache(void *p){
    __asm__ __volatile__ (
    "wbinvd\n"
    "mov %%cr0, %%rax\n\t"
    "or $(1<<30), %%eax\n\t"  // set bit CD
    "and $~(1<<29), %%eax\n\t" // clear bit NW
    "mov %%rax, %%cr0\n\t"
    "wbinvd\n"
    ::
    :"%rax"
    );

    printk(KERN_INFO "cpuid %d --> cache disable\n", smp_processor_id());

}


void enaCache(void *p){
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "and $~(1<<30), %%eax\n\t"
    "mov %%rax, %%cr0\n\t"
    ::
    :"%rax"
    );

    printk(KERN_INFO "cpuid %d --> cache enable\n", smp_processor_id());

}

int changeFixedValue (struct CACHE_ENV *env){
    int ret=1;
    memcpy(env->in, change, sizeof (change));
    memcpy(env->out, change,sizeof (change));

    //strcpy(env->in,change);
    //strcpy(env->out,change);
    printk(KERN_INFO "changeFixedValue: env.in fixed is %s\n", env->in);
    printk(KERN_INFO "changeFixedValue: env.out fixed is %s\n", env->out);



    return ret;
}



void fillCache(unsigned char *p, int num){
    int i;
    //unsigned char *buf = p;
    volatile unsigned char *buf=p;

    for(i=0;i<num;++i){

//        asm volatile(
//        "movq $0,(%0)\n"
//        :
//        :"r"(buf)
//        :
//        );

        //__builtin_prefetch(buf,1,1);
        __builtin_prefetch(buf,0,3);
        //*buf += 0;

        buf += 64;
        //*buf += 0;
    }
    printk(KERN_INFO "Inside fillCache, num is %d\n", num);
}


static int __init device_init(void){
    unsigned long flags;
    int result;

    struct CACHE_ENV env;

    //setup Fixed values
    char word[] ="0xabcd";
    memcpy(env.in, word, sizeof(word) );
    memcpy(env.out, word, sizeof (word));
    printk(KERN_INFO "env.in fixed is %s\n", env.in);
    printk(KERN_INFO "env.out fixed is %s\n", env.out);

    printk(KERN_INFO "Current CPU %d\n", smp_processor_id());

    // start atomic
    preempt_disable();
    smp_call_function(disCache,NULL,1);
    local_irq_save(flags);

    asm("lfence; mfence" ::: "memory");
    fillCache(&env, cacheEnvSize);

    result=changeFixedValue(&env);

    //asm volatile("invd\n":::);
    asm volatile("invd\n":::"memory");

    // exit atomic
    smp_call_function(enaCache,NULL,1);
    local_irq_restore(flags);
    preempt_enable();

    printk(KERN_INFO "After: env.in is %s\n", env.in);
    printk(KERN_INFO "After: env.out is %s\n", env.out);

    return 0;
}

static void __exit device_cleanup(void){
    printk(KERN_ALERT "Removing invd_driver.\n");
}

module_init(device_init);
module_exit(device_cleanup);
*/





