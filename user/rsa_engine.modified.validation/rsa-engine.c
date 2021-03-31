#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sched.h>
#include <openssl/opensslconf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <pthread.h>

// loading RSA helper function
#include "rsa/config.h"
#include "rsa/aes.h"
#include "rsa/bignum.h"
#include "rsa/rsa.h"
#include "rsa/key.h"
#include <immintrin.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <x86intrin.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/resource.h>


// dune lib
#include "libdune/dune.h"
#include "libdune/cpu-x86.h"


// Start: all the functions for RSA operation

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)

# define KEY_BUFFER_SIZE 1216 // this is for 1024-bit key. For different key length it will be different
#define KEY_LEN 128


//*********************  global variable for cache_crypto_env struct ************************//
#define CACHE_STACK_SIZE 9000 // most likely will be changed, depending on the size of the structure
#define CACHE_LINE_SIZE 64

// Assuming in my processor, my 4 cores are assigned into 2 separate cache set
// core 0,1 (cpu 0-3) into cache set 0
// core 2,3 (cpu 4-7) into cache set 1
// I need to find a dynamic way to figure out how many cache set I have but until then this is my configuration
#define SET_NUM 2
#define idcache 0
int ID;

/* set MTRR region*/
#include <asm/mtrr.h>
#include <sys/mman.h>

#define TRUE 1
#define FALSE 0
#define ERRSTRING strerror (errno)



// Secure CRYPTO structure
static struct CACHE_CRYPTO_ENV{
    unsigned char in[KEY_LEN]; // in --> encrypted msg
    unsigned char masterKey[128/8]; // for 128 bit master key
    //unsigned char out[(KEY_LEN + CACHE_LINE_SIZE -1)/(CACHE_LINE_SIZE * CACHE_LINE_SIZE)] __attribute__ ((aligned(CACHE_LINE_SIZE)));  // out--> decrypted plaintext.
    //unsigned char out[KEY_LEN];
    unsigned char out[KEY_LEN] __attribute__ ((aligned(CACHE_LINE_SIZE)));
    aes_context aes; // initialize AES
    rsa_context rsa; // initialize RSA
    unsigned char cachestack[CACHE_STACK_SIZE];
    unsigned long privateKeyID;
    unsigned char encryptPrivateKey[KEY_BUFFER_SIZE]; // encrypted private key
}cacheCryptoEnv __attribute__((aligned(64)));;

#define cacheCryptoEnvSize (sizeof(cacheCryptoEnv)/64)

__attribute__((always_inline)) inline void gl_clflush(const char *adrs){
    asm __volatile__ (
    "lfence\n"
    "mfence\n"
    "clflush 0(%0)  \n"
    :
    : "r" (adrs)
    :
    );
}

static unsigned int gl_clflush_cache_range(void *vaddr, unsigned int size){
    void *vend = vaddr + size - 1;

    //for (; vaddr < vend; vaddr += boot_cpu_data.x86_clflush_size)
    asm("lfence; mfence" ::: "memory");
    for (; vaddr < vend; vaddr += 64){
        gl_clflush(vaddr);
    }
    printf("Inside gl_clflush_cache_range\n");
    return 0;
}


// set high priority to this process
void set_realtime_priority() {
    int ret;

    // We'll operate on the currently running thread.
    pthread_t this_thread = pthread_self();

    struct sched_param params;

    // We'll set the priority to the maximum.
    params.sched_priority = sched_get_priority_max(SCHED_FIFO);
    printf("Trying to set thread realtime priority = %d\n", params.sched_priority );

    // Attempt to set thread real-time priority to the SCHED_FIFO policy
    ret = pthread_setschedparam(this_thread, SCHED_FIFO, &params);
    if (ret != 0) {
        // Print the error
        printf("Unsuccessful in setting thread realtime priority\n");
        return;
    }

    // Now verify the change in thread priority
    int policy = 0;
    ret = pthread_getschedparam(this_thread, &policy, &params);
    if (ret != 0) {
        printf("Couldn't retrieve real-time scheduling parameters\n");
        return;
    }

    // Check the correct policy was applied
    if(policy != SCHED_FIFO) {
        printf("Scheduling is NOT SCHED_FIFO!\n");
    } else {
        printf("SCHED_FIFO OK\n");
    }

    // Print thread scheduling priority
    printf("Thread priority is  = %d\n", params.sched_priority );
}


 // Check Interrupts status
 // Returns a true boolean value if irq are enabled for the CPU
static inline bool are_interrupts_enabled(){
    unsigned long flags;
    asm volatile ( "pushf\n\t"
                   "pop %0"
    : "=g"(flags) );
    return flags & (1 << 9);
}


// reading debug registers
static unsigned long long get_dr0(void){
    unsigned long long value;
    asm volatile("mov %%dr0,%0" : "=r" (value));
    return value;
}

static unsigned long long get_dr1(void){
    unsigned long long value;

    asm volatile("mov %%dr1,%0" : "=r" (value));
    return value;
}

static unsigned long long get_dr2(void){
    unsigned long long value;

    asm volatile("mov %%dr2,%0" : "=r" (value));
    return value;
}

static unsigned long long get_dr3(void){
    unsigned long long value;

    asm volatile("mov %%dr3,%0" : "=r" (value));
    return value;
}


// return CR0 current value
u64 get_cr0(void){
    u64 cr0;
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "mov %%eax, %0\n\t"
    : "=m" (cr0)
    : /* no input */
    : "%rax"
    );
    return cr0;
}


// clear bit 30 of cr0, Clearing all the CPU core except cpu1 from no-fill mode
// return 1 on success.
int clear_no_fill_mode(int idcacheNum){

    long nproc,i;
    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu

    switch (idcacheNum) {
        case 0:
            // disenable no-fill mode for cpu 0-7
            //printf("Inside clearing cache set 1\n");
            for (i = 0; i < nproc; i++) {
                // avoiding cpu1
                if(i!=ID){
                    cpu_set_t mask;
                    CPU_ZERO(&mask);
                    CPU_SET(i, &mask); // setting cpu affinity

                    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                        perror("sched_getaffinity");
                        assert(false);
                    }

                    //printf("\n\nExit no-fill mode[cpu%ld]: sched_getcpu() is %d\n",i, sched_getcpu());
                    //printf("Exit no-fill mode: before cr0 is = 0x%8.8X\n", get_cr0());

                    // clear bit 30
                    __asm__ __volatile__ (
                    "mov %%cr0, %%rax\n\t"
                    "and $~(1<<30), %%eax\n\t"
                    "mov %%rax, %%cr0\n\t"
                    ::
                    :"%rax"
                    );
                    //printf("After clear no-fill mode[cpu%ld] cr0 is =0x%8.8X\n\n", i, get_cr0());

                }
            }
            break;

        case 1:
            // enable no fill-mode for cpu 4-7
            printf("no-fill mode for cpu 4-7 is not setup yet.\n");
            break;

        default:
            printf("Error while setting no-fill mode\n");
            return 0;
    }
    return 1;
}

// set bit 30 of cr0.
// calling all available cpu's expept cpu 1. And set the cr0 bit 30 for no-fill mode.
// return 1 on success.
int set_no_fill_mode(int idcacheNum, int cpuID){

    long nproc,i;
    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu
    switch (idcacheNum) {
        case 0:
            // enable no-fill mode for cpu 0-3
            for (i = 0; i < nproc; i++) {

                // avoiding the first CPU where the program is currently loaded
                if(i!=cpuID){
                    cpu_set_t mask;
                    CPU_ZERO(&mask);
                    CPU_SET(i, &mask); // setting cpu affinity

                    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                        perror("sched_getaffinity");
                        assert(false);
                    }

                    //printf("\n\nSet no-fill mode[cpu%ld]: sched_getcpu() is %d\n", i, sched_getcpu());
                    //printf("Set no-fill mode: before cr0 is = 0x%8.8X\n", get_cr0());

                    // clear bit 30
                    __asm__ __volatile__ (
                        "wbinvd\n"
                        "mov %%cr0, %%rax\n\t"
                        "or $(1<<30), %%eax\n\t"
                        "mov %%rax, %%cr0\n\t"
                        "wbinvd\n"
                        ::
                        :"%rax"
                    );
                    //printf("Set no-fill mode[cpu%ld]: After cr0 is =0x%8.8X\n\n", i,get_cr0());
                }
            }
            // set CPU affinity to original CPU where the program is first loaded
            cpu_set_t mask;
            CPU_ZERO(&mask);
            CPU_SET(cpuID, &mask); // setting cpu affinity to CPU 1

            if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                perror("sched_getaffinity");
                assert(false);
            }
            printf("\n\n After putting all other CPU's to no fill mode, putting the rsa-engine to CPU %d\n\n", sched_getcpu());
            break;

        case 1:
            // enable no fill-mode for cpu 4-7
            printf("no-fill mode for cpu 4-7 is not setup yet.\n");
            break;

        default:
            printf("Error while setting no-fill mode\n");
            return 0;
    }

    return 1;
}

// check the if CPU1 memory is write back type
bool get_memory_type(void){

    // Change CPU affinity to CPU 1
    cpu_set_t mask;
    CPU_ZERO(&mask);

    // setting current thread affinity to cpu 1
    CPU_SET(1, &mask);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_setaffinity");
        assert(false);
    }

    // read CR0 and check for bit 29 & 30
    printf("Inside get_memory_type: current cpu is %d\n", sched_getcpu());
    printf("cr0 is = 0x%" PRIx64 "\n", get_cr0());

    // checking bit 29 & 30, if any of the two bit is set. Then memory is not write back type.
    if((get_cr0()&(1<<29)) || (get_cr0()&(1<<30))){
        printf("CR0 ==> either bit 29/30 is set\n");
        return false;
    }

    printf("Memory is write back type\n");
    return true;
}

void fillL1(struct CACHE_CRYPTO_ENV *p, int num){
    int i;
    //unsigned char *buf = p;
    volatile struct CACHE_CRYPTO_ENV *buf = p;
    for(i=0;i<num;++i){
/*
        asm volatile(
        "movq $0,(%0)\n"
        :
        :"r"(buf)
        :
        );
*/
        //asm("lfence; mfence" ::: "memory");
        __builtin_prefetch(buf,0,3);
        //*buf += 0;

        buf += 64;
    }
    printf("Inside fillL1, num is %d\n", num);
}

// clear all the variable
int clear_env(unsigned char *field_to_clear, int forEachCacheLine){
    unsigned char *address,*byte_value;
    for (int i = 0; i<forEachCacheLine ; i++) {
        asm("lfence; mfence" ::: "memory");
        address=((unsigned char *)field_to_clear);
        memset(address+i, 0, 1);
    }
    return 1;
}

// wbinvd
static inline void wbinvd(void){
    __asm__ __volatile__ ("wbinvd" : : : "memory");
}


/*
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

    //printk(KERN_INFO "cpuid %d --> cache disable\n", get_cpu());

}

void enaCache(void *p){
    __asm__ __volatile__ (
    "mov %%cr0, %%rax\n\t"
    "and $~(1<<30), %%eax\n\t"
    "mov %%rax, %%cr0\n\t"
    ::
    :"%rax"
    );

    //printk(KERN_INFO "cpuid %d --> cache enable\n", get_cpu());

}
*/

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

unsigned char randArray[cacheCryptoEnvSize];

int checkCache(unsigned char *p, int num){
    //unsigned long long r1,r2;
    uint64_t r1,r2;
    int avg;
    int total=0,i,r = 0;
    unsigned char *buf = p;
    for(i=0;i<num;++i){
        buf = p + randArray[i]*64;
        r1 = rdtsc();
        __asm__ __volatile__(
                "movl (%0),%%eax;\n"
				:
				:"r"(buf)
				: "%eax"
				);

        r2 = rdtsc();
        total += r2-r1;

    }
	avg = total/num;
    //printf("average cycle to access cache is %d\n", avg);
    return avg;
}


int decryptFunction (struct CACHE_CRYPTO_ENV *env){

    // wbinvd?
    //asm("lfence; mfence" ::: "memory");
    //wbinvd();

    // copy master key into env
    memcpy(env->masterKey, mkt, sizeof (mkt));

    //unsigned char *from=env->in;
    unsigned char *private_encrypt=env->encryptPrivateKey;

    int j,ret=0;
    size_t len;

    //unsigned char rsa_decrypted[1000];
    unsigned char msg_decrypted[sizeof (env->out)];
    unsigned char private_decrypt[KEY_BUFFER_SIZE]; // hold the decrypted key

    // context
    aes_context *aesContext =&(env->aes);
    rsa_context *rsaContext = &(env->rsa);

    // initialize
    aes_setkey_dec(aesContext,&(env->masterKey),AES_KEY_SIZE_BITS);
    rsa_init(rsaContext,RSA_PKCS_V15, 0);
    rsaContext->len=KEY_LEN;

    // read the keyId from env
    if (env->privateKeyID == NULL){
        //printf("Info for Which key to load is missing\n ");
        exit(0);
    }


    // performing decryption on encrypted keys, working
    for(j=0;j<KEY_BUFFER_SIZE/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&(env->aes),AES_DECRYPT, private_encrypt + AES_BLOCK_SIZE*j,private_decrypt+AES_BLOCK_SIZE*j);
    }
    //printf("After decryption Decrypted private key is --> \n %s \n", private_decrypt);

    size_t lenght=strlen(private_decrypt);
    int N= lenght-1209; // 1209 is the original buffer size for 1024-bit key
    //printf ("N is : %d\n", N);

    private_decrypt[lenght-N]='\0';
    //printf("length is %d\n", lenght);

    //printf("Final Decrypted private key is --> \n %s \n", private_decrypt);

    // tokenize key and read into rsa context
    const char s[3] = "= ";
    char *token;
    int k=0, size;

    // get the first token
    token = strtok(private_decrypt, s);

    // walk through other tokens
    while( token != NULL ) {
        size = strlen(token);

        if(k==1){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n\n", token);
            mpi_read_string(&rsaContext->N, 16, token);
            //memcpy(&rsaContext.N,token, size);
        }
        if(k==3){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n\n", token);
            mpi_read_string(&rsaContext->E, 16, token);
            //memcpy(&rsaContext.E,token, size);
        }
        if(k==5){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n\n", token);
            mpi_read_string(&rsaContext->D, 16, token);
            //memcpy(&rsaContext.D,token, size);
        }
        if(k==7){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n\n", token);
            mpi_read_string(&rsaContext->P, 16, token);
            //memcpy(&rsaContext.P,token, size);
        }
        if(k==9){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n\n", token);
            mpi_read_string(&rsaContext->Q, 16, token);
            //memcpy(&rsaContext.Q,token, size);
        }
        if(k==11){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n\n", token);
            mpi_read_string(&rsaContext->DP, 16, token);
            //memcpy(&rsaContext.DP,token, size);
        }
        if(k==13){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n\n", token);
            mpi_read_string(&rsaContext->DQ, 16, token);
            //memcpy(&rsaContext.DQ,token, size);

        }
        if(k==15){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            //printf("final token is %s\n", token);
            mpi_read_string(&rsaContext->QP, 16, token);
            //memcpy(&rsaContext.QP,token, size);
        }

       // size = strlen(token);
    //    printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );

        k=k+1;
        token = strtok(NULL, "= \n");
    }


    // check rsa public key
    if(rsa_check_pubkey(rsaContext)!=0){
        //printf("Reading public key error\n");
        exit(0);
    }

    if(rsa_check_privkey(rsaContext)!=0){
        //printf("Reading private key error\n");
        exit(0);
    }

    //printf("Public & private key reading success\n");

    // reading msg
    unsigned char *from=env->in;

    if( rsa_private(&(env->rsa),from, msg_decrypted) != 0 ) {
        printf( "Decryption failed! %d\n", rsa_private(&(env->rsa),from, msg_decrypted));
        exit(0);
    }else{
        //printf("Decrypted plaintext-----> %s\n",msg_decrypted );

        //should I use clflush here?
        //asm("lfence; mfence" ::: "memory");
        //gl_clflush_cache_range(env->out,KEY_LEN);


        //printf("After INVD:  average cycle to access cache is %d\n", checkCache(&env, cacheCryptoEnvSize));
        //printf("Current CPU [%d] cache is enabled : CR0 is: 0x%8.8X\n",sched_getcpu(), get_cr0());

        //asm("lfence; mfence" ::: "memory");
        //__asm__ __volatile__ ("invd\n":::"memory");

        // putting into structure to read in the main function
        asm("lfence; mfence" ::: "memory");
        memcpy(&(env->out), &msg_decrypted, sizeof (msg_decrypted));
        ret =1;
    }

    return ret;

}


// END: all the functions for RSA operation


// define stackswitch function
int stackswitch( void *env, int (*f)(struct CACHE_CRYPTO_ENV *), unsigned char *stackBottom){

    printf("******************   Inside stack_switch function ***************\n");

/*
    printf("\t\t\t\n\n");
    printf("******************   **************************** ***************\n");
    printf("******************   Inside stack_switch function ***************\n");
    printf("******************   **************************** ***************\n");
    printf("\t\t\t\n\n");
*/

    //printf("Inside stackswitch, msg is:  %s\n", ((struct CACHE_CRYPTO_ENV *)env)->in);


    //creating the original stack switch function
    asm volatile(

    //prologue
    "pushq %%rbp \t\n"
    "movq %%rsp, %%rbp \t\n" // can't modify rbp without clobber register.


    // create space for stackswitch function parameter. rax now point to the stack bottom
    // ok, So, 16(%%rbp) --> point to the *stackbottom. When we move 16(%%rbp)--> rax, rax is now point to stack bottom.
    "movq 16(%%rbp), %%rax\t\n"

    //save system rbp on the new stack.
    // creating new stack. Setting rbp.
    "movq %%rbp, (%%rax)\t\n"

    //save system rsp on the new stack
    // setting rsp to the new stack
    "movq %%rbp, -8(%%rax)\t\n"

    //rbx now point to the old rbp
    // rbx --> point to the original stack rbp
    "movq %%rbp, %%rbx\t\n"

    // Create new stack frame
    "movq %%rax, %%rbp\t\n"
    "movq %%rax, %%rsp\t\n"

    // pointing to rsp, from previous line, movq %%rbp, -8(%%rax)
    //"sub $8, %%rsp\t\n"
    "subq $40, %%rsp\t\n"

    // create parameter for decryption function
    //"pushq 32(%%rbx)\t\n"
    "movq 32(%%rbx), %%rdx\t\n"
    "movq %%rdx, %%rdi\t\n"

    //call wbinvd, only for validation
    "lfence\n"
    "mfence\n"
    "wbinvd\n"

    //call decryption function
    "call 24(%%rbx)\t\n"

    // returning to the original stack
    "movq %%rbp, %%rbx\t\n"
    "movq (%%rbx), %%rbp\t\n"
    "mov -8(%%rbx), %%rsp\t\n"

    "leave\t\n"
    //"ret \t\n"

    :
    :
    :"rax","rbx","rbp"
    );

    // cleaning the cacheStack buffer
    struct CACHE_CRYPTO_ENV *p =env;


    // clearing the full env
    //memset(&p, 0, sizeof (p));
    clear_env(p->masterKey, sizeof (p->masterKey));
    clear_env(p->cachestack, sizeof (p->cachestack));
    clear_env(p->encryptPrivateKey, sizeof (p->encryptPrivateKey));


    //INVD
    asm("lfence; mfence" ::: "memory");
    __asm__ __volatile__ ("invd\n":::"memory");

    //exit no-fill mode
    clear_no_fill_mode(idcache);

    // restore Interrupts
    asm volatile("sti": : :"memory");
/*
    printf("\t\t\t\n\n");
    printf("******************   **************** ***************\n");
    printf("******************   Stack Switch end ***************\n");
    printf("******************   **************** ***************\n");
    printf("\t\t\t\n\n");
*/
    printf("******************   Stack Switch end ***************\n");
    return 1;
}




/* Declared already in ossl_typ.h */
/* typedef struct rsa_st RSA; */
/* typedef struct rsa_meth_st RSA_METHOD; */


struct rsa_meth_st {

    const char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

    /* Can be null */

    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);

    /* Can be null */

    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

    /* called at new */

    int (*init) (RSA *rsa);

    /* called at free */

    int (*finish) (RSA *rsa);

    /* RSA_METHOD_FLAG_* things */

    int flags;

    /* may be needed! */

    char *app_data;

    /*

     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
     * *NOT* be used RSA_sign(), RSA_verify() should be used instead. Note:
     * for backwards compatibility this functionality is only enabled if the
     * RSA_FLAG_SIGN_VER option is set in 'flags'.

     */

    int (*rsa_sign) (int type,

                     const unsigned char *m, unsigned int m_length,

                     unsigned char *sigret, unsigned int *siglen,

                     const RSA *rsa);

    int (*rsa_verify) (int dtype, const unsigned char *m,

                       unsigned int m_length, const unsigned char *sigbuf,

                       unsigned int siglen, const RSA *rsa);

    /*

     * If this callback is NULL, the builtin software RSA key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */

    int (*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

};


// RSA Public key operation
static int eng_rsa_pub_enc (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding){

    printf ("Engine is encrypting using pub key \n");

    // getting the lenght of msg.txt
    int msg_len= strlen(from);
    printf("Plain text is is ---- %s\n", from);


    unsigned char rsa_plaintext[msg_len];
    unsigned char rsa_ciphertext[KEY_LEN];

    rsa_context rsa_polar;

    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
    rsa_polar.len = KEY_LEN;
/*
    // reading public keys from file
    unsigned char * buffer = 0;
    long length;
    FILE * fp = fopen ("rsa_pub.txt", "rb");

    if (fp)
    {
        fseek (fp, 0, SEEK_END);
        length = ftell (fp);
        fseek (fp, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer)
        {
            fread (buffer, 1, length, fp);
        }
        fclose (fp);
    }

    // print the original plaintext private key before encrypted
    printf("Key in buffer is \n %s\n", buffer);
    printf("main: Size of Buffer is %d\n", strlen(buffer));

    // tokenize key and read into rsa context
    const char s[3] = "= ";
    char *token;
    int k=0, size;

    // get the first token
    token = strtok(buffer, s);
    printf( " first token %s\n", token );

    // walk through other tokens
    while( token != NULL ) {
        size = strlen(token);

        if(k==1){
            printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            printf("final token is %s\n\n", token);
            mpi_read_string(&rsa_polar.N, 16, token);
            //memcpy(&rsaContext.N,token, size);
        }
        if(k==3){
            //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
            token[size-1]='\0';
            printf("final token is %s\n\n", token);
            mpi_read_string(&rsa_polar.E, 16, token);
            //memcpy(&rsaContext.E,token, size);
        }
        // size = strlen(token);
        //    printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );

        k=k+1;
        token = strtok(NULL, "= \n");
    }
*/


    // setting RSA public key
    mpi_read_string( &rsa_polar.N , 16, RSA_N  );
    mpi_read_string( &rsa_polar.E , 16, RSA_E  );

    if( rsa_check_pubkey(&rsa_polar) != 0) {
        printf( "Public key error! \n" );
        exit(0);
    }

    // copy from msg.txt to rsa_plaintext
    memcpy( rsa_plaintext, from, msg_len);

    //if( rsa_pkcs1_encrypt( &rsa_polar, &myrand, NULL, RSA_PUBLIC, msg_len, rsa_plaintext, rsa_ciphertext ) != 0 ) {
    if( rsa_public(&rsa_polar, rsa_plaintext, rsa_ciphertext)!=0) {
        printf( "Encryption failed! \n" );
        exit(0);
    }else {
        printf("RSA Encryption Successful\n");
        FILE *fp;
        //fp = fopen("to", "w+");
        fp = fopen("msg.enc", "w+");
        fprintf(fp, "%s", rsa_ciphertext);
        fclose(fp);
    }

}



static int eng_rsa_pub_dec (int flen, const unsigned char *from,  unsigned char *to, RSA * rsa, int padding){

    printf ("Engine is decrypting using pub key \n");

    //RSA_public_decrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);

}



static int eng_rsa_priv_enc (int flen, const unsigned char *from, unsigned char *to,

                             RSA * rsa, int padding __attribute__ ((unused)))

{

    printf ("Engine is encrypting using priv key \n");

    //RSA_private_encrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);

}



//static int eng_rsa_priv_dec (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){
static int eng_rsa_priv_dec (int flen, unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    printf ("Engine is decrypting using priv key \n");
    int j;

    // read plaintext private keys from file. Private keys will be generated using executable simple.example/rsa-keygen
    // reading private key in a buffer
    unsigned char * buffer = 0;
    long length;
    FILE * fp = fopen ("rsa_priv.txt", "rb");

    if (fp)
    {
        fseek (fp, 0, SEEK_END);
        length = ftell (fp);
        fseek (fp, 0, SEEK_SET);
        buffer = malloc (length);
        if (buffer)
        {
            fread (buffer, 1, length, fp);
        }
        fclose (fp);
    }

    //call a function for padding the buffer to make it multiple of 16
    if(strlen(buffer)%AES_BLOCK_SIZE == 0){
        printf("No padding needed\n");
    }else{
        int k=AES_BLOCK_SIZE-(strlen(buffer)%AES_BLOCK_SIZE);
        //printf("padding needed: %d\n", k );

        char ch[k];
        int i;
        for (i=0;i<k;i++){
            ch[i]='0';
        }
        strncat(buffer,&ch,k);

        //printf("After padding: Wish to see 0 here in output, strlen(buffer)/AES_BLOCK_SIZE is  %d\n", strlen(buffer)%AES_BLOCK_SIZE);
        //printf("Padded buffer is \n %s\n", buffer);
        //printf("Padded buffer size \n %d\n", strlen(buffer));
    }

    unsigned char private_encrypt[KEY_BUFFER_SIZE];
    //unsigned char private_decrypt[KEY_BUFFER_SIZE];

    // initialize aes context &
    // following function will generate all the AES round keys for encryption
    aes_context aes;
    aes_setkey_enc(&aes,mkt,AES_KEY_SIZE_BITS);

    for(j=0;j<strlen(buffer)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, buffer + AES_BLOCK_SIZE*j,private_encrypt+AES_BLOCK_SIZE*j);
        //printf("j= %d Encrypted private key is -->\n %s \n", j, private_encrypt);
    }
    printf("Encrypted private key is -->\n %s \n", private_encrypt);


    // writing encrypted keys into file
    // *fp is declared previously from reading plain keys into buffer
    //FILE *fp;
    fp = fopen("private.enc", "w+");
    fprintf(fp, "%s", private_encrypt);
    fclose(fp);

    // Till now, Private key encryption complete

// ************************************ Start Calling decryption function here ******************************//


/*************************************** Start: Disabling Dune ***********************/
    // set current process with high priority
    setpriority(PRIO_PROCESS, 0, -20);

    volatile int ret, result;
    int cpuId=sched_getcpu();
    ID=cpuId;
    printf(" First: Before dune current cpu is  = %d\n", cpuId);

    struct CACHE_CRYPTO_ENV env;


    // check cache access cycle
    //printf("Before disable average cycle to access cache is %d\n", checkCache(&env, cacheCryptoEnvSize));

    // DUNE starts
    printf("Dune: not running dune yet\n");
    ret = dune_init_and_enter();
    if (ret) {
        printf("failed to initialize dune\n");
        return ret;
    }
    printf("Dune: now printing from dune mode\n");

/*
    // check if cpu 1 has write back memory type.
    // Write back memory : CR0 ==> bit 29 & 30 should be 0
    // for write back memory type, get_memory_type() should return true

    if (!get_memory_type()){
        printf("Memory is not write back type");
        exit(0);
    }
*/


/*
    // Change CPU affinity to CPU 1, Isolated cpu
    cpu_set_t mask;
    CPU_ZERO(&mask);

    // setting current thread affinity to cpu 1
    CPU_SET(1, &mask);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_setaffinity");
        assert(false);
    }

    int cpu= sched_getcpu();
    printf("UseSpace: Current CPU is %d \n", cpu);
    printf("  ***************** CPU 1 is set for operation **************** \n");
*/

    // Even though following line print current cpu is 123 (I don't know why).
    // cat /proc/sched_debug | grep openssl
    // shows openssl is running on CPU 1. when calling do_someWork() function
    // Look for term cpu-hotplug
    // In our case, We always run our engine in core 1. Therefore, other core in the same cache set will not
    // be able to run our engine


/*************************************** Ends: Disabling Dune ***********************/


    // Giving current process the high priority
    //set_realtime_priority();


    //fixed canary word
    char word[] ="0xaaaa";

    // setting word canary
    memcpy(env.masterKey, word, sizeof(word) );
    memcpy(env.cachestack, word, sizeof (word));
    printf("master key canary is %s\n", env.masterKey);
    printf("cacheStack canary is %s\n", env.cachestack);
    //exit(0);

    //calling wbinvd & prevent memory inconsistency
    asm("lfence; mfence" ::: "memory");
    asm volatile("wbinvd":::"memory");

    // Disable interrupt
    asm volatile("cli": : :"memory");

/*
    // Check Interrupt status : Returns a true boolean value if irq are enabled for the CPU
    printf("Interrupt enable?:\t");
    printf(are_interrupts_enabled() ? "Yes\n" : "No\n");
*/
    //printf("After disable cache:  average cycle to access cache is %d\n", checkCache(&env, cacheCryptoEnvSize));
    //printf("Cache Disable from kernel : CR0 is: 0x%8.8X\n", get_cr0());

    //asm("lfence; mfence" ::: "memory");
    //asm volatile("wbinvd":::"memory");

    // Local: set_no_fill_mode() return 1 on success
    if(!set_no_fill_mode(idcache,cpuId)){
        printf("Setting Other CPUs to no-fill mode failed\n");
        exit(0);
    }

    // to prevent memory inconsistency and clear CAHE
    asm("lfence; mfence" ::: "memory");
    asm volatile("wbinvd":::"memory");


    // fillup L1d cache
    //asm("lfence; mfence" ::: "memory");
    fillL1(&env, cacheCryptoEnvSize);

    // setting env.privateKeyID =1 to read encrypted keys from "private.enc"
    // this is where we select the private keyID to load the corresponding encrypted key file
    // for now, privateKeyID =1 means select private.enc
    env.privateKeyID=1;

    // reading encrypted msg from msg.enc into secure env
    memcpy(env.in, (unsigned char *)from, KEY_LEN);
    memcpy(env.encryptPrivateKey, private_encrypt, sizeof(private_encrypt));

    // Creating new stack in cache for private key computation
    asm("lfence; mfence" ::: "memory");
    result=stackswitch(&env, decryptFunction, env.cachestack+CACHE_STACK_SIZE-8);


/*
    // run INVD here?
    printf("Running invd\n");
    asm("lfence; mfence" ::: "memory");
    asm volatile("invd":::"memory");
    printf("Running invd: done\n");

    //exit no-fill mode
    clear_no_fill_mode(idcache);

    // restore Interrupts
    asm volatile("sti": : :"memory");
*/

    printf("after operation, result is %d\n",result);
    printf("after operation, Inside main function\n");
    printf("Decrypted plaintext-----> %s\n",env.out );
    printf("master key is %s\n", env.masterKey);
    printf("cacheStack is %s\n", env.cachestack);

    // restore Interrupts
    //asm volatile("sti": : :"memory");

    //check interrupt
    printf("Interrupt enable?:\t");
    printf(are_interrupts_enabled() ? "Yes\n" : "No\n");



    // Without it code cause segfault. Will look at it later
    exit(0);

}



/* Constants used when creating the ENGINE */

static const char *engine_rsa_id = "rsa-engine-new";
static const char *engine_rsa_name = "engine for testing 1";

struct rsa_meth_st suse_rsa =
        {
                "RSA engine for demo",
                eng_rsa_pub_enc,
                eng_rsa_pub_dec,
                eng_rsa_priv_enc,
                eng_rsa_priv_dec,
                NULL,
                NULL,
                NULL,
                NULL,
                RSA_FLAG_CACHE_PUBLIC | RSA_FLAG_CACHE_PRIVATE,
                NULL,
                NULL,
                NULL,
                NULL
        };



static int bind (ENGINE * e, const char *id)

{

    printf ("%s\n", id);



    if (!ENGINE_set_id (e, engine_rsa_id) ||

        !ENGINE_set_name (e, engine_rsa_name) ||

        !ENGINE_set_RSA (e, &suse_rsa))

        return 0;



    return 1;

}



IMPLEMENT_DYNAMIC_BIND_FN (bind)

IMPLEMENT_DYNAMIC_CHECK_FN ()
