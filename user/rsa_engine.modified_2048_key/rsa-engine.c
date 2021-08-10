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
#include <signal.h>

// loading RSA helper function
//#include "rsa/cacheCryptoMain.h"
#include "rsa/config.h"
#include "rsa/aes.h"
#include "rsa/bignum.h"
#include "rsa/rsa.h"
#include "rsa/key.h"
//#include "rsa/memory_buffer_alloc.h"
//#include "rsa/memory.h"
//#include "rsa/platform.h"
//#include "rsa/threading.h"
#include <immintrin.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>

//#include <pthread.h>
#include <time.h>

// dune lib
#include "libdune/dune.h"
#include "libdune/cpu-x86.h"

// Start: all the functions for RSA operation

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)


// reading from files, Ideally below function
// global
//unsigned char private_encrypt[KEY_BUFFER_SIZE];
//unsigned char private_decrypt[KEY_BUFFER_SIZE];


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

// clear bit 30 of cr0
// Clearing all the CPU core except cpu1 from no-fill mode
// return 1 on success.
int clear_no_fill_mode(int idcacheNum){

    long nproc,i;
    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu

    switch (idcacheNum) {
        case 0:
            // enable no-fill mode for cpu 0-3
            printf("Inside clearing cache set 1\n");
            for (i = 0; i <= 3; i++) {
                // avoiding cpu1
                if(i!=1){
                    cpu_set_t mask;
                    CPU_ZERO(&mask);
                    CPU_SET(i, &mask); // setting cpu affinity

                    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                        perror("sched_getaffinity");
                        assert(false);
                    }

                    printf("\n\nExit no-fill mode[cpu%ld]: sched_getcpu() is %d\n",i, sched_getcpu());
                    printf("Exit no-fill mode: before cr0 is = 0x%8.8X\n", get_cr0());

                    // clear bit 30
                    __asm__ __volatile__ (
                    "mov %%cr0, %%rax\n\t"
                    "and $~(1<<30), %%eax\n\t"
                    "mov %%rax, %%cr0\n\t"
                    ::
                    :"%rax"
                    );
                    printf("After clear no-fill mode[cpu%ld] cr0 is =0x%8.8X\n\n", i, get_cr0());

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
int set_no_fill_mode(int idcacheNum){

    long nproc,i;
    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu

    switch (idcacheNum) {
        case 0:
            // enable no-fill mode for cpu 0-3
            printf("Inside cache set 1\n");
            for (i = 0; i <= 3; i++) {

                // avoiding cpu1
                if(i!=1){
                    cpu_set_t mask;
                    CPU_ZERO(&mask);
                    CPU_SET(i, &mask); // setting cpu affinity

                    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                        perror("sched_getaffinity");
                        assert(false);
                    }

                    printf("\n\nSet no-fill mode[cpu%ld]: sched_getcpu() is %d\n", i, sched_getcpu());
                    printf("Set no-fill mode: before cr0 is = 0x%8.8X\n", get_cr0());

                    // clear bit 30
                    __asm__ __volatile__ (
                    "mov %%cr0, %%rax\n\t"
                    "or $(1<<30), %%eax\n\t"
                    "mov %%rax, %%cr0\n\t"
                    ::
                    :"%rax"
                    );
                    printf("Set no-fill mode[cpu%ld]: After cr0 is =0x%8.8X\n\n", i,get_cr0());

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
    //printf("Inside fillL1, num is %d\n", num);
}

//threading_mutex_t lock;
int decryptFunction (struct CACHE_CRYPTO_ENV *env){

    //printf("Decryption: Interrupt enable?:\t");
    //printf(are_interrupts_enabled() ? "Yes\n\n\n\n" : "No\n\n\n\n\n");

    //pthread_mutex_lock(&lock);

    // allocating buffer
    //unsigned char alloc_buf[10000];
    //memory_buffer_alloc_init( &alloc_buf, sizeof(alloc_buf) );



    unsigned char *from=env->in;
    unsigned char *private_encrypt=env->encryptPrivateKey;


    int j,ret=0;
    size_t len;

    unsigned char msg_decrypted[sizeof (env->out)];
    unsigned char private_decrypt[KEY_BUFFER_SIZE]; // hold the decrypted key

    // context
    aes_context *aesContext =&(env->aes);
    rsa_context *rsaContext = &(env->rsa);

    // initialize: old implementation, works!!
    aes_setkey_dec(aesContext,mkt,AES_KEY_SIZE_BITS);
    rsa_init(rsaContext,RSA_PKCS_V15, 0);
    rsaContext->len=KEY_LEN;


    // read the keyId from env
    if (env->privateKeyID == NULL){
        printf("Info for Which key to load is missing\n ");
        exit(0);
    }


    // performing decryption on encrypted keys, working
    for(j=0;j<KEY_BUFFER_SIZE/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&(env->aes),AES_DECRYPT, private_encrypt + AES_BLOCK_SIZE*j,private_decrypt+AES_BLOCK_SIZE*j);
    }
    //printf("After decryption Decrypted private key is --> \n %s \n", private_decrypt);

    size_t lenght=strlen(private_decrypt);
    //printf("Size of total decrypted_with buffer is %d\n",sizeof(private_decrypt));

    int N= lenght-2361; // 2361 is the original buffer size for 2048-bit key
    //printf ("N is : %d\n", N);

    private_decrypt[lenght-N]='\0';
    //printf("length is %d\n", lenght);

    //printf("Final Decrypted private key is --> \n %s \n", private_decrypt);

    //exit(0);

    /*************** Original Key decryption ends here  ***************/

    // Following code is the replace of the previous block. Also works

    // tokenize key and read into rsa context
    const char s[3] = "= ";
    char *token;
    int k=0, size;

    unsigned char *rest=private_decrypt;

    // get the first token
    //token = strtok(private_decrypt, s);
    token = strtok_r(rest, s, &rest);

    // walk through other tokens
    while( token != NULL ) {
        size = strlen(token);

        switch (k) {
            case 1:
                token[size-1]='\0';
                mpi_read_string(&rsaContext->N, 16, token);
                break;

            case 3:
                token[size-1]='\0';
                mpi_read_string(&rsaContext->E, 16, token);
                break;

            case 5:
                token[size-1]='\0';
                mpi_read_string(&rsaContext->D, 16, token);
                break;

            case 7:
                token[size-1]='\0';
                mpi_read_string(&rsaContext->P, 16, token);
                break;

            case 9:
                token[size-1]='\0';
                mpi_read_string(&rsaContext->Q, 16, token);
                break;

            case 11:
                token[size-1]='\0';
                mpi_read_string(&rsaContext->DP, 16, token);
                break;

            case 13:
                token[size-1]='\0';
                mpi_read_string(&rsaContext->DQ, 16, token);
                break;

            case 15:
                //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );
                token[size-1]='\0';
                //printf("final token is %s\n", token);
                mpi_read_string(&rsaContext->QP, 16, token);
                //memcpy(&rsaContext.QP,token, size);
                break;
        }
        k=k+1;
        //token = strtok(NULL, "= \n");
        token = strtok_r(rest, "= \n", &rest);
    }
//*/


// commenting for performance measurement
/*
    // check rsa public key
    if(rsa_check_pubkey(rsaContext)!=0){
        printf("Reading public key error\n");
        exit(0);
    }

    if(rsa_check_privkey(rsaContext)!=0){
        printf("Reading private key error\n");
        exit(0);
    }

    printf("Public & private key reading success\n");
*/


    if( rsa_private(&(env->rsa),from, msg_decrypted) != 0 ) {
        printf( "Decryption failed! %d\n", rsa_private(&(env->rsa),from, msg_decrypted));
        exit(0);
    }else{
        //printf("Decrypted plaintext-----> %s\n",msg_decrypted );

        // putting into structure to read in the main function
        memcpy(&(env->out), &msg_decrypted, sizeof (msg_decrypted));
        ret =1;
    }
    //polarssl_mutex_unlock(&lock);

    return ret;
}
// END: all the functions for RSA operation


// define stackswitch function
int stackswitch( void *env, int (*f)(struct CACHE_CRYPTO_ENV *), unsigned char *stackBottom){

    printf("\t\t\t\n\n");
//    printf("******************   **************************** ***************\n");
//    printf("******************   Inside stack_switch function ***************\n");
//    printf("******************   **************************** ***************\n");
//    printf("\t\t\t\n\n");


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


//    printf("\t\t\t\n\n");
//    printf("******************   **************** ***************\n");
//    printf("******************   Stack Switch end ***************\n");
//    printf("******************   **************** ***************\n");
//    printf("\t\t\t\n\n");

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



static int eng_rsa_priv_enc (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    printf ("Engine is encrypting using priv key \n");
    //RSA_private_encrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);
}


// thread function
void thread_function(void * input){

    // set process priority to the highest
    setpriority(PRIO_PROCESS, 0, -20);

    struct arg_thread *argThread=(struct arg_thread *)input;
    printf("%d thread created\n",argThread->thread_id);


    unsigned char private_encrypt[KEY_BUFFER_SIZE];
    int total_dec=1000;

    // start dune again
    if(dune_enter()){
        printf("Coundn't start dune\n");
        exit(0);
    }

    printf("Thread created \n");


    // reading the private.enc from file
    FILE * fp2 = fopen ("private.enc", "rb");
    int size=KEY_BUFFER_SIZE;
    if(fp2){
        while(size>0){
            fread(private_encrypt,1,sizeof (private_encrypt),fp2);
            size=size-1;
        }
    }
    fclose(fp2);


    // Disable interrupt
    asm volatile("cli": : :"memory");

    // Check Interrupt status : Returns a true boolean value if irq are enabled for the CPU
    //printf("Interrupt enable?:\t");
    //printf(are_interrupts_enabled() ? "Yes\n" : "No\n");

    // initializing a env structure
    struct CACHE_CRYPTO_ENV env;
    
    //set thread_no
    env.thread_no=argThread->thread_id;


    // fillup L1d cache
    fillL1(&env, cacheCryptoEnvSize);

    // setting env.privateKeyID =1 to read encrypted keys from "private.enc". This is where we select the private keyID to load the corresponding encrypted key file
    // for now, privateKeyID =1 means select private.enc
    env.privateKeyID=1;

    // reading encrypted msg from msg.enc into secure env
    memcpy(env.in, argThread->from, KEY_LEN);
    memcpy(env.encryptPrivateKey, private_encrypt, sizeof(private_encrypt));

    while (total_dec>0) {
        // Creating new stack in cache for private key computation
        stackswitch(&env, decryptFunction, env.cachestack + CACHE_STACK_SIZE - 8);
        //decryptFunction(&env);
        printf("%d Decrypted plaintext-----> %s\n",total_dec, env.out);
        total_dec--;
    }



    // restore Interrupts
    asm volatile("sti": : :"memory");
    //printf("Interrupt enable?:\t");
    //printf(are_interrupts_enabled() ? "Yes\n" : "No\n");
    //printf("Test thread number %d Finish\n",argThread->thread_count);



}




static int eng_rsa_priv_dec (int flen, unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){
    printf ("Engine is decrypting using private key \n");

    // copy engine argument to a predefine structure for using inside a thread function
    struct arg_thread argThread[NUM_OF_THREAD];


    // DUNE starts
    volatile int ret;
    ret = dune_init_and_enter();
    if (ret) {
        printf("failed to initialize dune\n");
        return ret;
    }

    // Initialize thread: Start clock to measure the time
    int i;
    clock_t t;

    // total number of thread
    pthread_t ths[NUM_OF_THREAD];

    // start time count
    time_t start = time(NULL);

    for (i = 0; i < NUM_OF_THREAD; i++) {
        argThread[i].from=from;
        argThread[i].to=from;
        argThread[i].thread_id=i;
        pthread_create(&ths[i], NULL, thread_function, (void *)&argThread[i]);
    }

    for (i = 0; i < NUM_OF_THREAD; i++) {
        void* res;
        pthread_join(ths[i], &res);
    }

    // measure end time
    printf("Time %.2f\n", (double)(time(NULL) - start));

    //printf("Here value is %d\n",Here);


    // exit dune
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
