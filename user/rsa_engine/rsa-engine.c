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

// loading RSA helper function
#include "rsa/cacheCryptoMain.h"
#include "rsa/config.h"
#include "rsa/aes.h"
#include "rsa/bignum.h"
#include "rsa/rsa.h"
#include <immintrin.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

// dune lib
#include "libdune/dune.h"
#include "libdune/cpu-x86.h"


// test function to check running CPU number.
// cat /proc/sched_debug | less
// should show the running process (openssl, in this case) into CPU 1
void do_someWork(int a ,int b){

    volatile int c;
    printf("Inside do_somework(), current CPU set, current cpu is  = %d\n", sched_getcpu());
    for(int i=0;i<100000;i++){
        c =c+a+b;
        //printf("C is %d\n",c);
        sleep(1);
        //printf("Process ID is %d\n",getpid());
    }
}

// test function for multi core affinity
int test_affinity_multipleCore(void){

    cpu_set_t mask;
    long nproc,i;
    //int i;

    nproc = sysconf(_SC_NPROCESSORS_ONLN); // return number of total available cpu

    for (i = 0; i < nproc; i++) {

        // avoiding cpu1
        if(i!=1){
            CPU_ZERO(&mask);
            CPU_SET(i, &mask); // setting cpu affinity

            if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
                perror("sched_getaffinity");
                assert(false);
            }
            printf("\nCurrent i=%ld and sched_getcpu() is %d\n", i,sched_getcpu());
        }
    }

    return 1;
}


// affinity single core
int test_affinity_single(void){

    cpu_set_t mask;
    long nproc,i;

    CPU_ZERO(&mask);
    CPU_SET(1, &mask);  // 1 is the target cpu number
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) { // 0 means current process
        perror("sched_setaffinity");
        assert(false);
    }
    printf("\n\nSingle core: Current sched_getcpu() is %d\n",sched_getcpu());

    return 1;
}

// test current cpu online
void print_affinity() {
    cpu_set_t mask;
    long nproc, i;

    if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_getaffinity");
        assert(false);
    }
    nproc = sysconf(_SC_NPROCESSORS_ONLN);
    printf("sched_getaffinity = ");
    for (i = 0; i < nproc; i++) {
        printf("%d ", CPU_ISSET(i, &mask));
    }
    printf("\n");
}



// Start: all the functions for RSA operation

/* this is the AES master key, in this project, it is supposed to be derived from the debug registers. */
unsigned char mkt[16] = { \
0x52,0x47,0x99,0x32, \
0x4f,0x20,0x6d,0xf0, \
0x1f,0x5b,0x30,0x31, \
0x0c,0xe3,0x50,0x1a \
};

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)

# define KEY_BUFFER_SIZE 992 // this is for 1024-bit key. For different key length it will be different
#define KEY_LEN 128


//*********************  global variable for cache_crypto_env struct ************************//
#define CACHE_STACK_SIZE 10000 // most likely will be changed, depending on the size of the structure

// Assuming in my processor, my 4 cores are assigned into 2 separate cache set
// core 0,1 (cpu 0-3) into cache set 0
// core 2,3 (cpu 4-7) into cache set 1
// I need to find a dynamic way to figure out how many cache set I have but until then this is my configuration
#define SET_NUM 2


// Secure CRYPTO structure
struct CACHE_CRYPTO_ENV{
    unsigned char masterKey[128/8]; // for 128 bit master key
    aes_context aes; // initialize AES
    rsa_context rsa; // initialize RSA
    unsigned char cachestack[CACHE_STACK_SIZE];
    //unsigned long privateKeyID;
    unsigned long encryptPrivateKey;
    unsigned char in[KEY_BUFFER_SIZE]; // KEY_BUFFER_SIZE is the total size of the encrypted key
                                       // in --> encrypted RSA privateKey

    unsigned char out[KEY_BUFFER_SIZE]; // Need to remove those extra padding to get back the original key
                                        // out--> plaintext RSA privateKey

};

// Following structure contain the parameter for decryption().
struct ENV{
    unsigned char *encMsg[1000];
    unsigned char *encPrivateKey[KEY_BUFFER_SIZE];
    //struct CACHE_CRYPTO_ENV structCacheCryptoEnv;
}env;

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
//Clearing all the CPU core except cpu1 from no-fill mode
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


    //for (i = 0; i < nproc; i++) {

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


int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}

int decryptFunction (unsigned char *from, unsigned char *private_encrypt){

    // Need to populate cacheCrptoEnv here?


    printf("Inside Decryption function, current CPU set, current cpu is  = %d\n", sched_getcpu());
    //do_someWork(1,2);
    //printf("decryptFunction\n");
    int j, result=-1;
    //int N=7;
    aes_context aes;
    rsa_context rsa_polar;

    //rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );


//    int len_cipher=strlen(from);
//    unsigned char decrypt_plaintext[len_cipher]; // len cipher is causing failure, need to find a size in Byte

    unsigned char private_decrypt[KEY_BUFFER_SIZE];

    // performing decryption on encrypted keys, working
    aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS);
    for(j=0;j<KEY_BUFFER_SIZE/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, private_encrypt + AES_BLOCK_SIZE*j,private_decrypt+AES_BLOCK_SIZE*j);
    }

    // For 1024-bit key, total buffer size is 986 -fixed.
    // After aes-decryption, total decryption lenght will be different
    // But need to make private_decrypt[] size same as 986
    // So, I will choose N, dynamically.
    // N = strlen(private_decrypt) - 986

    // for 1024 bit keys, removing the extra 10 padding
    //int N=11;
    //int N=15;
    int len=strlen(private_decrypt);
    int N= len-986; // 986 is the buffer size for 1024-bit key
    //printf ("N is : %d\n", N);


    private_decrypt[len-N]='\0';
    //printf("len is %d\n", len);

    //printf("Decrypted private key is --> \n %s \n", private_decrypt);


    // Printing here shows extra something after the key


    //reading private.pem and perform decryption
    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );


    int len_cipher=strlen(from);

    //unsigned char decrypt_plaintext[len_cipher];
    /*
     *
     * Need to fix this
     *
     * */
    unsigned char decrypt_plaintext[1000];


    // read decrypted key from buffer into rsa_context
    if (x509parse_key(&rsa_polar,private_decrypt,strlen(private_decrypt), "1234",4)!=0){
        //printf("Error code\n");
        exit(0);
    }else{
        //printf("Reading decrypted private key from buffer into rsa_context is success\n");
    }



    if( rsa_check_pubkey(  &rsa_polar ) != 0 ||rsa_check_privkey( &rsa_polar ) != 0 ) {
        //printf( "decryption : Public/Private key error! \n" );
        exit(0);
    }else{
        //printf("decryption :Key reading success\n");
    }

    if( rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ) != 0 ) {
        //printf( "Decryption failed! \n" );
        //printf("Error code,  %d\n",rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ));
        exit(0);
    }else {
        //printf("decryption: Decrypted plaintext-----> %s\n", decrypt_plaintext);
    }

    return 1;
    //exit(0);

}



// END: all the functions for RSA operation

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

    /*
     * Following code segment is working.
     * for encrypt a file with public.pem keys
     * */



    printf ("Engine is encrypting using public.pem key \n");
    //RSA_public_encrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);

    // getting the lenght of msg.txt
    int msg_len= strlen(from);
    printf("lenght of msg.txt is %d\n", msg_len);
    printf("Plain text is is ---- %s\n", from);



    unsigned char rsa_plaintext[msg_len];
    unsigned char rsa_ciphertext[KEY_LEN];

    rsa_context rsa_polar;

    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
    rsa_polar.len = KEY_LEN;

    // loading RSA public key from public.pem file, working
    if(x509parse_public_keyfile(&rsa_polar, "public.pem")!=0){
        printf("Error reading public.pem file");
        exit(0);
    }

    if( rsa_check_pubkey(&rsa_polar) != 0) {
        printf( "Public key error! \n" );
        exit(0);
    }else
        printf("Reading public key successful\n");

    memcpy( rsa_plaintext, from, msg_len);

    if( rsa_pkcs1_encrypt( &rsa_polar, &myrand, NULL, RSA_PUBLIC, msg_len, rsa_plaintext, rsa_ciphertext ) != 0 ) {

        // Following is working
        //if( rsa_public(&rsa_polar, rsa_plaintext, rsa_ciphertext) != 0 ) {
        printf( "Encryption failed! \n" );
        exit(0);
    }else {
        printf("RSA Encryption with public.pem Successful\n");
        //memcpy( to, rsa_ciphertext, strlen(rsa_ciphertext));

        // writing into output file
        FILE *fp;
        //fp = fopen("to", "w+");
        fp = fopen("msg.enc", "w+");
        //fprintf(fp, "%s", &to);
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

static int eng_rsa_priv_dec (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    /*
     * New goal:
     * read private.pem file into buffer and encrypt
     * send encrypted file to the decryptmsg function
     *
     * */
    int result=0;

    rsa_context rsa_polar;
    aes_context aes;


    // reading private key in a buffer
    unsigned char * buffer = 0;
    long length;
    FILE * fp = fopen ("private.pem", "rb");

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
    //printf("buffer is \n %s\n", buffer);
    //printf("Size of Buffer is %d\n", strlen(buffer));

    // here total message length is strlen(buffer)/AES_BLOCK_SIZE, or 986/16 =61.625
    // but the following line rounded it to 61. So, .625 length of the message is missing
    // need to pad the buffer to make it multiple of 16. Reminder of 986%16=10. So we need (16-10)=6
    //  extra char to padding with the buffer
    // before performing the encryption operation


    //call a function for padding the buffer to make it multiple of 16
    if(strlen(buffer)%AES_BLOCK_SIZE == 0){
        printf("No padding needed\n");
    }else{
        //printf("padding needed: %i\n", strlen(buffer)%AES_BLOCK_SIZE );
        int k=AES_BLOCK_SIZE-(strlen(buffer)%AES_BLOCK_SIZE);
        printf("padding needed: %d\n", k );

        // adding extra 10 char for 1024-bit key. For 2048-bit key this padding will be different
        //char ch[10]={'0','0','0','0','0','0','0','0','0','0'};
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
    unsigned char private_decrypt[KEY_BUFFER_SIZE];
    int j;

    // following function will generate all the AES round keys for encryption
    aes_setkey_enc(&aes,mkt,AES_KEY_SIZE_BITS);

    for(j=0;j<strlen(buffer)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, buffer + AES_BLOCK_SIZE*j,private_encrypt+AES_BLOCK_SIZE*j);
    }
    //printf("Encrypted private key lenght -->\n %d \n", strlen(private_encrypt));
    printf("Encrypted private key is -->\n %s \n", private_encrypt);


// ************************************ Start Calling decryption function here ******************************//


    //struct CACHE_CRYPTO_ENV cacheCryptoEnv[SET_NUM];
    struct CACHE_CRYPTO_ENV cacheCryptoEnv;
    //struct ENV env;

    // DUNE starts
    volatile int ret;
    printf("hello: not running dune yet\n");

    ret = dune_init_and_enter();
    if (ret) {
        printf("failed to initialize dune\n");
        return ret;
    }
    printf("hello: now printing from dune mode\n");

    // printing the coreID
    printf(" First: current cpu is  = %d\n", sched_getcpu());

    // core & cache ID
    // for now assuming CPU has 2 separate cache set [0,1]
    // cpu 0-3 is in cache set 0
    // cpu 4-7 is in cache set 1

    int idcore=1;
    int idcache=0; // as I'm targeting cpu 1

    // check if cpu 1 has write back memory type.
    // Write back memory : CR0 ==> bit 29 & 30 should be 0
    // for write back memory type, get_memory_type() should return true
    if (!get_memory_type()){
        printf("Memory is not write back type");
        exit(0);
    }

    // setting other CPUs to no-fill mode
    // set_no_fill_mode() return 1 on success
    if(!set_no_fill_mode(idcache)){
        printf("Setting Other CPUs to no-fill mode failed\n");
        exit(0);
    }



  //  clear_no_fill_mode(idcache);
  //  exit(0);

    // Change CPU affinity to CPU 1, Isolated cpu
    cpu_set_t mask;
    CPU_ZERO(&mask);

    // setting current thread affinity to cpu 1
    CPU_SET(1, &mask);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) {
        perror("sched_setaffinity");
        assert(false);
    }
    printf("  ***************** CPU 1 is set for operation **************** \n");


    // Even though following line print current cpu is 123 (I don't know why).
    // cat /proc/sched_debug | grep openssl
    // shows openssl is running on CPU 1. when calling do_someWork() function

    //do_someWork(2,3);
    //exit(0);


    // do i need to use semaphore?
    // Paper says, Semaphore are used to avoid multiple cores in the same cache-sharing set to
    // execute Copker concurrently, as only one cacheCryptoEnv is allowed for each separate cache set.

    // Look for term cpu-hotplug

    // In our case, We always run our engine in core 1. Therefore, other core in the same cache set will not
    // be able to run our engine


    // Disable interrupt
    asm volatile("cli": : :"memory");

    // Check Interrupt status : Returns a true boolean value if irq are enabled for the CPU

    printf("Interrupt enable?:\t");
    printf(are_interrupts_enabled() ? "Yes\n" : "No\n");





    // Setting up secure env
    struct ENV env;
    printf("size of env is %ld\n", sizeof (env));

    // coping both encrypted message & RSA private key into env
    memcpy(env.encMsg, from, 1000);
    memcpy(env.encPrivateKey,private_encrypt,KEY_BUFFER_SIZE);

    // checking decryption function parameter
    //result =decryptFunction(from, private_encrypt);
    result =decryptFunction(env.encMsg, env.encPrivateKey);
    printf("after operation, result is %d\n",result);






    // restore Interrupts
    asm volatile("sti": : :"memory");
    printf("Interrupt enable?:\t");
    printf(are_interrupts_enabled() ? "Yes\n" : "No\n");

    // clear no fill mode. Return 1 on success
    if(!clear_no_fill_mode(idcache)){
        printf("Error: Couldn't clear CD flag of cr0 register.\n");
        exit(0);
    }



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
