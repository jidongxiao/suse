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
//#include "rsa/cacheCryptoMain.h"
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

#include <sys/resource.h>

#include <pthread.h>
#include <time.h>


#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)
//This is the paddedd buffer size. This is for 2048-bit key.
// For different key length it will be different
# define KEY_BUFFER_SIZE 2368

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


}



static int eng_rsa_pub_dec (int flen, const unsigned char *from,  unsigned char *to, RSA * rsa, int padding){

    printf ("Engine is decrypting using pub key \n");

    //RSA_public_decrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);

}



static int eng_rsa_priv_enc (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    printf ("Engine is encrypting using priv key \n");
    //RSA_private_encrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);
}


void test(void * input){
    setpriority(PRIO_PROCESS, 0, -20);
    printf("Test thread\n");

    struct arg_thread *argThread=input;
    volatile int total_dec=1000;

    int j;
    unsigned char * buffer = 0;
    long length;
    unsigned char msg_decrypted[KEY_LEN];

    FILE * fp = fopen ("rsa_priv.txt", "rb");

    if (fp){
        fseek (fp, 0, SEEK_END);
        length = ftell (fp);
        fseek (fp, 0, SEEK_SET);
        buffer = calloc (1,length+1);
        if (buffer){
            fread (buffer, 1, length, fp);
        }
        fclose (fp);
    }

    // initialize rsaContext
    rsa_context rsaContext;
    rsa_init(&rsaContext,RSA_PKCS_V15, 0);
    rsaContext.len=KEY_LEN;

    // spliting keys and load into rsa context
    const char s[3] = "= ";
    char *token;
    int k=0, size;
    unsigned char *rest=buffer;

    // get the first token
    token = strtok_r(rest,s,&rest);

    // walk through other tokens
    while( token != NULL ) {
        size = strlen(token);

        switch (k) {
            case 1:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.N, 16, token);
                break;

            case 3:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.E, 16, token);
                break;

            case 5:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.D, 16, token);
                break;

            case 7:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.P, 16, token);
                break;

            case 9:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.Q, 16, token);
                break;

            case 11:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.DP, 16, token);
                break;

            case 13:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.DQ, 16, token);
                break;

            case 15:
                token[size-1]='\0';
                mpi_read_string(&rsaContext.QP, 16, token);
                break;
        }
        k=k+1;
        //token = strtok(NULL, "= \n");
        token = strtok_r(rest, "= \n", &rest);
    }

    while (total_dec>=0) {
        if( rsa_private(&rsaContext,argThread->from, msg_decrypted) != 0 ) {
            printf( "Decryption failed! %d\n", rsa_private(&rsaContext,argThread->from, msg_decrypted));
        }else{
            printf("Decrypted plaintext-----> %s\n",msg_decrypted );
        }
        total_dec--;
    }

}

static int eng_rsa_priv_dec (int flen, unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    // copy engine argument to a predefine structure for using inside a thread function
    struct arg_thread argThread;
    argThread.from=from;
    argThread.to=from;

    // calling thread from here
    int i;

    // total number of thread
    pthread_t ths[NUM_OF_THREAD];

    // start time count
    time_t start = time(NULL);


    for (i = 0; i < NUM_OF_THREAD; i++) {
        pthread_create(&ths[i], NULL, test, (void *)&argThread);
    }

    for (i = 0; i < NUM_OF_THREAD; i++) {
        void* res;
        pthread_join(ths[i], &res);
    }

    // measure end time
    printf("Time %.2f\n", (double)(time(NULL) - start));

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
