#include <openssl/opensslconf.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>

// loading RSA helper function
#include "rsa/config.h"
#include "rsa/aes.h"
#include "rsa/bignum.h"
#include "rsa/rsa.h"
#include "key.h"

// Start: all the functions for RSA operation



int myrand( void *rng_state, unsigned char *output, size_t len ){
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}


int decryptmsg(unsigned char *ciphertext, key_rsa *keys_kernel){

    int j;
    aes_context aesContext;
    rsa_context rsaContext;

    size_t len;
    unsigned char rsa_decrypted[200];
    rsaContext.len=KEY_LEN;


    rsa_init(&rsaContext,RSA_PKCS_V15, 0);

    unsigned char plain[sizeof(RSA_KEY_NO_LABEL)];
    RSA_KEY_NO_LABEL_PTR rsa_no_label_ptr;
    //RSA_KEY_NO_LABEL rsa_no_label;


    aes_setkey_dec(&aesContext,mkt,AES_KEY_SIZE_BITS);

    if(mpi_read_binary(&rsaContext.N, keys_kernel->N, sizeof (keys_kernel->N))){
        printf("Error reading keys_kernel->N");
        exit(0);
    }

    if(mpi_read_binary(&rsaContext.E, keys_kernel->E, sizeof (keys_kernel->E))){
        printf("Error reading keys_kernel->E");
        exit(0);
    }


    for(j=0;j<sizeof(plain)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aesContext,AES_DECRYPT,(unsigned char *)(keys_kernel) + 2 * (4 + MAX_MPI_IN_BYTE) + LABEL_SIZE + AES_BLOCK_SIZE*j,plain+AES_BLOCK_SIZE*j);
        //printf("plain\n");
    }

    rsa_no_label_ptr = (RSA_KEY_NO_LABEL_PTR ) plain;
    //rsa_no_label = (RSA_KEY_NO_LABEL_PTR) plain;



    if(mpi_read_binary(&rsaContext.D,rsa_no_label_ptr->D,sizeof(rsa_no_label_ptr->D))){
        printf("Error reading rsa_no_label->D");
        exit(0);
    }

    if(mpi_read_binary(&rsaContext.P,rsa_no_label_ptr->P,sizeof(rsa_no_label_ptr->P))){
        printf("Error reading rsa_no_label_ptr->P");
        exit(0);
    }

    if(mpi_read_binary(&rsaContext.Q,rsa_no_label_ptr->Q,sizeof(rsa_no_label_ptr->Q))){
        printf("Error reading rsa_no_label_ptr->Q");
        exit(0);
    }

    if(mpi_read_binary(&rsaContext.DP,rsa_no_label_ptr->DP,sizeof(rsa_no_label_ptr->DP))){
        printf("Error reading rsa_no_label_ptr->DP");
        exit(0);
    }

    if(mpi_read_binary(&rsaContext.DQ,rsa_no_label_ptr->DQ,sizeof(rsa_no_label_ptr->DQ))){
        printf("Error reading rsa_no_label_ptr->DQ");
        exit(0);
    }

    if(mpi_read_binary(&rsaContext.QP,rsa_no_label_ptr->QP,sizeof(rsa_no_label_ptr->QP))){
        printf("Error reading rsa_no_label_ptr->QP");
        exit(0);
    }

    if( rsa_pkcs1_decrypt( &rsaContext, &myrand, NULL, RSA_PRIVATE, &len, ciphertext, rsa_decrypted, sizeof(rsa_decrypted) ) != 0 ) {
    //if( rsa_private(&rsaContext,ciphertext, rsa_decrypted) != 0 ) {
        printf( "Decryption failed! \n" );
        exit(0);
    }else{
        printf("Decrypted plaintext-----> %s\n",rsa_decrypted );


    return 0;
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

    int (*rsa_sign) (int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

    int (*rsa_verify) (int dtype, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);

    int (*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

};


// RSA Public key operation
static int eng_rsa_pub_enc (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding){

    printf ("Engine is encrypting using pub key \n");
/*
    // getting the lenght of msg.txt
    int msg_len= strlen(from);
    printf("Plain text is is ---- %s\n", from);


    unsigned char rsa_plaintext[msg_len];
    unsigned char rsa_ciphertext[KEY_LEN];

    rsa_context rsa_polar;

    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
    rsa_polar.len = KEY_LEN;

    // setting RSA public key
    mpi_read_string( &rsa_polar.N , 16, RSA_N  );
    mpi_read_string( &rsa_polar.E , 16, RSA_E  );

    if( rsa_check_pubkey(&rsa_polar) != 0) {
        printf( "Public key error! \n" );
        exit(0);
    }

    // copy from msg.txt to rsa_plaintext
    memcpy( rsa_plaintext, from, msg_len);

    if( rsa_pkcs1_encrypt( &rsa_polar, &myrand, NULL, RSA_PUBLIC, msg_len, rsa_plaintext, rsa_ciphertext ) != 0 ) {
        printf( "Encryption failed! \n" );
        exit(0);
    }else {
        printf("RSA Encryption Successful\n");


    if(rsa_public(&rsa_polar, rsa_plaintext, rsa_ciphertext)!=0){
        printf("ENC failed");
        exit(0);
    } else{
        printf("RSA Encryption Successful\n");
    }
    */
}



static int eng_rsa_pub_dec (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding){
    printf ("Engine is decrypting using pub key \n");
    //RSA_public_decrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);

}

static int eng_rsa_priv_enc (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    printf ("Engine is encrypting using priv key \n");
    //RSA_private_encrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);
}


static int eng_rsa_priv_dec (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    printf ("Engine is decrypting using priv key \n");

    int result =-1,j;
    rsa_context rsa_polar;
    key_rsa test;
    size_t len;


    unsigned char encrypted_RSA_D[sizeof(RSA_D)];
    unsigned char encrypted_RSA_P[sizeof(RSA_P)];
    unsigned char encrypted_RSA_Q[sizeof(RSA_Q)];
    unsigned char encrypted_RSA_DP[sizeof(RSA_DP)];
    unsigned char encrypted_RSA_DQ[sizeof(RSA_DQ)];
    unsigned char encrypted_RSA_QP[sizeof(RSA_QP)];


    aes_context aes;
    // following function will generate all the AES round keys for encryption
    aes_setkey_enc(&aes,mkt,AES_KEY_SIZE_BITS);

    for(j=0;j<sizeof(RSA_D)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_D + AES_BLOCK_SIZE*j,encrypted_RSA_D+AES_BLOCK_SIZE*j);
    }
    printf("private key --> RSA_D encrypted \n");

    for(j=0;j<sizeof(RSA_P)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_P + AES_BLOCK_SIZE*j,encrypted_RSA_P+AES_BLOCK_SIZE*j);
    }
    printf("private key --> RSA_P encrypted \n");

    for(j=0;j<sizeof(RSA_Q)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_Q + AES_BLOCK_SIZE*j,encrypted_RSA_Q+AES_BLOCK_SIZE*j);
    }
    printf("private key --> RSA_Q encrypted \n");

    for(j=0;j<sizeof(RSA_DP)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_DP + AES_BLOCK_SIZE*j,encrypted_RSA_DP+AES_BLOCK_SIZE*j);
    }
    printf("private key --> RSA_DP encrypted \n");

    for(j=0;j<sizeof(RSA_DQ)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_DQ + AES_BLOCK_SIZE*j,encrypted_RSA_DQ+AES_BLOCK_SIZE*j);
    }
    printf("private key --> RSA_DQ encrypted \n");

    for(j=0;j<sizeof(RSA_QP)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_QP + AES_BLOCK_SIZE*j,encrypted_RSA_QP+AES_BLOCK_SIZE*j);
    }
    printf("private key --> RSA_QP encrypted \n");


    // adding this encrypted keys into _key_rsa structure
    memcpy(test.N, RSA_N, sizeof(RSA_N));
    memcpy(test.E, RSA_E, sizeof(RSA_E));
    memcpy(test.D, encrypted_RSA_D, sizeof(encrypted_RSA_D));
    memcpy(test.P, encrypted_RSA_P, sizeof(encrypted_RSA_P));
    memcpy(test.Q, encrypted_RSA_Q, sizeof(encrypted_RSA_Q));
    memcpy(test.DP, encrypted_RSA_DP, sizeof(encrypted_RSA_DP));
    memcpy(test.DQ, encrypted_RSA_DQ, sizeof(encrypted_RSA_DQ));
    memcpy(test.QP, encrypted_RSA_QP, sizeof(encrypted_RSA_QP));


/*
    aes_context aesContext;
    rsa_context rsaContext;

    key_rsa keys_kernel;
    rsa_init(&rsaContext,RSA_PKCS_V15, 0);

    // copy public key
    if(mpi_read_binary(&rsaContext.N, RSA_N, sizeof (RSA_N))){
        printf("Error\n");
        exit(0);

    }

    if(mpi_read_binary(&rsaContext.E, keys_kernel->E, sizeof (keys_kernel->E))){
        printf("Error reading keys_kernel->E\n");
        exit(0);
    }



    for(j=0;j<sizeof(plain)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aesContext,AES_DECRYPT,(unsigned char *)(keys_kernel) + 2 * (4 + MAX_MPI_IN_BYTE) + LABEL_SIZE + AES_BLOCK_SIZE*j,plain+AES_BLOCK_SIZE*j);
        //printf("plain\n");
    }
*/

    // calling decrypt funciton here
    result = decryptmsg(from,&test);


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



static int bind (ENGINE * e, const char *id){
    printf ("%s\n", id);

    if (!ENGINE_set_id (e, engine_rsa_id) || !ENGINE_set_name (e, engine_rsa_name) || !ENGINE_set_RSA (e, &suse_rsa))
        return 0;

    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN (bind)
IMPLEMENT_DYNAMIC_CHECK_FN ()
