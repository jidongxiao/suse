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



int decryptmsg(unsigned char *ciphertext, key_rsa *encrypted_keys){

    int j,ret=0;
    size_t len;
    unsigned char rsa_decrypted[1000];

    // context
    aes_context aesContext;
    rsa_context rsaContext;


    // size of all the keys
    printf("size of RSA_D is %ld\n", sizeof (RSA_D));
    printf("size of RSA_P is %ld\n", sizeof (RSA_P));
    printf("size of RSA_Q is %ld\n", sizeof (RSA_Q));

    // initialize
    aes_setkey_dec(&aesContext,mkt,AES_KEY_SIZE_BITS);
    rsa_init(&rsaContext,RSA_PKCS_V15, 0);
    rsaContext.len=KEY_LEN;


    unsigned char plainKey[sizeof(RSA_KEY_NO_LABEL)];
    RSA_KEY_NO_LABEL_PTR plainKey_rsa_no_label;

    // keys without public parameter
    RSA_KEY_NO_LABEL no_lebel_enc_key;

    // copying all encypt keys
    memcpy(no_lebel_enc_key.D, encrypted_keys->D, sizeof(RSA_D));
    memcpy(no_lebel_enc_key.P, encrypted_keys->P, sizeof(RSA_P));
    memcpy(no_lebel_enc_key.Q, encrypted_keys->Q, sizeof(RSA_Q));
    memcpy(no_lebel_enc_key.DP, encrypted_keys->DP, sizeof(RSA_DP));
    memcpy(no_lebel_enc_key.DQ, encrypted_keys->DQ, sizeof(RSA_DQ));
    memcpy(no_lebel_enc_key.QP, encrypted_keys->QP, sizeof(RSA_QP));


    //printf("size of encrypted_keys->N is %ld\n", sizeof (encrypted_keys->N));

    //exit(0);



/*
    if(mpi_read_binary(&rsaContext.N, encrypted_keys->N, sizeof (encrypted_keys->N))){
        printf("Error reading keys_kernel->N");
        exit(0);
    }

    if(mpi_read_binary(&rsaContext.E, encrypted_keys->E, sizeof (encrypted_keys->E))){
        printf("Error reading keys_kernel->E");
        exit(0);
    }

*/


    // NULL terminated buffer for N
    unsigned char BUFF_RSA_N[sizeof(RSA_N)];
    memcpy(&BUFF_RSA_N, encrypted_keys->N, sizeof (RSA_N));
    BUFF_RSA_N[sizeof(RSA_N)-1]='\0';
    mpi_read_string( &rsaContext.N , 16, BUFF_RSA_N);



    // NULL terminated buffer for E
    unsigned char BUFF_RSA_E[sizeof(RSA_E)];
    memcpy(&BUFF_RSA_E, encrypted_keys->E, sizeof (RSA_E));
    BUFF_RSA_E[sizeof(RSA_E)-1]='\0';
    mpi_read_string( &rsaContext.E , 16, BUFF_RSA_E);


    //mpi_read_string( &rsaContext.N , 16, encrypted_keys->N);
    //mpi_read_string( &rsaContext.E , 16, encrypted_keys->E);


    for(j=0;j<sizeof(plainKey)/AES_BLOCK_SIZE;++j){
        //aes_crypt_ecb(&aesContext,AES_DECRYPT,(unsigned char *)(&no_lebel_enc_key) + 2 * ( MAX_MPI_IN_BYTE) + AES_BLOCK_SIZE*j,plain+AES_BLOCK_SIZE*j);
        aes_crypt_ecb(&aesContext,AES_DECRYPT,(unsigned char *)(&no_lebel_enc_key) + AES_BLOCK_SIZE*j,plainKey+AES_BLOCK_SIZE*j);
    }

    // assigning _key_rsa type to RSA_KEY_NO_LABEL type
    plainKey_rsa_no_label = (RSA_KEY_NO_LABEL_PTR) plainKey;

    //printf("size of plainKey_rsa_no_label->D is %ld\n", sizeof (plainKey_rsa_no_label->D));
    //printf("plainKey_rsa_no_label->P is %s\n", plainKey_rsa_no_label->P);


    // Decrypted key storing buffer
    unsigned char decrypted_RSA_D[sizeof(RSA_D)];
    unsigned char decrypted_RSA_P[sizeof(RSA_P)];
    unsigned char decrypted_RSA_Q[sizeof(RSA_Q)];
    unsigned char decrypted_RSA_DP[sizeof(RSA_DP)];
    unsigned char decrypted_RSA_DQ[sizeof(RSA_DQ)];
    unsigned char decrypted_RSA_QP[sizeof(RSA_QP)];


    memcpy(&decrypted_RSA_D, plainKey_rsa_no_label->D, sizeof (RSA_D));
    memcpy(&decrypted_RSA_P, plainKey_rsa_no_label->P, sizeof (RSA_P));
    memcpy(&decrypted_RSA_Q, plainKey_rsa_no_label->Q, sizeof (RSA_Q));
    memcpy(&decrypted_RSA_DP, plainKey_rsa_no_label->DP, sizeof (RSA_DP));
    memcpy(&decrypted_RSA_DQ, plainKey_rsa_no_label->DQ, sizeof (RSA_DQ));
    memcpy(&decrypted_RSA_QP, plainKey_rsa_no_label->QP, sizeof (RSA_QP));



    // Adding Null at the end
    decrypted_RSA_D[sizeof(RSA_D)-1]='\0';
    decrypted_RSA_P[sizeof(RSA_P)-1]='\0';
    decrypted_RSA_Q[sizeof(RSA_Q)-1]='\0';
    decrypted_RSA_DP[sizeof(RSA_DP)-1]='\0';
    decrypted_RSA_DQ[sizeof(RSA_DQ)-1]='\0';
    decrypted_RSA_QP[sizeof(RSA_QP)-1]='\0';


    // printing Decrypted private keys
    printf("decrypted_RSA_D %s\n", decrypted_RSA_D);
    printf("decrypted_RSA_P %s\n", decrypted_RSA_P);
    printf("decrypted_RSA_Q %s\n", decrypted_RSA_Q);
    printf("decrypted_RSA_DP %s\n", decrypted_RSA_DP);
    printf("decrypted_RSA_DQ %s\n", decrypted_RSA_DQ);
    printf("decrypted_RSA_QP %s\n", decrypted_RSA_QP);


    // reading keys
    // if(mpi_read_binary(&rsaContext.D,decrypted_RSA_D, sizeof (RSA_D))){
    // if(mpi_read_binary(&rsaContext.D,plainKey_rsa_no_label->D, sizeof (RSA_D))){
    if(mpi_read_string(&rsaContext.D,16, decrypted_RSA_D)){
        printf("Error reading plainKey_rsa_no_label->D\n");
        exit(0);
    }

    // if(mpi_read_binary(&rsaContext.P,decrypted_RSA_P, sizeof (RSA_P))){
    // if(mpi_read_binary(&rsaContext.P,plainKey_rsa_no_label->P,sizeof (RSA_P))){
    if(mpi_read_string(&rsaContext.P,16, decrypted_RSA_P)){
        printf("Error reading plainKey_rsa_no_label->P\n");
        exit(0);
    }

    //if(mpi_read_binary(&rsaContext.Q,decrypted_RSA_Q, sizeof (RSA_Q))){
    //if(mpi_read_binary(&rsaContext.Q,plainKey_rsa_no_label->Q,128)){
    if(mpi_read_string(&rsaContext.Q,16, decrypted_RSA_Q)){
        printf("Error reading plainKey_rsa_no_label->Q\n");
        exit(0);
    }

    //if(mpi_read_binary(&rsaContext.DP,decrypted_RSA_DP, sizeof (RSA_DP))){
    //if(mpi_read_binary(&rsaContext.DP,plainKey_rsa_no_label->DP,128)){
    if(mpi_read_string(&rsaContext.DP,16, decrypted_RSA_DP)){
        printf("Error reading plainKey_rsa_no_label->DP\n");
        exit(0);
    }

    //if(mpi_read_binary(&rsaContext.DQ,decrypted_RSA_DQ, sizeof (RSA_DQ))){
    //if(mpi_read_binary(&rsaContext.DQ,plainKey_rsa_no_label->DQ,128)){
    if(mpi_read_string(&rsaContext.DQ,16, decrypted_RSA_DQ)){
        printf("Error reading plainKey_rsa_no_label->DQ\n");
        exit(0);
    }

    //if(mpi_read_binary(&rsaContext.QP,decrypted_RSA_QP, sizeof (RSA_QP))){
    //if(mpi_read_binary(&rsaContext.QP,plainKey_rsa_no_label->QP,128)){
    if(mpi_read_string(&rsaContext.QP,16, decrypted_RSA_QP)){
        printf("Error reading plainKey_rsa_no_label->QP\n");
        exit(0);
    }

    // check rsa public key
    if(rsa_check_pubkey(&rsaContext)!=0){
        printf("Reading public key error\n");
    }

    if(rsa_check_privkey(&rsaContext)!=0){
        printf("Reading private key error\n");
    }

    printf("before rsa_pkcs1\n");

    size_t olen;


    //if( rsa_pkcs1_decrypt( &rsaContext,RSA_PRIVATE,&olen,ciphertext,rsa_decrypted,sizeof(rsa_decrypted) ) != 0 ) {
    if( rsa_private(&rsaContext,ciphertext, rsa_decrypted) != 0 ) {
        printf( "Decryption failed! %d\n", rsa_private(&rsaContext,ciphertext, rsa_decrypted));
        //printf( "Decryption failed! %d\n", rsa_pkcs1_decrypt( &rsaContext,RSA_PRIVATE,&olen,ciphertext,rsa_decrypted,sizeof(rsa_decrypted) ));
        exit(0);
    }else{
        printf("Decrypted plaintext-----> %s\n",rsa_decrypted );
        ret =1;

}

    return ret;
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

    int j, result;
    aes_context aesContext;

    // variable to hold the enc key
    unsigned char plain[sizeof(RSA_KEY_NO_LABEL)];
    RSA_KEY_NO_LABEL_PTR rsa_no_label;


    //RSA_KEY_NO_LABEL_PTR keys_kernel;
    RSA_KEY_NO_LABEL keys_kernel;


    // will use hold the final keys
    key_rsa encKEy;

/*
    // copy public key
    if(mpi_read_binary(&test.N, RSA_N, sizeof (RSA_N))){
        printf("Error\n");
        exit(0);
    }

    if(mpi_read_binary(&test.E, RSA_E, sizeof (RSA_E))){
        printf("Error reading keys_kernel->E\n");
        exit(0);
    }
*/

    memcpy(keys_kernel.D, RSA_D, sizeof(RSA_D));
    memcpy(keys_kernel.P, RSA_P, sizeof(RSA_P));
    memcpy(keys_kernel.Q, RSA_Q, sizeof(RSA_Q));
    memcpy(keys_kernel.DP, RSA_DP, sizeof(RSA_DP));
    memcpy(keys_kernel.DQ, RSA_DQ, sizeof(RSA_DQ));
    memcpy(keys_kernel.QP, RSA_QP, sizeof(RSA_QP));

    printf("Size od RSA_D is %ld\n", sizeof (RSA_D));

    //printf("keys_kernel->D is %s\n", keys_kernel.D);
    printf("size of keys_kernel is %ld\n", sizeof (keys_kernel.D));


    // initialize
    aes_setkey_enc(&aesContext,mkt,AES_KEY_SIZE_BITS);

    for(j=0;j<sizeof(plain)/AES_BLOCK_SIZE;j++){
        aes_crypt_ecb(&aesContext,AES_ENCRYPT,((unsigned char *)(&keys_kernel) + AES_BLOCK_SIZE*j),plain+AES_BLOCK_SIZE*j);
    }

    rsa_no_label = (RSA_KEY_NO_LABEL_PTR ) plain;

    memcpy(encKEy.N, RSA_N, sizeof(RSA_N));
    memcpy(encKEy.E, RSA_E, sizeof(RSA_E));
    memcpy(encKEy.D, rsa_no_label->D, sizeof(RSA_D));
    memcpy(encKEy.P, rsa_no_label->P, sizeof(RSA_P));
    memcpy(encKEy.Q, rsa_no_label->Q, sizeof(RSA_Q));
    memcpy(encKEy.DP, rsa_no_label->DP, sizeof(RSA_DP));
    memcpy(encKEy.DQ, rsa_no_label->DQ, sizeof(RSA_DQ));
    memcpy(encKEy.QP, rsa_no_label->QP, sizeof(RSA_QP));

    // calling decrypt funciton here
    result = decryptmsg(from,&encKEy);
    printf("result: %d\n",result);


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
