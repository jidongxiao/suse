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
#include "rsa/cacheCryptoMain.h"
#include "rsa/config.h"
#include "rsa/aes.h"
#include "rsa/bignum.h"
#include "rsa/rsa.h"

// Start: all the functions for RSA operation

/* this is the AES master key, in this project, it is supposed to be derived from the debug registers. */
unsigned char mkt[16] = { \
0x52,0x47,0x99,0x32, \
0x4f,0x20,0x6d,0xf0, \
0x1f,0x5b,0x30,0x31, \
0x0c,0xe3,0x50,0x1a \
};


#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#define KEY_LEN 128



typedef struct _key_rsa{
    unsigned char N[MAX_MPI_IN_BYTE];
    unsigned char E[MAX_MPI_IN_BYTE];
    unsigned char D[MAX_MPI_IN_BYTE];
    unsigned char P[KEY_LEN];
    unsigned char Q[KEY_LEN];
    unsigned char DP[KEY_LEN];
    unsigned char DQ[KEY_LEN];
    unsigned char QP[KEY_LEN];
}key_rsa;


int myrand( void *rng_state, unsigned char *output, size_t len ){
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();

    return( 0 );
}

int decryptmsg(unsigned char *ciphertext, key_rsa *cipherKey){
    int j;
    size_t len;
    rsa_context rsa_polar;

    int len_cipher= strlen(ciphertext);
    unsigned char rsa_decrypted[len_cipher];

    printf("Cipher text is ------\n %s\n", ciphertext);

    // Decrypted key storing buffer
    unsigned char decrypted_RSA_D[sizeof(RSA_D)];
    unsigned char decrypted_RSA_P[sizeof(RSA_P)];
    unsigned char decrypted_RSA_Q[sizeof(RSA_Q)];
    unsigned char decrypted_RSA_DP[sizeof(RSA_DP)];
    unsigned char decrypted_RSA_DQ[sizeof(RSA_DQ)];
    unsigned char decrypted_RSA_QP[sizeof(RSA_QP)];


    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
    rsa_polar.len = KEY_LEN;

    //reading public key from the key_rsa structure
    mpi_read_string( &rsa_polar.N , 16, cipherKey->N);
    mpi_read_string( &rsa_polar.E , 16, cipherKey->E);

    if( rsa_check_pubkey(&rsa_polar) != 0 ) {
        printf( "Public key error! \n" );
        exit(0);
    }else{
        printf( "Public key reading successful! \n" );
    }

// decrypt rsa private key's with AES
    aes_context aes;
    aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS);

    for(j=0;j<sizeof(cipherKey->D)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->D + AES_BLOCK_SIZE*j,decrypted_RSA_D+AES_BLOCK_SIZE*j);
    }

    for(j=0;j<sizeof(cipherKey->P)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->P + AES_BLOCK_SIZE*j,decrypted_RSA_P+AES_BLOCK_SIZE*j);
    }

    for(j=0;j<sizeof(cipherKey->Q)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->Q + AES_BLOCK_SIZE*j,decrypted_RSA_Q+AES_BLOCK_SIZE*j);
    }

    for(j=0;j<sizeof(cipherKey->DP)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->DP + AES_BLOCK_SIZE*j,decrypted_RSA_DP+AES_BLOCK_SIZE*j);
    }

    for(j=0;j<sizeof(cipherKey->DQ)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->DQ + AES_BLOCK_SIZE*j,decrypted_RSA_DQ+AES_BLOCK_SIZE*j);
    }

    for(j=0;j<sizeof(cipherKey->QP)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->QP + AES_BLOCK_SIZE*j,decrypted_RSA_QP+AES_BLOCK_SIZE*j);
    }

    /*Adding Null at the end*/

    decrypted_RSA_D[sizeof(RSA_D)-1]='\0';
    decrypted_RSA_P[sizeof(RSA_P)-1]='\0';
    decrypted_RSA_Q[sizeof(RSA_Q)-1]='\0';
    decrypted_RSA_DP[sizeof(RSA_DP)-1]='\0';
    decrypted_RSA_DQ[sizeof(RSA_DQ)-1]='\0';
    decrypted_RSA_QP[sizeof(RSA_QP)-1]='\0';


    //reading
    mpi_read_string( &rsa_polar.N , 16, RSA_N);
    mpi_read_string( &rsa_polar.E , 16, cipherKey->E);
    mpi_read_string( &rsa_polar.D , 16, decrypted_RSA_D);
    mpi_read_string( &rsa_polar.P , 16, decrypted_RSA_P);
    mpi_read_string( &rsa_polar.Q , 16, decrypted_RSA_Q);
    mpi_read_string( &rsa_polar.DP, 16, decrypted_RSA_DP);
    mpi_read_string( &rsa_polar.DQ, 16, decrypted_RSA_DQ);
    mpi_read_string( &rsa_polar.QP, 16, decrypted_RSA_QP);


    // Checking the public and private keys
    if( rsa_check_pubkey(  &rsa_polar ) != 0 ||rsa_check_privkey( &rsa_polar ) != 0 ) {
        printf( "Public/Private key error! \n" );
        exit(0);
    }else{
        printf("Key reading success\n");
    }

    if( rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, ciphertext, rsa_decrypted, sizeof(rsa_decrypted) ) != 0 ) {
        printf( "Decryption failed! \n" );
        exit(0);
    }else{
        printf("Decrypted plaintext-----> %s\n",rsa_decrypted );

        // writing into output file
        FILE *fp;
        fp = fopen("msg.decrypt", "w+");
        fprintf(fp, "%s", rsa_decrypted);
        fclose(fp);
    }

    rsa_free(&rsa_polar);

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

    /*

     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
     * *NOT* be used RSA_sign(), RSA_verify() should be used instead. Note:
     * for backwards compatibility this functionality is only enabled if the
     * RSA_FLAG_SIGN_VER option is set in 'flags'.

     */

    int (*rsa_sign) (int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

    int (*rsa_verify) (int dtype, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);

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
    //RSA_public_encrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);

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

        // writing into output file
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
    //RSA_private_decrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);

    int result =-1,j;
    rsa_context rsa_polar;
    key_rsa test;
    size_t len;


    // Will Encrypt RSA private key with AES to look like Mimosa

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

    // calling Do all funciton here
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
