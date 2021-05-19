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
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>


/* Declared already in ossl_typ.h */
/* typedef struct rsa_st RSA; */
/* typedef struct rsa_meth_st RSA_METHOD; */


struct rsa_meth_st {

    const char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);

    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);

    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

    int (*init) (RSA *rsa);

    int (*finish) (RSA *rsa);

    int flags;

    char *app_data;

    int (*rsa_sign) (int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, const RSA *rsa);

    int (*rsa_verify) (int dtype, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa);

    int (*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);

};

// RSA Public key operation
static int eng_rsa_pub_enc (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding){
    printf ("Engine is encrypting using pub key \n");
}

static int eng_rsa_pub_dec (int flen, const unsigned char *from,  unsigned char *to, RSA * rsa, int padding){

    printf ("Engine is decrypting using pub key \n");
}

static int eng_rsa_priv_enc (int flen, const unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){

    printf ("Engine is encrypting using priv key \n");
}

static int eng_rsa_priv_dec (int flen, unsigned char *from, unsigned char *to, RSA * rsa, int padding __attribute__ ((unused))){
    printf ("Engine is decrypting using priv key \n");
}

/* Constants used when creating the ENGINE */
static const char *engine_rsa_id = "rsa-engine-new";
static const char *engine_rsa_name = "Demo engine";

struct rsa_meth_st suse_rsa =
        {
                "demo RSA Engine",
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

    if (!ENGINE_set_id (e, engine_rsa_id) ||

        !ENGINE_set_name (e, engine_rsa_name) ||

        !ENGINE_set_RSA (e, &suse_rsa))

        return 0;

    return 1;

}

IMPLEMENT_DYNAMIC_BIND_FN (bind)
IMPLEMENT_DYNAMIC_CHECK_FN ()

