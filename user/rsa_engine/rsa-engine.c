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
#define device "/proc/deviceDriver"
#define buff_size 3

# define KEY_BUFFER_SIZE 996 // this is for 1024-bit key. For different key lenght it will be different
#define KEY_LEN 128


void clear_buffer (char *buffer){
    memset(buffer,0,buff_size);
}

void enable_interrupt(){
    int fd;
    char buff[buff_size];
    int count=1; //count should be less then the buff size
    //char message[]="Hello";
    //char message[0]="1";
    int rv;
    clear_buffer(buff);

    fd=open(device, O_RDWR, S_IWUSR | S_IRUSR);
    if(fd==-1){
        // was throwing error. I fixed it by giving permission
        //  sudo chmod 0777/0666 deviceDriver
        fprintf(stderr, "Error Opening device File\n");
        exit(-1);
    }

    //writing to device
    printf("enable_interrupt\n");
    //strcpy(buff,message);
    strcpy(buff,"1");
    rv=write(fd,buff,count);
    if (rv==-1){
        fprintf(stderr, "Error while writing\n");
        exit(0);
    }

    rv=close(fd);
    if (rv==-1){
        fprintf(stderr, "Error while closing\n");
        exit(0);
    }

}

void disable_interrupt(){
    int fd;
    char buff[buff_size];
    int count=1; //count should be less then the buff size
    //char message[]="Hello";
    //char message[0]="1";
    int rv;
    clear_buffer(buff);

    fd=open(device, O_RDWR, S_IWUSR | S_IRUSR);
    if(fd==-1){
        // was throwing error. I fixed it by giving permission
        //  sudo chmod 0777/0666 deviceDriver
        fprintf(stderr, "Error Opening device File\n");
        exit(-1);
    }

    //writing to device
    printf("disable_interrupt\n");
    //strcpy(buff,message);
    strcpy(buff,"0");
    rv=write(fd,buff,count);
    if (rv==-1){
        fprintf(stderr, "Error while writing\n");
        exit(0);
    }

    rv=close(fd);
    if (rv==-1){
        fprintf(stderr, "Error while closing\n");
        exit(0);
    }
}

char check_interruptStatus(){

    int fd;
    char buff[buff_size];
    int count=1; //count should be less then the buff size
    //char message[]="Hello";
    //char message[0]="1";
    int rv;

    // Clear Buffer
    clear_buffer(buff);

    fd=open(device, O_RDWR, S_IWUSR | S_IRUSR);
    if(fd==-1){
        // was throwing error. I fixed it by giving permission
        //  sudo chmod 0777/0666 deviceDriver
        fprintf(stderr, "Error Opening device File\n");
        exit(-1);
    }

    printf("Reading from the %s\n", device);
    rv= read(fd, buff,count);
    if (rv==-1){
        fprintf(stderr, "Error while reading\n");
        exit(-1);
    }
    printf(" %d char from %s is %s. \n",rv,device, buff);

    for(int i=0;i<sizeof(buff);i++){
        printf("Buff[%d] is %c\n",i,buff[i]);
    }
    rv=close(fd);
    if (rv==-1){
        fprintf(stderr, "Error while closing\n");
        exit(-1);
    }
    return buff[0];

}

int test_otherfunction(int a, int b){
    int c=0;
    for (int i=0; i<1000000;i++){
        c=c+a+b;
        //printf("%d\n",c);
    }
//    for (int i=0; i<1000000;i++){
//        c=c+a+b;
//        //printf("%d\n",c);
//    }
    // RTM did Succeeded, but after some tires

//    for (int i=0; i<1000000;i++){
//        c=c+a+b;
//        //printf("%d\n",c);
//    }
//    for (int i=0; i<1000000;i++){
//        c=c+a+b;
//        //printf("%d\n",c);
//    }

    return 1;
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

    int j, result=-1;
    int N=6;
    aes_context aes;
    rsa_context rsa_polar;

    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );

    int len_cipher=strlen(from);
    unsigned char decrypt_plaintext[len_cipher]; // lencipher is causuing failure, need to find a size in Byte

    unsigned char private_decrypt[KEY_BUFFER_SIZE];

    // this should be inside RTM, this is the main AES master key
    aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS);

    unsigned status;
    while(result!=1){
        if ((status = _xbegin()) == _XBEGIN_STARTED) {


            for(j=0;j<KEY_BUFFER_SIZE/AES_BLOCK_SIZE;++j){
                aes_crypt_ecb(&aes,AES_DECRYPT, private_encrypt + AES_BLOCK_SIZE*j,private_decrypt+AES_BLOCK_SIZE*j);
            }

            // for 1024 bit keys, removing the extra 10 padding
            int len=strlen(private_decrypt);
            private_decrypt[len-N]='\0';

// Following code, causing RTM abort
//            if( rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ) != 0 )
//                exit(0);

            result=1;
            _xend();
        }else{
            printf("Block 1: Transaction failed\n");
            printf("status is %ld\n", status);
            //break;
        }
        printf("Block 1: Result is %d\n", result);
    }
    printf("First Block working\n", result);
    printf("Decrypted private key is --> \n %s \n", private_decrypt);

    // First block working
    //exit(0);


    // RTM BLOCK 2
    result=-1;
    unsigned block;

    int key_len= KEY_LEN;

    while(result!=1){
        if ((block = _xbegin()) == _XBEGIN_STARTED) {
            if( rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &key_len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ) != 0 )
                exit(0);
            //rsa_free(&rsa_polar);
            result=1;
            _xend();
        }else{
            printf("RTM 2: Transaction failed\n");
            printf("status is %ld\n", block);
            //break;
        }
        printf("Block 2: Result is %d\n", result);
    }









    printf("decryption: Decrypted plaintext-----> %s\n", decrypt_plaintext);
    exit(0);

    return result;


    // performing decryption on encrypted keys, working
//    aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS);
//    for(j=0;j<KEY_BUFFER_SIZE/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_DECRYPT, private_encrypt + AES_BLOCK_SIZE*j,private_decrypt+AES_BLOCK_SIZE*j);
//    }
//
//    // for 1024 bit keys, removing the extra 10 padding
//    int N=11;
//    int len=strlen(private_decrypt);
//    private_decrypt[len-N]='\0';
//
//    printf("Decrypted private key is --> \n %s \n", private_decrypt);
//
//
//    //reading private.pem and perform decryption
//    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
//    int len_cipher=strlen(from);
//    unsigned char decrypt_plaintext[len_cipher];
//
//
//    // read decrypted key from buffer into rsa_context
//    if (x509parse_key(&rsa_polar,private_decrypt,strlen(private_decrypt), "1234",4)!=0){
//        printf("Error code\n");
//    }else{
//        printf("Reading decrypted private key from buffer into rsa_context is success\n");
//    }
//
//    if( rsa_check_pubkey(  &rsa_polar ) != 0 ||rsa_check_privkey( &rsa_polar ) != 0 ) {
//        printf( "decryption : Public/Private key error! \n" );
//        exit(0);
//    }else{
//        printf("decryption :Key reading success\n");
//    }
//
//    if( rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ) != 0 ) {
//    //if( rsa_private(&rsa_polar, &myrand, NULL, from, decrypt_plaintext)!=0){
//        printf( "Decryption failed! \n" );
//        printf("Error code,  %d",rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ));
//        exit(0);
//    }else {
//        printf("decryption: Decrypted plaintext-----> %s\n", decrypt_plaintext);
//    }
//
//    exit(0);

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



static int eng_rsa_pub_dec (int flen, const unsigned char *from,

                            unsigned char *to, RSA * rsa, int padding)

{



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

    // here total message lenght is strlen(buffer)/AES_BLOCK_SIZE, or 986/16 =61.625
    // but the following line rounded it to 61. So, .625 lenght if message is missing
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
       for (int i=0;i<k;i++){
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



//using RTM, bind dec decryptmsg() into a particular CPU
    cpu_set_t set;
    int parentCPU, childCPU;
    childCPU = 1;
    parentCPU = 0;

    CPU_ZERO(&set);
    switch (fork()) {
        case -1:            //error
            errExit("fork");

        case 0:             // Child
            CPU_SET(childCPU, &set);

            if (sched_setaffinity(getpid(), sizeof(set), &set) == -1)
            //if (sched_setaffinity(1, sizeof(set), &set) == -1)
                errExit("sched_setaffinity");

            //calling decryption function from here
            result =decryptFunction(from, private_encrypt);
            printf("result %d\n", result);

            exit(0);

        default:            // parent
            CPU_SET(parentCPU, &set);

            if (sched_setaffinity(getpid(), sizeof(set), &set) == -1)
                errExit("sched_setaffinity");

            wait(NULL);     // Wait for child to terminate
            exit(EXIT_SUCCESS);
    }



    // Calling decryption function here

    printf("after operation, result is %d\n",result);

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
