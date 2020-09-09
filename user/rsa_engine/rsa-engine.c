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

int decryptmsg(unsigned char *ciphertext, key_rsa *cipherKey){

/*
you can't disable/enable interrupt in user mode, but you have a work around.
 You can write a driver which encapsulates the "loop" code in an interface,
 and you can enable/disable interrupt in your driver. Your application just need to call that interface.
*/


/*
 * Following code segment working fine with the hard coded keys.
 * and manual decryption of each field of rsa_context separately
 */

//
//    int j;
//    int result=-1;
//
//
//    size_t len;
//
//    rsa_context rsa_polar;
//    aes_context aes;
//
//    int len_cipher= strlen(ciphertext); /* this line causing an RTM abort*/
//    unsigned char rsa_decrypted[len_cipher];
//
//    //unsigned char rsa_decrypted[1024];
//
//    //printf("Cipher text is %s\n", ciphertext);
//
//    // Decrypted key storing buffer
//    unsigned char decrypted_RSA_D[sizeof(RSA_D)];
//    unsigned char decrypted_RSA_P[sizeof(RSA_P)];
//    unsigned char decrypted_RSA_Q[sizeof(RSA_Q)];
//    unsigned char decrypted_RSA_DP[sizeof(RSA_DP)];
//    unsigned char decrypted_RSA_DQ[sizeof(RSA_DQ)];
//    unsigned char decrypted_RSA_QP[sizeof(RSA_QP)];
//
//
//    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 ); /* This line is causing an RTM abort*/
//    rsa_polar.len = KEY_LEN;
//
//    //reading public key from the key_rsa structure
//    mpi_read_string( &rsa_polar.N , 16, cipherKey->N);
//    mpi_read_string( &rsa_polar.E , 16, cipherKey->E);
//
//
//    if( rsa_check_pubkey(&rsa_polar) != 0 ) {
//        printf( "Public key error! \n" );
//        exit(0);
//    }else{
//        printf( "Public key reading successful! \n" );
//    }
//
//
//
//// decrypt rsa private key's with AES
//
//    aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS);
//
//    for(j=0;j<sizeof(cipherKey->D)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->D + AES_BLOCK_SIZE*j,decrypted_RSA_D+AES_BLOCK_SIZE*j);
//    }
//    //decrypted_RSA_D[sizeof(RSA_D)-1]='\0';
//    //printf("sizeof RSA D is %d, decrypted D is : %s\n",sizeof(RSA_D), decrypted_RSA_D );
//
//    for(j=0;j<sizeof(cipherKey->P)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->P + AES_BLOCK_SIZE*j,decrypted_RSA_P+AES_BLOCK_SIZE*j);
//    }
//
//    for(j=0;j<sizeof(cipherKey->Q)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->Q + AES_BLOCK_SIZE*j,decrypted_RSA_Q+AES_BLOCK_SIZE*j);
//    }
//
//    for(j=0;j<sizeof(cipherKey->DP)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->DP + AES_BLOCK_SIZE*j,decrypted_RSA_DP+AES_BLOCK_SIZE*j);
//    }
//
//    for(j=0;j<sizeof(cipherKey->DQ)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->DQ + AES_BLOCK_SIZE*j,decrypted_RSA_DQ+AES_BLOCK_SIZE*j);
//    }
//
//    for(j=0;j<sizeof(cipherKey->QP)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_DECRYPT, cipherKey->QP + AES_BLOCK_SIZE*j,decrypted_RSA_QP+AES_BLOCK_SIZE*j);
//    }
//
//    //Adding Null at the end
//
//    decrypted_RSA_D[sizeof(RSA_D)-1]='\0';
//    decrypted_RSA_P[sizeof(RSA_P)-1]='\0';
//    decrypted_RSA_Q[sizeof(RSA_Q)-1]='\0';
//    decrypted_RSA_DP[sizeof(RSA_DP)-1]='\0';
//    decrypted_RSA_DQ[sizeof(RSA_DQ)-1]='\0';
//    decrypted_RSA_QP[sizeof(RSA_QP)-1]='\0';
//
//
//
//    //reading
//    mpi_read_string( &rsa_polar.N , 16, RSA_N);
//    mpi_read_string( &rsa_polar.E , 16, cipherKey->E);
//    mpi_read_string( &rsa_polar.D , 16, decrypted_RSA_D);
//    mpi_read_string( &rsa_polar.P , 16, decrypted_RSA_P);
//    mpi_read_string( &rsa_polar.Q , 16, decrypted_RSA_Q);
//    mpi_read_string( &rsa_polar.DP, 16, decrypted_RSA_DP);
//    mpi_read_string( &rsa_polar.DQ, 16, decrypted_RSA_DQ);
//    mpi_read_string( &rsa_polar.QP, 16, decrypted_RSA_QP);
//
//
//    // Checking the public and private keys
//    if( rsa_check_pubkey(  &rsa_polar ) != 0 ||rsa_check_privkey( &rsa_polar ) != 0 ) {
//        //printf( "Public/Private key error! \n" );
//        exit(0);
//    }else{
//       // printf("Key reading success\n");
//    }
//
//    if( rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, ciphertext, rsa_decrypted, sizeof(rsa_decrypted) ) != 0 ) {
//       // printf( "Decryption failed! \n" );
//        exit(0);
//    }else{
//        printf("Decrypted plaintext-----> %s\n",rsa_decrypted );
//
//        // writing into output file
//       FILE *fp;
//       fp = fopen("msg.decrypt", "w+");
//        fprintf(fp, "%s", rsa_decrypted);
//        fclose(fp);
//    }
//
//    rsa_free(&rsa_polar);
//
//
    return 1;

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
     * for encrypt a file hard coded keys
     * */


//    printf ("Engine is encrypting using pub key \n");
//
//
//    // getting the lenght of msg.txt
//    int msg_len= strlen(from);
//    printf("Plain text is is ---- %s\n", from);
//
//
//    // initializing RSA context
//    rsa_context rsa_polar;
//    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
//
//    unsigned char rsa_plaintext[msg_len];
//    unsigned char rsa_ciphertext[msg_len];
//
//    rsa_polar.len = KEY_LEN;
//
//    // setting RSA public key
//    mpi_read_string( &rsa_polar.N , 16, RSA_N  );
//    mpi_read_string( &rsa_polar.E , 16, RSA_E  );
//
//
//
//    // copy from msg.txt to rsa_plaintext
//    memcpy( rsa_plaintext, from, msg_len);
//
//    if( rsa_pkcs1_encrypt( &rsa_polar, &myrand, NULL, RSA_PUBLIC, msg_len, rsa_plaintext, rsa_ciphertext ) != 0 ) {
//   // if( rsa_pkcs1_encrypt( &rsa_polar, &myrand, NULL, RSA_PUBLIC, msg_len, rsa_plaintext, to ) != 0 ) {
//        printf( "Encryption failed! \n" );
//        exit(0);
//    }else {
//        printf("public: RSA Encryption Successful\n");
//
//        // writing into output file
//        FILE *fp;
//        //fp = fopen("to", "w+");
//        fp = fopen("msg.enc", "w+");
//        fprintf(fp, "%s", rsa_ciphertext);
//        fclose(fp);
//    }


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
    //if( rsa_pkcs1_encrypt( &rsa_polar, &myrand, NULL, RSA_PUBLIC, msg_len, from, to ) != 0 ) {
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

    // As of yet I did not use AES to encrypt private keys


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
    printf("buffer is \n %s\n", buffer);

    // here total message lenght is strlen(buffer)/AES_BLOCK_SIZE, or 986/16 =61.625
    // but the following line rounded it to 61. So, .625 lenght if message is missing
    // need to pad the buffer to make it multiple of 16, so need to add .625*16=10 padding with the buffer
    // before performing the encryption operation


    //call a function for padding the buffer to make it multiple of 16
   if(strlen(buffer)%AES_BLOCK_SIZE == 0){
       printf("No padding needed\n");
   }else{
       //printf("padding needed: %i\n", strlen(buffer)%AES_BLOCK_SIZE );
       int k=strlen(buffer)%AES_BLOCK_SIZE;
       printf("padding needed: %d\n", k );

       // adding extra 10 char for 1024-bit key. For 2048-bit key this padding will be different
       char ch[10]={'0','0','0','0','0','0','0','0','0','0'};

       strncat(buffer,&ch,k);
       //printf("After padding: strlen(buffer)/AES_BLOCK_SIZE is \n %d\n", strlen(buffer)/AES_BLOCK_SIZE);
       printf("Padded buffer is \n %s\n", buffer);

   }


    unsigned char private_encrypt[strlen(buffer)];
    unsigned char private_decrypt[strlen(buffer)];
    int j;

    // following function will generate all the AES round keys for encryption
    aes_setkey_enc(&aes,mkt,AES_KEY_SIZE_BITS);

    for(j=0;j<strlen(buffer)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_ENCRYPT, buffer + AES_BLOCK_SIZE*j,private_encrypt+AES_BLOCK_SIZE*j);
    }
    //printf("Encrypted private key lenght -->\n %d \n", strlen(private_encrypt));
    printf("Encrypted private key is -->\n %s \n", private_encrypt);



    // performing decryption on encrypted keys, working
    aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS);
    for(j=0;j<strlen(buffer)/AES_BLOCK_SIZE;++j){
        aes_crypt_ecb(&aes,AES_DECRYPT, private_encrypt + AES_BLOCK_SIZE*j,private_decrypt+AES_BLOCK_SIZE*j);
    }

    // for 1024 bit keys
    // removing the extra 10 padding
    int N=0;
    int len=strlen(private_decrypt);
    private_decrypt[length-N]='\0';




    printf("Decrypted private key is --> \n %s \n", private_decrypt);
    //printf("Decrypted private key lenght -->\n %d \n", strlen(private_decrypt));
    //printf("strlen(private_encrypt)/AES_BLOCK_SIZE is \n %d\n", strlen(private_encrypt)/AES_BLOCK_SIZE);


    //reading private.pem and perform decryption
    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
    int len_cipher=strlen(from);
    unsigned char decrypt_plaintext[len_cipher];


    // read decrypted key from buffer into rsa_context
    if (x509parse_key(&rsa_polar,private_decrypt,strlen(private_decrypt), "1234",4)!=0){
        printf("Error code\n");
    }else{
        printf("Reading decrypted private key from buffer into rsa_context is success\n");
    }

    if( rsa_check_pubkey(  &rsa_polar ) != 0 ||rsa_check_privkey( &rsa_polar ) != 0 ) {
        printf( "decryption : Public/Private key error! \n" );
        exit(0);
    }else{
        printf("decryption :Key reading success\n");
    }

    if( rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ) != 0 ) {
        printf( "Decryption failed! \n" );
        //printf("Error code,  %d",rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ));
        exit(0);
    }else {
        printf("decryption: Decrypted plaintext-----> %s\n", decrypt_plaintext);
    }

    exit(0);
















    /*
     * Following commented section is for reading private.pem file and perform decryption
     * Working
     *
     * */

//    printf ("Engine is decrypting using priv key \n");
//
//    int result =-1,j;
//    rsa_context rsa_polar;
//    rsa_context read_public;
//    key_rsa test;
//    size_t len;
//    int len_cipher= strlen(from);
//
//    // following is needed otherwise thorow error code -4400
//    unsigned char decrypt_plaintext[len_cipher];
//
//    //reading private.pem and perform decryption
//    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
//
//    if(x509parse_keyfile(&rsa_polar, "private.pem", "1234")!=0){
//        printf("Error code");
//    }else{
//        printf("private key reading success\n");
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
//        printf( "Decryption failed! \n" );
//        printf("Error code,  %d",rsa_pkcs1_decrypt( &rsa_polar, &myrand, NULL, RSA_PRIVATE, &len, from, decrypt_plaintext, sizeof(decrypt_plaintext) ));
//        exit(0);
//    }else{
//        printf("decryption: Decrypted plaintext-----> %s\n",decrypt_plaintext );
//
//        // writing into output file
//        FILE *fp;
//        fp = fopen("msg.decrypt", "w+");
//        fprintf(fp, "%s", decrypt_plaintext);
//        fclose(fp);
//    }
//
//    exit(0);



/*
 * Following code segment is working for hard coded keys and perform encryption and decryption of each field
 * of rsa_context manually.
 *
 * */

//
//    printf ("Engine is decrypting using priv key \n");
//    //RSA_private_decrypt (flen, from, to, rsa, RSA_PKCS1_PADDING);
//
//    int result =-1,j;
//    rsa_context rsa_polar;
//    key_rsa test;
//    size_t len;
//    //const char pass[]='1234';
//
//    int len_cipher= strlen(from);
//    unsigned char decrypt_plaintext[len_cipher];
//    rsa_init( &rsa_polar, RSA_PKCS_V15, 0 );
//
//    // Will Encrypt RSA private key with AES to look like Mimosa
//
//    unsigned char encrypted_RSA_D[sizeof(RSA_D)];
//    unsigned char encrypted_RSA_P[sizeof(RSA_P)];
//    unsigned char encrypted_RSA_Q[sizeof(RSA_Q)];
//    unsigned char encrypted_RSA_DP[sizeof(RSA_DP)];
//    unsigned char encrypted_RSA_DQ[sizeof(RSA_DQ)];
//    unsigned char encrypted_RSA_QP[sizeof(RSA_QP)];
//
//    aes_context aes;
//    // following function will generate all the AES round keys for encryption
//    aes_setkey_enc(&aes,mkt,AES_KEY_SIZE_BITS);
//
//    for(j=0;j<sizeof(RSA_D)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_D + AES_BLOCK_SIZE*j,encrypted_RSA_D+AES_BLOCK_SIZE*j);
//    }
//    printf("private key --> RSA_D encrypted \n");
//
//    for(j=0;j<sizeof(RSA_P)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_P + AES_BLOCK_SIZE*j,encrypted_RSA_P+AES_BLOCK_SIZE*j);
//    }
//    printf("private key --> RSA_P encrypted \n");
//
//    for(j=0;j<sizeof(RSA_Q)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_Q + AES_BLOCK_SIZE*j,encrypted_RSA_Q+AES_BLOCK_SIZE*j);
//    }
//    printf("private key --> RSA_Q encrypted \n");
//
//    for(j=0;j<sizeof(RSA_DP)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_DP + AES_BLOCK_SIZE*j,encrypted_RSA_DP+AES_BLOCK_SIZE*j);
//    }
//    printf("private key --> RSA_DP encrypted \n");
//
//    for(j=0;j<sizeof(RSA_DQ)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_DQ + AES_BLOCK_SIZE*j,encrypted_RSA_DQ+AES_BLOCK_SIZE*j);
//    }
//    printf("private key --> RSA_DQ encrypted \n");
//
//    for(j=0;j<sizeof(RSA_QP)/AES_BLOCK_SIZE;++j){
//        aes_crypt_ecb(&aes,AES_ENCRYPT, RSA_QP + AES_BLOCK_SIZE*j,encrypted_RSA_QP+AES_BLOCK_SIZE*j);
//    }
//    printf("private key --> RSA_QP encrypted \n");
//
//    // adding this encrypted keys into _key_rsa structure
//    memcpy(test.N, RSA_N, sizeof(RSA_N));
//    memcpy(test.E, RSA_E, sizeof(RSA_E));
//    memcpy(test.D, encrypted_RSA_D, sizeof(encrypted_RSA_D));
//    memcpy(test.P, encrypted_RSA_P, sizeof(encrypted_RSA_P));
//    memcpy(test.Q, encrypted_RSA_Q, sizeof(encrypted_RSA_Q));
//    memcpy(test.DP, encrypted_RSA_DP, sizeof(encrypted_RSA_DP));
//    memcpy(test.DQ, encrypted_RSA_DQ, sizeof(encrypted_RSA_DQ));
//    memcpy(test.QP, encrypted_RSA_QP, sizeof(encrypted_RSA_QP));
//
//
//    //using RTM, bind dec decryptmsg() into a particular CPU
//    cpu_set_t set;
//    int parentCPU, childCPU;
//    childCPU = 1;
//    parentCPU = 0;
//
//    CPU_ZERO(&set);
//    switch (fork()) {
//        case -1:            //error
//            errExit("fork");
//
//        case 0:             // Child
//            CPU_SET(childCPU, &set);
//
//            if (sched_setaffinity(getpid(), sizeof(set), &set) == -1)
//                //if (sched_setaffinity(1, sizeof(set), &set) == -1)
//                errExit("sched_setaffinity");
//
//            //calling decryption function from here
//            result = decryptmsg(from,&test);
//            printf("result %d\n", result);
//
//            exit(0);
//
//        default:            // parent
//            CPU_SET(parentCPU, &set);
//
//            if (sched_setaffinity(getpid(), sizeof(set), &set) == -1)
//                errExit("sched_setaffinity");
//
//            wait(NULL);     // Wait for child to terminate
//            exit(EXIT_SUCCESS);
//    }
//
//


/*
 *
 * Following commented code is used to try limited number of tries on RTM failure
 *
 * */


//    int n_retries=0;
//    int MAX_TRIES=50;
//    unsigned status;
//    while (1){
//        if(++n_retries==MAX_TRIES)
//            goto out;
//        status=_xbegin();
//        if (status==_XBEGIN_STARTED)
//            break;
//    }
//
//    result = decryptmsg(from,&test);
//    printf("result is %d\n",result);
//
//    out:
//        if(_xtest()){
//            _xend();
//        }else{
//            printf("Transaction failed\n");
//        }


    // calling Do all funciton here
    // result = decryptmsg(from,&test);
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
