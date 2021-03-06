#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

//# define KEY_BUFFER_SIZE 992 // this is for 1024-bit key. For different key length it will be different
# define KEY_BUFFER_SIZE 992
#define KEY_LEN 128


//*********************  global variable for cache_crypto_env struct ************************//
#define CACHE_STACK_SIZE 10000 // most likely will be changed, depending on the size of the structure

// Secure CRYPTO structure
//#pragma pack(1) // Not adding extra structure padding
static struct CACHE_CRYPTO_ENV{
    unsigned char masterKey[128/8]; // for 128 bit master key
    //aes_context aes; // initialize AES
    //rsa_context rsa; // initialize RSA
    unsigned char cachestack[CACHE_STACK_SIZE];
    //unsigned long privateKeyID;
    unsigned long encryptPrivateKey;
    unsigned char in[KEY_BUFFER_SIZE]; // KEY_BUFFER_SIZE is the total size of the encrypted key
                                       // in --> encrypted RSA privateKey

    unsigned char out[KEY_BUFFER_SIZE]; // Need to remove those extra padding to get back the original key
                                        // out--> plaintext RSA privateKey

}cacheCryptoEnv;


// original decryption function
//int decryptFunction (unsigned char *from, unsigned char *private_encrypt){
int decryptFunction (struct CACHE_CRYPTO_ENV *env){
    printf("INside decryptFunction, Size of env is %ld\n", sizeof(*env));
    printf("INside decryptFunction, msg is:  %s\n", env->in);
    printf("INside decryptFunction, key is:  %s\n", env->out);

    return 0;
    //exit(0);

}


void stackswitch( void *env, int (*f)(struct CACHE_CRYPTO_ENV *), unsigned char *stackBottom){

    printf("Inside stackswitch, Size of env is %ld\n", sizeof(*(struct CACHE_CRYPTO_ENV *)env));
    printf("Inside stackswitch, msg is:  %s\n", ((struct CACHE_CRYPTO_ENV *)env)->in);
    printf("Inside stackswitch, key is:  %s\n", ((struct CACHE_CRYPTO_ENV *)env)->out);



    //calling the actual decryption function
    //(*f)(env);

    //creating the original stack switch function
    asm volatile(

    //prologue
    "pushq %%rbp \t\n"
    //"mov %%rbp, %2 \t\n"

    "movq %%rsp, %%rbp \t\n" // can't modify rbp without clobber register.
    //"mov %%rbp, %3 \t\n"

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
}



int main(){

    struct CACHE_CRYPTO_ENV env;
    memcpy(cacheCryptoEnv.in,"This is test ", sizeof(cacheCryptoEnv.in));
    memcpy(cacheCryptoEnv.out,"This is key ", sizeof(cacheCryptoEnv.out));

    //copying cachecryptoenv into env
    env=cacheCryptoEnv;

    //check values
    printf("env.in is: %s\n",env.in);
    printf("env.out is: %s\n",env.out);


    // calling stackswitch function
    stackswitch(&env, decryptFunction, env.cachestack+CACHE_STACK_SIZE-8);
    printf("Main function END\n");



}