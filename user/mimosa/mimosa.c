#include <stddef.h>
#include <stdint.h>

#include "cacheCryptoMain.h"
#include "config.h"
#include "aes.h"
#include "bignum.h"
#include "rsa.h"

//#define MAX_CPUS_TSX 8
//RSA_KEY keys_kernel[MAX_CPUS_TSX];      //encrypt

RSA_KEY key[8];

/* this is the AES master key, in this project, it is supposed to be derived from the debug registers. */
unsigned char mkt[16] = { \
0x52,0x47,0x99,0x32, \
0x4f,0x20,0x6d,0xf0, \
0x1f,0x5b,0x30,0x31, \
0x0c,0xe3,0x50,0x1a \
};


/* cipherKey is one of the encrypted RSA private keys, read from the file /EncRsaKey.key, which contains several keys. */

static int doAll(unsigned char *inout, RSA_KEY *cipherKey){
        int j,ret = 1;
        rsa_context rsa;
        aes_context aes;
        unsigned char plain[sizeof(RSA_KEY_NO_LABEL)];
        RSA_KEY_NO_LABEL_PTR rsa_no_label;
        unsigned char out[MAX_MPI_IN_BYTE];
        unsigned char *cipher = (unsigned char *)cipherKey + 2 * (4 + MAX_MPI_IN_BYTE) + LABEL_SIZE;

        rsa_init(&rsa,RSA_PKCS_V15, 0); /* initialized an RSA context. */
        aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS); /* aes is the aes context to be initialized, mkt here is the decryption key, i.e., master key, AES_KEY_SIZE_BITS is the key size, must be 128, 192, or 256. Overall, this function does AES key decryption - which generates the AES context, which main includes the AES round keys. if successful, returns 0. */
    
	/* in RSA key(n,e,d), the public key is represented by integers n and e, the private key is represented by integer d. */

    mpi_read_binary(&rsa.N,cipherKey->N,sizeof(cipherKey->N)); /* import rsa.N from unsigned binary data cipherKey->N */

    mpi_read_binary(&rsa.E,cipherKey->E,sizeof(cipherKey->E)); /* import rsa.E from unsigned binary data cipherKey->E */


    for(j=0;j<sizeof(plain)/AES_BLOCK_SIZE;++j){// keys_kernel is not in cache
        aes_crypt_ecb(&aes,AES_DECRYPT, cipher + AES_BLOCK_SIZE*j,plain+AES_BLOCK_SIZE*j); /* AES-ECB block encryption/decryption. The 2nd parameter says it's encryption or decryption, here it is AES_DECRYPT, thus it's decryption. The 3rd parameter is the input, the 4th parameter is the output, and here the 4th parameter is plain, which is the plaintext RSA private key. */ 
    }           
                         
    rsa_no_label = (RSA_KEY_NO_LABEL_PTR)plain; /* now that everything is in plaintext in this plain, we can then easily figure out D, and other RSA private key parameters, as below */
        
                
    mpi_read_binary(&rsa.D,rsa_no_label->D,sizeof(rsa_no_label->D)); /* import rsa.D from unsigned binary data rsa_no_label->D */
        
        
    mpi_read_binary(&rsa.P,rsa_no_label->P,sizeof(rsa_no_label->P));

        
    mpi_read_binary(&rsa.Q,rsa_no_label->Q,sizeof(rsa_no_label->Q));


    mpi_read_binary(&rsa.DP,rsa_no_label->DP,sizeof(rsa_no_label->DP));


    mpi_read_binary(&rsa.DQ,rsa_no_label->DQ,sizeof(rsa_no_label->DQ));


    mpi_read_binary(&rsa.QP,rsa_no_label->QP,sizeof(rsa_no_label->QP));


    rsa.len = cipherKey->sizeofN;


    rsa_private( &rsa, NULL, NULL, inout,  out ); /* Do an RSA private key operation. Once we have all the RSA private key paramters stored in the data structure rsa (i.e., rsa context), we call this rsa_private function to decrypt the message, which is in inout, and the final result will be stored in out. */

    memcpy(inout,out,MAX_MPI_IN_BYTE); /* copy the output back to the inout parameter. */

        ret = 0;
err:
        return ret;
}

void main()
{
	int result;
	result = -1;

	unsigned char mes[MAX_MOD] = {1,2,3,4,5,0}; /* MAX_MOD is 32. this line is copied from user.c, message is, either an encrypted message that we want to decrypt, or a message we want to sign a signature on. */
	unsigned char in[MAX_MPI_IN_BYTE];
	memcpy(in,mes,MAX_MPI_IN_BYTE);

	char testkey[]="x+OttA2nORA4NGD5JFUX7e3mEg2hB3RZ+yOAghIHZri9aVCzHrLJAIoZY1D/VTz7QSWlGxXWSGBJBwN8OpAl3T06bM5UruPzAnBAFvp3yfAaCvQ87ARTRjCTAZmVDYs2x3KAQoc9a27htYRcEKUhJJ6quC0O2FeQu1Rb8eTQg05URw0vPQNzycJt1rvSDA55nfFbs0xCq90xixqWa9L+/y110kb4fRiO8Hb8QS+urLv8EzDDZk8aOGr14It1nXgtcCARvO7qhfJH4WvSywjbrwuHIBqx0Inrdl5ifIQPNf2/5hY+SkDiHDQ8/R2vixyS72/di2i9DWqG9jpydM645Ikzq19G/qi3VyyVvik3hqSodDdcVAb2ZMvjEN2LRo20wB+2kaA9znKZmv+5BoSQHKYHwoEmhzhewRP77TR+bZ1iJUfebGrNCBnzp6RxBdvmhJMJCw+cuH49S0eG9icWAxGql3C7Lt2EUyv3VvFNoNZ1B2aMoeSTzQAolvapFoqKwGR5czbLKBxk6U/pLeuE176GvOajwJK44BUxSuSK61SYQVmBhJ6wzV2zPytjsAuQGe3Ks4JL70+s4I0aPHPDyX08A4JsVTbGKEGvU1OSNf3oKOoMkspq/s7LP+LkvbSLWtqXx+SRxtN8DodyQ6Oe0S/6e219LNaTfg7wZShp06Yaont4HmfJN0b5zvvDB7gs1lmekVQDFnsbxrYSbL2Kwt23d47kad+0pISfU2AgE5LzvXhT7pAT321L4tSdWcMd+9FyY2SHdr63EIM0n24gfwt3hC6LKbkIkp5SpSXW9ypDeLsDPuxSP3EogeZIGzianPDFzcPSXm5jwkchdZKj74dm2Z4mAqEOKcW0lElsBlWEHNVjH3tG6ScKssWC226vlM79QfsAmDkLUw9Knm6giEoajZFYBlZfoZarHNQUoNSaSvOUAuH7g16LaDT6r7yUt9ZzJvGMECI2k6TMjzv+zobyOhF+Z26vbmD06GfdARo7xJdWoH0DHxQbM7Zc1GMYZCJya6Tpgrc48IXsdjJDSPgYXJ7Tf1Ldqh3Gg+EZUugD34mxjEFftCNNjdO437YRzxcMiArymAvRFWR0kBrNoadUtenKtvnso3LV5kKEOh4=";
	memcpy(key, testkey, sizeof(testkey));

	result = doAll(in,key+0);
	printf("in is: %s\n",in); /* in here is either a signed message, or a decrypted message? */
}
