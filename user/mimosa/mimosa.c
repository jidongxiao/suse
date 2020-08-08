#include <stddef.h>
#include <stdint.h>

#include "cacheCryptoMain.h"
#include "config.h"
#include "aes.h"
#include "bignum.h"
#include "rsa.h"

#define MAX_CPUS_TSX 8
RSA_KEY keys_kernel[MAX_CPUS_TSX];      //encrypt

unsigned char mkt[16] = { \
0x52,0x47,0x99,0x32, \
0x4f,0x20,0x6d,0xf0, \
0x1f,0x5b,0x30,0x31, \
0x0c,0xe3,0x50,0x1a \
};


static int doAll(unsigned char *inout, RSA_KEY *cipherKey){
        int j,ret = 1;
        rsa_context rsa;
        aes_context aes;
        unsigned char plain[sizeof(RSA_KEY_NO_LABEL)];
        RSA_KEY_NO_LABEL_PTR rsa_no_label;
        unsigned char out[MAX_MPI_IN_BYTE];
        unsigned char *cipher = (unsigned char *)cipherKey + 2 * (4 + MAX_MPI_IN_BYTE) + LABEL_SIZE;

        rsa_init(&rsa,RSA_PKCS_V15, 0);
        aes_setkey_dec(&aes,mkt,AES_KEY_SIZE_BITS);
    


    mpi_read_binary(&rsa.N,cipherKey->N,sizeof(cipherKey->N));


    mpi_read_binary(&rsa.E,cipherKey->E,sizeof(cipherKey->E));

        

    for(j=0;j<sizeof(plain)/AES_BLOCK_SIZE;++j){// keys_kernel is not in cache
        aes_crypt_ecb(&aes,AES_DECRYPT, cipher + AES_BLOCK_SIZE*j,plain+AES_BLOCK_SIZE*j);
    }           
                         
    rsa_no_label = (RSA_KEY_NO_LABEL_PTR)plain;
        
                
    mpi_read_binary(&rsa.D,rsa_no_label->D,sizeof(rsa_no_label->D));
        
        
    mpi_read_binary(&rsa.P,rsa_no_label->P,sizeof(rsa_no_label->P));

        
    mpi_read_binary(&rsa.Q,rsa_no_label->Q,sizeof(rsa_no_label->Q));


    mpi_read_binary(&rsa.DP,rsa_no_label->DP,sizeof(rsa_no_label->DP));


    mpi_read_binary(&rsa.DQ,rsa_no_label->DQ,sizeof(rsa_no_label->DQ));


    mpi_read_binary(&rsa.QP,rsa_no_label->QP,sizeof(rsa_no_label->QP));


    rsa.len = cipherKey->sizeofN;


    rsa_private( &rsa,NULL, NULL, inout,  out );

    memcpy(inout,out,MAX_MPI_IN_BYTE);

        ret = 0;
err:
        return ret;
}

void main()
{
	int result, i;
	i = 0;
	result = -1;
	unsigned char in[MAX_MPI_IN_BYTE];

	result = doAll(in,keys_kernel + i);
}
