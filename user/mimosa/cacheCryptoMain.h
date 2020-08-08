#ifndef CCK_H
#define CCK_H
#include "rsa.h"
#include "aes.h"

#ifdef __KERNEL__
#include <linux/crypto.h>
#include <linux/types.h>
#endif


#include "config.h"

#define AES_KEY_SIZE 16
#define MASTER_KEY_SIZE AES_KEY_SIZE

#define	SHA1_LEN	20




/*
typedef struct _WRAPPED_PRI_KEY{
	int size;
	uint8_t *key;
};

*/
typedef struct _Key_Info{
	int index;
	int size;
}Key_Info,*pKey_Info;
/*
typedef struct _Key_Mes{
	int index;
	uint8_t *mes;
}Key_Mes,*pKey_Mes;
*/



//FILE FORMAT
//FILE = RSANUM(4 BYTE) || {Enc(RSA_KEY)*}
#define MAX_KEYS    20
//#define MAX_MPI_IN_BYTE (3072/8)
#define MAX_MPI_IN_BYTE (2048/8)
#define MAX_MOD	MAX_MPI_IN_BYTE
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE_BITS  (AES_KEY_SIZE<<3)
#define LABEL_SIZE  32
#define KEY_ID_LEN	(LABEL_SIZE)
//sizeof(RSA_KEY) = 0 mod AES_BLOCK_SZIE

typedef struct _Sign_Para{
	char label[LABEL_SIZE];
	//rsa_context	rsa;
	uint8_t in[MAX_MPI_IN_BYTE];
	uint8_t out[MAX_MPI_IN_BYTE];
}Sign_Para,*pSign_Para;

typedef struct _GetPubPara{
	char label[LABEL_SIZE];
	uint8_t N[MAX_MPI_IN_BYTE];
	uint8_t E[MAX_MPI_IN_BYTE];
}GetPubPara,*pGetPubPara;

typedef struct _RSA_KEY{
    unsigned char label[LABEL_SIZE];
    unsigned int sizeofN;
    unsigned char N[MAX_MPI_IN_BYTE];
    unsigned int sizeofE;
    unsigned char E[MAX_MPI_IN_BYTE];
    unsigned int sizeofD;
    unsigned char D[MAX_MPI_IN_BYTE];
    unsigned int sizeofP;
    unsigned char P[MAX_MPI_IN_BYTE];
    unsigned int sizeofQ;
    unsigned char Q[MAX_MPI_IN_BYTE];
    unsigned int sizeofDP;
    unsigned char DP[MAX_MPI_IN_BYTE];
    unsigned int sizeofDQ;
    unsigned char DQ[MAX_MPI_IN_BYTE];
    unsigned int sizeofQP;
    unsigned char QP[MAX_MPI_IN_BYTE];
    unsigned int pad1;
    unsigned int pad2;
}RSA_KEY,*RSA_KEY_PTR;

typedef struct _RSA_KEY_NO_LABEL{
    //unsigned int sizeofN;
    //unsigned char N[MAX_MPI_IN_BYTE];
    //unsigned int sizeofE;
    //unsigned char E[MAX_MPI_IN_BYTE];
    unsigned int sizeofD;
    unsigned char D[MAX_MPI_IN_BYTE];
    unsigned int sizeofP;
    unsigned char P[MAX_MPI_IN_BYTE];
    unsigned int sizeofQ;
    unsigned char Q[MAX_MPI_IN_BYTE];
    unsigned int sizeofDP;
    unsigned char DP[MAX_MPI_IN_BYTE];
    unsigned int sizeofDQ;
    unsigned char DQ[MAX_MPI_IN_BYTE];
    unsigned int sizeofQP;
    unsigned char QP[MAX_MPI_IN_BYTE];
    unsigned int pad1;
    unsigned int pad2;
}RSA_KEY_NO_LABEL,*RSA_KEY_NO_LABEL_PTR;

//RSA_KEY keys[MAX_KEYS];
//RSA_KEY keys_kernel[MAX_KEYS];
//


#ifdef __KERNEL__


/* number of iterations for key derivation */
#define TRESOR_KDF_ITER 2000

/* number of chars to clear memory */
//#define TRESOR_RANDOM_CHARS 4096
#define TRESOR_RANDOM_CHARS 20

/* TRESOR core functionality (enc, dec, setkey) */
void tresor_setkey(const u8 *in_key);


void tresor_kernel_init(void);

int  tresor_readkey(const char *device, int resume);

/* Key prompt on wakeup after suspend2ram */
//void tresor_dont_switch_console(int dont_switch);
//void tresor_thaw_processes(void);


#ifndef CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
/* Prevent the test manager from overwriting dbg regs with test keys */
//void tresor_unlock_tests(void);
//void tresor_lock_tests(void);
//int tresor_lock_status(void);
#endif

typedef struct _PRI_KEY{
	uint8_t key_id[KEY_ID_LEN];
	rsa_context	rsa;
}PRI_KEY,*PPRI_KEY;


struct IsoToken_dev{
	int master_key_present;
	struct miscdevice *cdev;
	
	int keyPresent;
	//PPRI_KEY	ppriKey;
	char *msg;
};
//#define gl_order	(1)
//#define gl_pageNum	(1<<gl_order)
//#define heapStackSize	(4096*gl_pageNum)
//#define heapStackSize (0x15D0) //for 2048
#define heapStackSize (0x15E0)
//#define heapStackSize (0x1f5c) //for 3072
/*
#define RandArraySize (((sizeof(ProtectedMem) + 63) /64)  + 2)
typedef struct _ProtectedMem{
	uint8_t master_key[MASTER_KEY_SIZE];
	rsa_context rsa;
	Sign_Para signPara;
	RSA_KEY cipherKey;
}ProtectedMem,*ProtectedMem_PTR;
*/
#endif

#endif
