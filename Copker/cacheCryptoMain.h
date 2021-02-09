#ifndef CCK_H
#define CCK_H
#include "rsa.h"
#include "aes.h"


/*

#define KEY_LEN 128

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

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"



*/


#ifdef __KERNEL__
#include <linux/crypto.h>
#include <linux/types.h>
#endif





void tresor_kernel_init(void);






//#define CCK_DEBUG

#undef P_DEBUG
#ifdef CCK_DEBUG
#  ifdef __KERNEL__
#    define P_DEBUG(fmt, args...) printk( KERN_DEBUG "CCK(File :%s Line: %d Name: %s PID: %u)"  fmt, __FILE__,__LINE__,current->comm, current->pid,## args)
#  else
#    define P_DEBUG(fmt, args...) fprintf(stderr, "CCK(File :%s Line: %d Name: %s PID: %u)"  fmt, __FILE__,__LINE__,current->comm, current->pid,## args)
#  endif
#else
#  define P_DEBUG(fmt, args...)
#endif

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
#define heapStackSize (0x15D0)
//#define heapStackSize (0x1f5c)
#define RandArraySize (sizeof(ProtectedMem)/64)
typedef struct _ProtectedMem{
	//uint8_t padding1[64];
	uint8_t master_key[MASTER_KEY_SIZE];
	aes_context aes;
	rsa_context rsa;
	Sign_Para signPara;
	unsigned char heapStack[heapStackSize];
	//uint8_t padding[64];
}ProtectedMem,*ProtectedMem_PTR;
#endif

#endif
