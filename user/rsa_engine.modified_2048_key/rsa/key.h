//
// Created by mass on 2/15/21.
//


//#define KEY_LEN 128 // for 1024-bit key
#define KEY_LEN 256

//#define CACHE_STACK_SIZE 20000 // most likely will be changed, depending on the size of the structure
#define CACHE_STACK_SIZE 19550

//This is the paddedd buffer size. This is for 2048-bit key. For different key length it will be different
# define KEY_BUFFER_SIZE 2368

// variables for threading
#define NUM_OF_THREAD 8

// following variable used inside fill-mode/no-fill mode
#define SET_NUM 2


#define AES_KEY_SIZE 16
#define MASTER_KEY_SIZE AES_KEY_SIZE
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE_BITS  (AES_KEY_SIZE<<3)
#define MAX_MPI_IN_BYTE (2048/8)
#define LABEL_SIZE  32

/* this is the AES master key */
unsigned char mkt[16] = { \
0x52,0x47,0x99,0x32, \
0x4f,0x20,0x6d,0xf0, \
0x1f,0x5b,0x30,0x31, \
0x0c,0xe3,0x50,0x1a \
};

// structure to pass enc_msg & enc_key to the concurrent thread
struct arg_thread{
    unsigned char *from;
    unsigned char *to;
    int thread_id;
};

typedef struct file
{
    unsigned char *from;
    unsigned char *to;
} file_entry;


// Secure CRYPTO structure
static struct CACHE_CRYPTO_ENV{
    unsigned char in[KEY_LEN]; // in --> encrypted msg
    unsigned char masterKey[128/8]; // for 128 bit master key
    unsigned char out[KEY_LEN];  // out--> decrypted plaintext.
    aes_context aes; // initialize AES
    rsa_context rsa; // initialize RSA
    unsigned char cachestack[CACHE_STACK_SIZE];
    unsigned long privateKeyID;
    unsigned char encryptPrivateKey[KEY_BUFFER_SIZE]; // encrypted private key
    int thread_no;
    //unsigned char alloc_buf[10000];
}cacheCryptoEnv;
#define cacheCryptoEnvSize (sizeof(cacheCryptoEnv)/64)


#define RSA_N   "D0C2ACDCF780B1E4846054BDA700F18D" \
                "567247FE8BC5BA4FBCAB814E619DA63A" \
                "20F65A58EE89FC0824DC9367C5725BDD" \
                "C596065F1C8868E99C896F3A0CF7D7F0" \
                "A785E668F2568F19BAFB8FF3BA5CDF48" \
                "7544EFE71010BEDB4EE16EDC3AF0A713" \
                "91AD3194B42D3FD40B4E0DE12A22D818" \
                "8AF03FF4E36D37BA1DA1F3C57188E60D" \
                "A38C25329E48805FC7FF524761A6F010" \
                "E737B927D8F67383274F8E600167A52A" \
                "042E1DCA3335150C090803F9D96F6E63" \
                "BEBFB153516E863F5B4CB02104077834" \
                "FC5EC31A47451783931D643CE736DD1B" \
                "AB40C5523858BB067FB9E490DCB5FDBB" \
                "B03B9D68A8998C1347E237C477AA14B0" \
                "997A84708CED05A9E24C7072B838F753"

#define RSA_E   "010001"

/*
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
*/

/*
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

typedef struct _RSA_KEY_NO_LABEL{
    //unsigned char N[MAX_MPI_IN_BYTE];
    //unsigned char E[MAX_MPI_IN_BYTE];
    unsigned char D[MAX_MPI_IN_BYTE];
    unsigned char P[KEY_LEN];
    unsigned char Q[KEY_LEN];
    unsigned char DP[KEY_LEN];
    unsigned char DQ[KEY_LEN];
    unsigned char QP[KEY_LEN];
    //unsigned int pad1;
    //unsigned int pad2;
}RSA_KEY_NO_LABEL,*RSA_KEY_NO_LABEL_PTR;
*/


typedef struct _key_rsa{

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

}key_rsa;




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
