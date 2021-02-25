//
// Created by mass on 2/15/21.
//


#define KEY_LEN 128 // for 1024-bit key

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

#define RSA_N   "AEFA161902BA79F23F4F031DE9746F57" \
                "EA010F0E8957184D3694D2BD0E5FA8D4" \
                "92EC8C5C9B922112650AFBB3F3BFC661" \
                "C19679ECE37BB9D66BBBE0A8BE69E095" \
                "F74A670B87A8C46C606FDA08BEB87637" \
                "57FF42E509FC9D4B9B93D6B6C70AAF84" \
                "F2D2524527C2D5C9B31CD45882F6DDEC" \
                "988DDEE437CEF0947026D763ECC7E75F"

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
