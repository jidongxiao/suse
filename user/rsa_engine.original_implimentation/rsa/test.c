#include "rsa.h"

#define MAX_MOD	MAX_MPI_IN_BYTE
#define MAX_MPI_IN_BYTE 256

// RSA public keypair
//unsigned char *RSA_N ="D25602401B019BE192561B2C8C2A4D7C8B28E0DAA0F71A78E30F598C2A5065C3F8327D71C9B53A9FD778F74F92670F2E15F72F3926511D8B676662E6DE2A793F4AF03A26A1CB3074CDAB8596B4705282C22DDD97BFC3832909B32E215BDA49C116861790FA186B4AA62DD510A298FC31F8C00F23E961E85999C2A96B2F914062EF8FF121BC5C4C8F7B2EEBC3057694D75480646B0CD3F66855E459E44BC9833012FE7F267611E1771C618698C84A3EDB090278AAF81DD3B0D9299D2A0BFBACF4AA74915B37189D5989011C289ABDABE9173401A9C99E01FA2EDEC58FB22EB56531E9AECEF8C1EEDD4771C87C87A680B97D16E224E3F98F6D32D2DD2AEBE4FB91";
//unsigned char *RSA_E =  "10001";

typedef struct _key_rsa{
     unsigned char N[MAX_MPI_IN_BYTE];
     unsigned char E[MAX_MPI_IN_BYTE];
}key_rsa;


static int public_key_computation(unsigned char *inout, key_rsa key){
       int j,ret = 1;
       rsa_context rsa;    
       rsa_init(&rsa,RSA_PKCS_V15, 0); 

       printf("public_key_computation: key.N contains\n %s\n", key.N);

       mpi_read_binary(&rsa.N,key.N,sizeof(key.N)); 
       printf("Inside doAll: rsa.N contains %s\n", rsa.N);

       return ret ;   
}


void main(){

     int result,j;
     result = -1;
     unsigned char mes[MAX_MOD] = {1,2,3,4,5,0}; 
     unsigned char in[MAX_MPI_IN_BYTE];
     memcpy(in,mes,MAX_MPI_IN_BYTE);
     key_rsa test={RSA_N,RSA_E};
     result = public_key_computation(in,test);
}
