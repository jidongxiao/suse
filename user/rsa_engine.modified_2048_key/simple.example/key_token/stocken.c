#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// working
/*
int main () {
   //char str[80] = "This is - www.tutorialspoint.com - website";
   const char s[3] = "= ";
   char *token;

    unsigned char * buffer = 0;
    long length;
    FILE * fp = fopen ("rsa_priv.txt", "rb");

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


   
   // get the first token
   token = strtok(buffer, s);
    printf( " first token %s\n", token );
   
   // walk through other tokens
   while( token != NULL ) {
      printf( " %s\n", token );
    
      token = strtok(NULL, s);
   }
   
   return(0);
}
*/

int main () {

    unsigned char * buffer = 0;
    long length;
    FILE * fp = fopen ("rsa_priv.txt", "rb");

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

    printf("Final Decrypted private key is --> \n %s \n", buffer);

    // tokenize key and read into rsa context
    const char s[3] = "= \n";
    char *token;
    int k=0;

    // get the first token
    token = strtok(buffer, s);

    // walk through other tokens
    while( token != NULL ) {

        if(k==1){
            printf( "token id %d, %s\n", k, token );
        }
        if(k==3){
            printf( "token id %d, %s\n", k, token );
        }
        if(k==5){
            printf( "token id %d, %s\n", k, token );
        }
        if(k==7){
            printf( "token id %d, %s\n", k, token );
        }
        if(k==9){
            printf( "token id %d, %s\n", k, token );
        }
        if(k==11){
            printf( "token id %d, %s\n", k, token );
        }
        if(k==13){
            printf( "token id %d, %s\n", k, token );
        }
        if(k==15){
            printf( "token id %d, %s\n", k, token );
        }

        int size = strlen(token);
        //printf( "token id %d, size if the token is %d, token is %s\n", k, size,token );

        k=k+1;
        token = strtok(NULL, s);
    }




    return(0);
}