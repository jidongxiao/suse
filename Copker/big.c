//
// Created by sourav on 2/12/21.
//

#include <stdio.h>
//#include "rsa.h"
#include "bignum.h"
int main(){

    mpi x;
    unsigned char buff[4]="abcd";
    mpi_read_binary(&x, &buff, sizeof (buff));


    return 0;
}





