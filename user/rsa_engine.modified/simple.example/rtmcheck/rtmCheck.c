#include <stdio.h>
#include <stdlib.h>
#include <immintrin.h>

int test_otherfunction(int a, int b){
    int c=0;
    for (int i=0; i<1000;i++){
        c=c+a+b;
        //printf("%d\n",c);
    }


    for (int i=0; i<1000000000;i++){
        c=c+a+b;
        //printf("%d\n",c);
    }
    // RTM did Succeeded, but after some tires

    for (int i=0; i<1000000000;i++){
        c=c+a+b;
        //printf("%d\n",c);
    }
    for (int i=0; i<1000000000;i++){
        c=c+a+b;
        //printf("%d\n",c);
    }


    return 1;
}

int main(int argc, char *argv[])
{
    int result=-1;
    unsigned status;
    while(result!=1){
        if ((status = _xbegin()) == _XBEGIN_STARTED) {
            if(test_otherfunction(1,2))
                result=1;
                _xend();
        }else{
            printf("rtmCheck: Transaction failed\n");
            printf("status is %ld\n", status);
	    printf("Trying again ...\n");
            //break;
        }
        
    }
    printf("rtmCheck : Result is %d\n", result);

    return 0;
}
