#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

/* single global variable */
/* shared, accessible, modifiable by all threads */
int accum = 0;

void test(){

	printf("Test thread\n");
	// or call the expect script from here
	// expect script will spawn Question bash script (where I will call the openssl engine). Then add the Question for password.
	// answer
	//int status = system("sudo openssl rsautl -decrypt -inkey private.pem -in msg.enc -engine rsa-engine-new");
    int status = system("./ans.sh");
    printf("%d", status);
}


int main(int argc, char** argv) {
    int i;

    //*
    pthread_t ths[20];
    for (i = 0; i < 20; i++) {
	printf("Inside pthread_create i=%d\n",i);
        //pthread_create(&ths[i], NULL, square, (void*)(i + 1));
	pthread_create(&ths[i], NULL, test, NULL);
	printf("Inside pthread_create ends i=%d\n",i);
    }

    for (i = 0; i < 20; i++) {
        void* res;
	    printf("Inside pthread_join i=%d\n",i);
        pthread_join(ths[i], &res);
	    printf("Inside pthread_create endsi=%d\n",i);
    }

    printf("accum = %d\n", accum);
//*/

/*
    // test
    for (i = 0; i < 20; i++) {
        int status = system("./ans.sh");
        printf("%d", status);
    }
*/




    return 0;
}

