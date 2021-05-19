#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

/* single global variable */
/* shared, accessible, modifiable by all threads */
int accum = 0;

void test(){

	char cmdbuf[256];
 	snprintf(cmdbuf, sizeof(cmdbuf), "sudo openssl rsautl -decrypt -inkey private.pem -in msg.enc -engine rsa-engine-new:%s %s", "1234");
 	int err = system(cmdbuf);
 	if (err) { 
		fprintf(stderr, "failed to %s\n", cmdbuf); 
            	exit(EXIT_FAILURE); 
	}



	//printf("Test thread\n");
	//int status = system("sudo openssl rsautl -decrypt -inkey private.pem -in msg.enc -engine rsa-engine-new");
}


int main(int argc, char** argv) {
    int i;
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
    return 0;
}

