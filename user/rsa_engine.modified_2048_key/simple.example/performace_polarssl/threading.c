#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

// Total number of Thread
#define NUM_OF_THREAD 1

int dec_counter =0;
int counter =0;
pthread_mutex_t lock;

void test(){
	printf("Test thread\n");
    pthread_mutex_lock(&lock);

    unsigned long i = 0;
    counter += 1;
    printf("\n Job %d has started\n", counter);

    time_t endwait;
    time_t start = time(NULL);
    time_t seconds = 5; // end loop after this time has elapsed
    endwait = start + seconds;

    while (start < endwait){
            start = time(NULL);
            // expect_script(ans.sh) will spawn run script (where I will call the openssl engine). Then add the ans script for password.
            system("./rsa_decrypt");
            dec_counter++;
    }
    printf("\n Job %d has finished\n", counter);

    pthread_mutex_unlock(&lock);
    //printf("\n Total decryption %d\n", dec_counter);
}


int main(int argc, char** argv) {
    int i;
    clock_t t;

    // total number of thread
    pthread_t ths[NUM_OF_THREAD];

    // start time count
    t = clock();

    // initialize lock
    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }

    for (i = 0; i < NUM_OF_THREAD; i++) {
        pthread_create(&ths[i], NULL, test, NULL);
    }

    for (i = 0; i < NUM_OF_THREAD; i++) {
        void* res;
        pthread_join(ths[i], &res);
    }

    // release lock
    pthread_mutex_destroy(&lock);

    printf("\n Total decryption %d\n", dec_counter);

    // end time count
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds
    printf("Took %f seconds to execute \n", time_taken);
    printf("Total Cycle %f  \n", t);

    return 0;
}

