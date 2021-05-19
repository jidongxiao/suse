/* 
 * WHAT THIS EXAMPLE DOES
 * 
 * We create a pool of 4 threads and then add 40 tasks to the pool(20 task1 
 * functions and 20 task2 functions). task1 and task2 simply print which thread is running them.
 * 
 * As soon as we add the tasks to the pool, the threads will run them. It can happen that 
 * you see a single thread running all the tasks (highly unlikely). It is up the OS to
 * decide which thread will run what. So it is not an error of the thread pool but rather
 * a decision of the OS.
 * 
 * */



// compile : 
// gcc example.c thpool.c -D THPOOL_DEBUG -pthread -o example


#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include "thpool.h"
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


int counter =0;

void task(){
	//printf("Thread #%u working on %d\n", (int)pthread_self(), (int) arg);
	
	int status = system("./ans.sh");
	counter++;
    	
	printf("Current Count is %d\n", counter);
}


int main(){


	time_t endwait;
 	time_t start = time(NULL);
    	time_t seconds = 100; // end loop after this time has elapsed

	endwait = start + seconds;

	
	puts("Making threadpool with 4 threads");
	threadpool thpool = thpool_init(8);

	//puts("Adding 40 tasks to threadpool");
	//int i;
	//for (i=0; i<40; i++){
	//	thpool_add_work(thpool, task, (void*)(uintptr_t)i);
	//};


	// running loop for a specific time
	while (start < endwait){
        	/* Do stuff while waiting */
        	//sleep(1);   // sleep 1s.
        	start = time(NULL);
        	//printf("loop time is : %s", ctime(&start));
		thpool_add_work(thpool, task, NULL);
	
        }



	thpool_wait(thpool);
	puts("Killing threadpool");
	thpool_destroy(thpool);

	printf("Total Decryption is %d\n", counter);
	
	return 0;
}
