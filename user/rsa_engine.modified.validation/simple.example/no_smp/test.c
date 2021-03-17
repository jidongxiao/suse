#include<stdio.h>
#include<stdlib.h>

int main(){

	int ret =0;
	int r=0;
	unsigned long flags;

	int ARR_LEN=10;
 	int STEP_SIZE=1;
	int SOME_VALUE=1;
  	int arr[ARR_LEN];

  	//long* arr = malloc(20*sizeof(int));

  	int i;
  	__asm__ __volatile__(
    		"loop:"
    		"movq %%rdx, (%%rbx);"
    		"leaq (%%rbx, %%rcx, 8), %%rbx;"
    		"cmpq %%rbx, %%rax;"
    		"jg loop;"
    		: // no output
    		: "b" (arr),
      		  "a" (arr+ARR_LEN),
      		  "c" (STEP_SIZE),
      		  "d" (SOME_VALUE)
    		: "cc", "memory"
  	);

  	for (i=0; i<ARR_LEN; i++){
    		printf("arr[%d] is %d\n", i, arr[i]);
  	}



	return 0;
}
