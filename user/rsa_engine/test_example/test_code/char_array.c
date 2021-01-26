//
// Created by sourav on 1/22/21.
//

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>

# define SIZE 20
# define CACHE_STACK_SIZE 100

static struct test{
    unsigned char in[SIZE];
    unsigned char out[SIZE];
    unsigned char cachestack[CACHE_STACK_SIZE];
}teststruct;

int func2 (struct test *test_func2){
    printf("Inside func2 function\n");
    //printf("Inside func2, address of test_func2 is : %x\n", &test_func2);
    printf("Inside func2, msg is : %s\n", test_func2->in);
    return 1;
}

//void func1( struct test *test_func1, int (*f)(struct test *)){
void func1( void *test_func1, int (*f)(struct test *), unsigned char *stackbottom){
    //printf("Inside func1, msg is:  %s\n", &test_func1->in);
    printf("Inside func1, msg is:  %s\n", ((struct test *)test_func1)->in);

    // calling function
    (*f)(test_func1);

}


void func3( void *test_func3, int (*f)(struct test *), unsigned char *stackbottom){
    //printf("Inside func1, msg is:  %s\n", &test_func1->in);
    //printf("Inside func1, msg is:  %s\n", test_func1->in);
    printf("Inside func3, msg is:  %s\n", ((struct test *)test_func3)->in);

    // calling function
    //(*f)(test_func3);


///*
    // creating a stack

    //creating the original stack switch function
    u_int64_t base, rsp, base1, rsp1;
    asm volatile(

    // store original rsp into the red-zone
    //"mov %%rbp, %0 \t\n"
    //"movq %%rsp, %1 \t\n"

    //prologue
    "pushq %%rbp \t\n"
    //"mov %%rbp, %2 \t\n"

    "movq %%rsp, %%rbp \t\n" // can't modify rbp without clobber register.
    //"mov %%rbp, %3 \t\n"

    // create space for stackswitch function parameter. rax now point to the stack bottom
    // ok, So, 16(%%rbp) --> point to the *stackbottom. When we move 16(%%rbp)--> rax, rax is now point to stack bottom.
    //"mov 32(%%rbp), %%rax\t\n"
    "movq 16(%%rbp), %%rax\t\n"

    //save system rbp on the new stack.
    // creating new stack. Setting rbp.
    "movq %%rbp, (%%rax)\t\n"

    //save system rsp on the new stack
    // setting rsp to the new stack
    "movq %%rbp, -8(%%rax)\t\n"

    //rbx now point to the old rbp
    // rbx --> point to the original stack rbp
    "movq %%rbp, %%rbx\t\n"

    // Create new stack frame
    "movq %%rax, %%rbp\t\n"
    "movq %%rax, %%rsp\t\n"

    // pointing to rsp, from previous line, movq %%rbp, -8(%%rax)
    //"sub $8, %%rsp\t\n"
    "subq $8, %%rsp\t\n"

    // create parameter for decryption function
    //"pushq 16(%%rbx)\t\n"
    //"pushq 32(%%rbx)\t\n"
    "movq 32(%%rbx), %%rdx\t\n"
    //"movq 24(%%rbx), %%rax\t\n" // Extra, if works, need to save rax and pop later
    "movq %%rdx, %%rdi\t\n"

    //call decryption function
    //"call 24(%%rbx)\t\n"
    "call 24(%%rbx)\t\n"
    //"call %%rax\t\n"



    // returning to the original stack
    "movq %%rbp, %%rbx\t\n"
    "movq (%%rbx), %%rbp\t\n"
    "movq -8(%%rbx), %%rsp\t\n"

    "leave\t\n"
    "ret \t\n"


    //"pop %%rbp"
    :"=r"(base), "=r"(rsp),"=r"(base1), "=r"(rsp1)
    :
    :"rax","rbx","rbp"
    );
    printf("Before: Base register %x\n", base);
    //printf("Before: stack pointer register %x\n", rsp);
    printf("After: (Should be same as previous )Base register %x\n", base1);
    printf("After: (Actually %rsp-8)Base register %x\n", rsp1);

//*/

/*
    // creating a stack

    //32-bit creating the original stack switch function
    u_int32_t base, rsp, base1, rsp1;
    asm volatile(

    // store original rsp into the red-zone
    //"mov %%rbp, %0 \t\n"
    "movl %%esp, %1 \t\n"

    //prologue
    "pushl %%ebp \t\n"
    //"mov %%rbp, %2 \t\n"

    "movl %%esp, %%ebp \t\n" // can't modify rbp without clobber register.
    //"mov %%rbp, %3 \t\n"

    // create space for stackswitch function parameter. rax now point to the stack bottom
    //"mov 32(%%rbp), %%rax\t\n"
    "movl 22(%%ebp), %%eax\t\n"

    //save system rbp on the new stack
    "movl %%ebp, (%%eax)\t\n"

    //save system rsp on the new stack
    "movl %%ebp, -4(%%eax)\t\n"

    //rbx now point to the old rbp
    "movl %%ebp, %%ebx\t\n"

    // Create new stack frame
    "movl %%eax, %%ebp\t\n"
    "movl %%eax, %%esp\t\n"
    //"sub $8, %%rsp\t\n"
    "subl $4, %%esp\t\n"

    // create parameter for decryption function
    "pushl 8(%%ebx)\t\n"
    //"pushq 8(%%rbx)\t\n"

    //call decryption function
    //"call 24(%%rbx)\t\n"
    "call 12(%%ebx)\t\n"



    // returning to the original stack
    "movl %%ebp, %%ebx\t\n"
    "movl (%%ebx), %%ebp\t\n"
    "movl -4(%%ebx), %%esp\t\n"

    "leave\t\n"
    "ret \t\n"


    //"pop %%rbp"
    :"=r"(base), "=r"(rsp),"=r"(base1), "=r"(rsp1)
    :
    :"eax","ebx","ebp"
    );
    printf("Before: Base register %x\n", base);
    printf("Before: stack pointer register %x\n", rsp);
    printf("After: (Should be same as previous )Base register %x\n", base1);
    printf("After: (Actually %rsp-8)Base register %x\n", rsp1);

*/


}



int main(){

    struct test test_main;

    memcpy(teststruct.in,"This is test ", sizeof(teststruct.in));

    //copying
    test_main=teststruct;

    //check values
    printf("test_main.in is: %s\n", test_main.in);


    // calling stackswitch function
    //func1(&test_main,func2, test_main.cachestack+CACHE_STACK_SIZE-8);
    func3(&test_main,func2, test_main.cachestack+CACHE_STACK_SIZE-8);


}