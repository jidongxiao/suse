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
    //(*f)(test_func1);

    //calling with stack
    //creating the original stack switch function
    asm volatile(

    //prologue
    "pushq %%rbp \t\n"
    //"mov %%rbp, %2 \t\n"

    "movq %%rsp, %%rbp \t\n" // can't modify rbp without clobber register.
    //"mov %%rbp, %3 \t\n"

    // create space for stackswitch function parameter. rax now point to the stack bottom
    // ok, So, 16(%%rbp) --> point to the *stackbottom. When we move 16(%%rbp)--> rax, rax is now point to stack bottom.
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
    "subq $40, %%rsp\t\n"

    // create parameter for decryption function
    //"pushq 32(%%rbx)\t\n"
    "movq 32(%%rbx), %%rdx\t\n"
    "movq %%rdx, %%rdi\t\n"

    //call decryption function
    "call 24(%%rbx)\t\n"

    // returning to the original stack
    "movq %%rbp, %%rbx\t\n"
    "movq (%%rbx), %%rbp\t\n"
    "mov -8(%%rbx), %%rsp\t\n"

    "leave\t\n"
    //"ret \t\n"

    :
    :
    :"rax","rbx","rbp"
    );

}


void func3( void *test_func3, int (*f)(struct test *), unsigned char *stackbottom){
    //printf("Inside func1, msg is:  %s\n", &test_func1->in);
    //printf("Inside func1, msg is:  %s\n", test_func1->in);
    printf("Inside func3, msg is:  %s\n", ((struct test *)test_func3)->in);

    // calling function
    (*f)(test_func3);




}



int main(){

    struct test test_main;

    memcpy(teststruct.in,"This is test ", sizeof(teststruct.in));

    //copying
    test_main=teststruct;

    //check values
    printf("test_main.in is: %s\n", test_main.in);


    // calling stackswitch function
    func1(&test_main,func2, test_main.cachestack+CACHE_STACK_SIZE-8);
    //func3(&test_main,func2, test_main.cachestack+CACHE_STACK_SIZE-8);


}