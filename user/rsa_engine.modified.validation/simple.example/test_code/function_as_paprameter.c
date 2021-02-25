//
// Created by sourav on 1/19/21.
//
#include <stdio.h>

typedef struct test{
    int a;
    int b;
}test;

void printNumber(int nbr, struct test *test){
    printf("nbr Is %d\n", nbr);

    printf("Printing from structure a is: %d\n", &test->a);
    printf("Printing from structure b is: %d\n", &test->b);
}

//void myFunction(void (*f)(int)){
//void myFunction( struct test *test, void (*f)(int, struct test)){
void myFunction( struct test *test, void (*f)(int, struct test)){
    for(int i = 0; i < 5; i++){
        //(*f)(i);
        test->a=i+1;
        test->b=i+2;
        //*(int *)test.
        (*f)(i, *test);
    }
}


void void_pointer(void *t1){
    printf("Inside void_pointer, i is %d\n", ((test *)t1)->a);
}

int main(void){

    //test1 an;
    test test2;
    test test1={3,4};

    test2=test1;
    printf("test2.a %d\n", test2.a);
    //exit(0);

    //myFunction(&test2,printNumber);

    void_pointer(&test2);

    return (0);
}