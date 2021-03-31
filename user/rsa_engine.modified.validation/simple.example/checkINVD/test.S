.file "test_asm.S"

.macro prolog
push	%rbp
mov	%rsp,%rbp
.endm

.macro epilog
leave
ret
.endm

.text

.global safeCall1

//int safeCall1(void *para0,void *fun, void *newStack); para: para0 point to a struct para, fun to to be called funtion, newStack is the new stack
safeCall1:
prolog
push	%rbx
//mov	16(%rbp),%rax	//rax->new stack top
mov %rdx, %rax // %rdx contain the third parameter -->new stack top


//constuct new stack and save rsp rbp ret
mov	%rbp,(%rax)	//save rbp
mov	%rsp,-8(%rax)	//save rsp
mov	%rbp,%rbx	//ebx->old ebp

mov	%rax,%rbp	//ebp ->  new stack top
mov	%rax,%rsp
sub	$40,%rsp		//esp

//push	8(%ebx)		//para0
//call	12(%ebx)	//fun

//mov 32(%rbx), %rdx    // do not need this because, 1st parameter is already in %rdi
//mov %rdx, %rdi

call %rsi // 2nd parameter (call do_All function)

//restore stack, common
mov	%rbp,%rbx
mov	(%rbx),%rbp
mov	-8(%rbx),%rsp
pop	%rbx
//popf
//popa

epilog

