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


.global	mtrr_fun
.global mtrr_cap_fun
.global mtrr_def_fun
.global mtrr_fixed_fun
.global set_fix
.global run_invd
.global safeCall1



#define IA32_MTRRCAP	0xFE
#define IA32_MTRR_DEF_TYPE	0x2FF
#define IA32_MTRR_PHYSBASED0	0x200	//0~9
#define IA32_MTRR_PHYSMASK0	0x201
#define IA32_MTRR_FIX64K_00000	0x250
#define IA32_MTRR_FIX16K_80000	0x258
#define IA32_MTRR_FIX16K_a0000	0x259
#define IA32_MTRR_FIX4K_C0000	0x268
#define IA32_MTRR_FIX4K_C8000	0x269
#define IA32_MTRR_FIX4K_D0000	0x26a
#define IA32_MTRR_FIX4K_D8000	0x26b
#define IA32_MTRR_FIX4K_E0000	0x26c
#define IA32_MTRR_FIX4K_E8000	0x26d
#define IA32_MTRR_FIX4K_F0000	0x26e
#define IA32_MTRR_FIX4K_F8000	0x26f


mtrr_fun://unsigned long long mtrr_fun()
prolog
push	%rbx
mov	$0x1,%rax
cpuid
//pop	%rbx
mov %rdx, %rax  // %rax, register is used for returning a value
pop	%rbx
epilog

mtrr_cap_fun://unsigned long long mtrr_cap_fun()
prolog
push	%rbx
mov	$IA32_MTRRCAP,%rcx
rdmsr
pop	%rbx
epilog

mtrr_def_fun://unsigned long long mtrr_def_fun();
prolog
push	%rbx
mov	$IA32_MTRR_DEF_TYPE,%rcx
rdmsr
pop	%rbx
epilog


mtrr_fixed_fun:          //unsigned long long mtrr_fixed_fun(unsigned int index);
prolog
push	%rbx
push	%rcx
//mov	10(%rbp),%rcx   //(decimal ~ 8 for return address + 8 for parameter), decimal 16 ~ 10 hex
mov %rdi, %rcx          //first argument is in rdi register
rdmsr
pop	%rcx
pop	%rbx
epilog

set_fix:	            //unsigned int set_fix(unsigned int value,unsigned int value2);
prolog
push	%rcx
push	%rbx
push	%rdx
push	%rax
mov	%cr4,%rax
push	%rax

//movl	8(%ebp),%ebx
//movl	12(%ebp),%ebx

//prepare
mov	%cr0,%rax	//no-fill mod
or	$0x40000000,%rax
mov	%rax,%cr0

wbinvd		//invd
//flush tlb

mov	$IA32_MTRR_DEF_TYPE,%rcx
xor	%rdx,%rdx
mov	$0x000,%rax
wrmsr

//begin set
mov	$IA32_MTRR_FIX4K_E0000,%rcx
rdmsr

mov	$IA32_MTRR_FIX4K_F0000,%rcx
//mov	8(%rbp),%rdx    // first parameter , 0x10 or %rdi
mov %rdi, %rdx
//mov	12(%rbp),%rax   // second parameter, 0x24 , or %rsi
mov	%rsi,%rax
wrmsr

mov	$IA32_MTRR_FIX4K_F8000,%rcx
//mov	8(%rbp),%rdx
mov %rdi, %rdx
//mov	12(%rbp),%rax
mov %rsi, %rax
wrmsr

//post
wbinvd
//flush tlb


mov	$IA32_MTRR_DEF_TYPE,%rcx
xor	%rdx,%rdx
mov	$0xc06,%rax
wrmsr


mov	%cr0,%rcx
and	$0x9FFFFFFF,%ecx
mov	%rcx,%cr0

pop	%rax
mov	%rax,%cr4
pop	%rax
pop	%rdx
pop	%rbx
pop	%rcx
epilog

run_invd:
prolog
wbinvd
invd
epilog


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
