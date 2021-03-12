.file "test_asm.S"

.macro prolog
push	%rbp
mov	%rsp,%rbp
.endm

.macro epilog
leave
ret
.endm

.data
msg:	.ascii	"from asm\0"

.text
.global	getData
//.global	_jiecheng
.global	getCR0
//.global disCache
//.global enaCache
.global enter_no_stack
.global restore_no_stack
.global safeCall
.global safeCall1
.global prepareMemAndDisCache
.global flushMemTest
.global readAddr
.global readAddrInv
.global	testStackSpeed
.global rdtscTime
.global readCompare
.global invd_t
.global enter_no_fill
.global exit_no_fill
.global	mtrr_fun
.global	mtrr_cap_fun
.global mtrr_def_fun
.global mtrr_def_set_fun
.global mtrr_fixed_fun
//.global gl_clflush_cache_range 
.global set_fix
.global readMem
.global writeMem


//wrmsr		EDX:EAX->MSR(ECX)
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



set_fix:	//unsigned int set_fix(unsigned int value,unsigned int value2);
prolog
push	%ecx
push	%ebx
push	%edx
push	%eax
mov	%cr4,%eax
push	%eax

//movl	8(%ebp),%ebx
//movl	12(%ebp),%ebx

//prepare
mov	%cr0,%eax	//no-fill mod
or	$0x40000000,%eax
mov	%eax,%cr0

wbinvd		//invd
//flush tlb

mov	$IA32_MTRR_DEF_TYPE,%ecx
xor	%edx,%edx
mov	$0x000,%eax
wrmsr

//begin set
mov	$IA32_MTRR_FIX4K_E0000,%ecx
rdmsr

//andl	$0xFFFFFF00,%eax
//orl	%ebx,%eax
/*
mov	$IA32_MTRR_FIX4K_E0000,%ecx
mov	8(%ebp),%edx
mov	12(%ebp),%eax
wrmsr

mov	$IA32_MTRR_FIX4K_E8000,%ecx
mov	8(%ebp),%edx
mov	12(%ebp),%eax
wrmsr
*/
mov	$IA32_MTRR_FIX4K_F0000,%ecx
mov	8(%ebp),%edx
mov	12(%ebp),%eax
wrmsr

mov	$IA32_MTRR_FIX4K_F8000,%ecx
mov	8(%ebp),%edx
mov	12(%ebp),%eax
wrmsr



//post
wbinvd
//flush tlb



mov	$IA32_MTRR_DEF_TYPE,%ecx
xor	%edx,%edx
mov	$0xc06,%eax
wrmsr


mov	%cr0,%ecx
and	$0x9FFFFFFF,%ecx
mov	%ecx,%cr0

pop	%eax
mov	%eax,%cr4
pop	%eax
pop	%edx
pop	%ebx
pop	%ecx
epilog



mtrr_fun://unsigned long long mtrr_fun()
prolog
push	%ebx
mov	$0x1,%eax
cpuid
pop	%ebx
epilog


mtrr_cap_fun://unsigned long long mtrr_cap_fun()
prolog
push	%ebx
mov	$IA32_MTRRCAP,%ecx
rdmsr
pop	%ebx
epilog


mtrr_def_fun://unsigned long long mtrr_def_fun();
prolog
push	%ebx
mov	$IA32_MTRR_DEF_TYPE,%ecx
rdmsr
pop	%ebx
epilog

mtrr_def_set_fun://unsigned long long mtrr_def_set_fun();
prolog
push	%ebx
mov	$IA32_MTRR_DEF_TYPE,%ecx
xor	%edx,%edx
mov	$0xc06,%eax
wrmsr
pop	%ebx
epilog


mtrr_fixed_fun://unsigned long long mtrr_fixed_fun(unsigned int index);
prolog
push	%ebx
push	%ecx

mov	8(%ebp),%ecx
rdmsr

pop	%ecx
pop	%ebx
epilog



add:
prolog
push	%ebx
mov	8(%ebp),%eax
add	12(%ebp),%eax
add	$100,%eax
mov	16(%ebp),%ebx
mov	%eax,(%ebx)
pop	%ebx
epilog

enter_no_fill:
prolog
mov	%cr0,%eax	//no-fill mod
or	$0x40000000,%eax
mov	%eax,%cr0
epilog


exit_no_fill:
prolog

mov	%cr0,%ecx
and	$0x9FFFFFFF,%ecx
mov	%ecx,%cr0
epilog

invd_t:
prolog
push	%ebx
push	%ecx
mov	8(%ebp),%eax

mov	$0x12,%ebx
wbinvd
mfence
sfence
lfence
//movl	(%eax),%ecx
mov	%ebx,(%eax)

//invd
//mfence

pop	%ecx
pop	%ebx
epilog



//int safeCall1(void *para0,void *fun, void *newStack); para: para0 point to a struct para, fun to to be called funtion, newStack is the new stack
safeCall1:
prolog
//pusha
//pushf
push	%ebx
mov	16(%ebp),%eax	//eax->new stack top

//constuct new stack and save esp ebp ret
mov	%ebp,(%eax)	//save ebp
mov	%esp,-4(%eax)	//save esp
mov	%ebp,%ebx	//ebx->old ebp

mov	%eax,%ebp	//ebp ->  new stack top
mov	%eax,%esp	
sub	$4,%esp		//esp

push	8(%ebx)		//para0
call	12(%ebx)	//fun

//restore stack, common
mov	%ebp,%ebx
mov	(%ebx),%ebp
mov	-4(%ebx),%esp
pop	%ebx
//popf
//popa

epilog

//safeCall(int para1,int para2,int *para3,void *newStack); para point to int int and int *
safeCall:
prolog
mov	20(%ebp),%eax	//new stack address,eax 		4*4 + 4,change

//constuct new stack and save esp ebp ret


mov	%ebp,(%eax)	//save ebp
mov	%ebx,-4(%eax)	//save ebx

mov	%ebp,%ebx	//ebx->old statck

mov	%eax,%ebp
sub	$4,%ebp
mov	%ebp,%esp		//esp -> saved ebx; ebp ->  saved ebx


push	16(%ebx)		//para3				change according to paras
push	12(%ebx)		//para2		
push	8(%ebx)			//prar1	
//pushl	$3		//para3				change according to paras
//pushl	$2		//para2		
//pushl	$1		//prar1		
//call	add1

//restore stack, common
mov	%ebp,%esp	///esp -> saved ebx; ebp ->  saved ebx

pop	%ebx
pop	%ebp
////movl	%esp,%ebx
////movl	(%ebx),%esp
//movl	(%esp),%esp
//movl	%ebp,%esp
mov	20(%ebp),%eax
epilog


/*int enter_no_stack(void *)*/
enter_no_stack:
mov	(%esp),%eax	//ret address
mov	4(%esp),%ebx	//new stack address
//constuct new stack
mov	%esp,(%ebx)	//save esp
mov	%ebp,-4(%ebx)	//save ebp
mov	%eax,-8(%ebx)	//ret add

mov	%ebx,%ebp
mov	%ebx,%esp
sub	$4,%ebp
sub	$8,%esp		//esp -> ret address; ebp -> saved esp
ret


/*void restore_no_stack()*/
restore_no_stack:
pop	%eax		//ret address
pop	%ebp
mov	%esp,%ebx
mov	(%ebx),%esp
mov	%eax,(%esp)
ret


/*char* getData(void)*/
getData:
prolog
mov	$msg,%eax
epilog

/*unsigned int getCR0(void)*/
getCR0:
prolog
mov	%cr0,%eax
epilog

/*unsigned int readMem(void *p,int size)*/
readMem:
prolog
push %esi
push %ecx
mov 8(%ebp),%esi
cld
mov	12(%ebp),%ecx
rep lodsl
pop %ecx
pop %esi
epilog


/*unsigned int writeMem(void *p,int size)*/
writeMem:
prolog
push %edi
push %ecx
mov 8(%ebp),%edi
cld
mov	12(%ebp),%ecx
xor %eax,%eax
rep stosl
pop %ecx
pop %edi
epilog






/*unsigned int flushMemTest(unsigned char *base,int size)*/
flushMemTest:
prolog
pushl %esi
pushl %edi
pushl %ecx

cld
mov	8(%ebp), %esi
mov	12(%ebp), %ecx
shr	$6,%ecx

mfence
loopstart:

clflush	(%esi)
add	$64,%esi
dec	%ecx
jnz	loopstart
mfence

pop %ecx
pop %edi
pop %esi

epilog


/*unsigned int prepareMemAndDisCache(unsigned char *base,int size)	return cr0*/ 
prepareMemAndDisCache:
prolog
push %esi
push %ebx
push %edi
push %ecx


mov	%cr0,%eax	//normal mode
and	$0x9FFFFFFF,%eax
mov	%eax,%cr0


cld		//fill cache with 0x12345678
mov	8(%ebp), %edi
mov	12(%ebp), %ecx
shr	$2,%ecx
mov	$0xFFFFFFFF,%eax
rep	stosl

wbinvd


mov	8(%ebp), %esi
mov	12(%ebp), %ecx

cld		//validate cache with mem access
shr	$2,%ecx
rep	lodsl

/*



cld		//fill cache with 0x12345678
mov	8(%ebp), %edi
mov	12(%ebp), %ecx
shr	$2,%ecx
mov	$0x00000000,%eax
rep	stosl

push	$0x3
mov	8(%ebp),%edi
//call	_jiecheng
mov	%eax,(%edi)
add	$4,%esp

*/
//movl	%cr0,%eax	//no-fill mod
//orl	$0x40000000,%eax
//movl	%eax,%cr0

pop %ecx
pop %edi
pop %ebx
pop %esi

epilog


/*void disCache(void *)
disCache:
prolog
push	%eax
mov	%cr0,%eax	//no-fill mod
or	$0x40000000,%eax
mov	%eax,%cr0

wbinvd
pop	%eax
epilog

*/
/*void enaCache(void *)
enaCache:
prolog
push	%eax
mov	%cr0,%eax
and	$0x9FFFFFFF,%eax
mov	%eax,%cr0
pop	%eax
epilog
*/
//unsigned int readAddr(unsigned char *mem)
readAddr:
prolog
push	%edx
push	%ebx
push	%edi

rdtsc
rdtsc
rdtsc
wbinvd

cld		//refill
mov	8(%ebp), %edi
mov	$1024, %ecx
rep	stosl

cld		//refill
mov	8(%ebp), %edi
mov	$1024, %ecx
rep	stosl

cld		//refill
mov	8(%ebp), %edi
mov	$1024, %ecx
rep	stosl

//movl	%cr0,%eax	//no-fill mod
//orl	$0x40000000,%eax
//movl	%eax,%cr0

mov	8(%ebp),%edi
mov	$1, %ecx

cld
rdtsc
mov	%eax,%ebx
rep	stosl
rdtsc
sub	%ebx,%eax

mov	%eax,%ebx
//wbinvd
//call	enaCache
mov	%ebx,%eax

pop	%edi
pop	%ebx
pop	%edx
epilog


//unsigned int readAddrInv(unsigned char *mem)
readAddrInv:
prolog
push	%edx
push	%ebx
push	%edi

rdtsc
rdtsc
rdtsc

mov	8(%ebp),%edi
mov	$1, %ecx
wbinvd
wbinvd
wbinvd


cld
rdtsc
mov	%eax,%ebx
rep	stosl
rdtsc
sub	%ebx,%eax

pop	%edi
pop	%ebx
pop	%edx
epilog


//unsigned int rdtscTime(void);

rdtscTime:
prolog
push	%ebx
push	%ecx


rdtsc
lfence
mov	%eax,%ebx

rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence
rdtsc
lfence



rdtsc
lfence
sub	%ebx,%eax

pop	%ecx
pop	%ebx
epilog

/*
rdtscTime:
prolog
pushl	%ebx
pushl	%ecx
pushl	%edx

rdtsc
movl	%eax,%ebx

movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
movl	%ecx,%edx
movl	%edx,%ecx
rdtsc
subl	%ebx,%eax

popl	%edx
popl	%ecx
popl	%ebx
epilog

*/


//unsigned int testStackSpeed(unsigned int *sp)
testStackSpeed:
prolog
push	%ebx
push	%ecx
push	%edx
push	%edi


mov	8(%ebp),%edx
mov	%esp,(%edx)

mov	%esp,%ebx
rdtscp
mov	%eax,%edi
mov	(%ebx),%edx
lfence
mov	-64(%ebx),%edx
lfence
mov	-2*64(%ebx),%edx
lfence
mov	-3*64(%ebx),%edx
lfence
mov	-4*64(%ebx),%edx
lfence
mov	-5*64(%ebx),%edx
lfence
mov	-6*64(%ebx),%edx
lfence
mov	-7*64(%ebx),%edx
lfence
rdtscp
sub	%edi,%eax




pop	%edi
pop	%edx
pop	%ecx
pop	%ebx
epilog

//unsigned int testSpeed(unsigned char *mem)
testSpeed:
prolog
push	%ebx
push	%ecx
push	%edx
push	%edi

mov	8(%ebp),%ebx
rdtsc
lfence
mov	%eax,%edi
mov	(%ebx),%edx
lfence
mov	64(%ebx),%edx
lfence
mov	2*64(%ebx),%edx
lfence
mov	3*64(%ebx),%edx
lfence
mov	4*64(%ebx),%edx
lfence
mov	5*64(%ebx),%edx
lfence
mov	6*64(%ebx),%edx
lfence
mov	7*64(%ebx),%edx
lfence
rdtsc
lfence
sub	%edi,%eax

pop	%edi
pop	%edx
pop	%ecx
pop	%ebx
epilog



/*
//unsigned int readCompare(unsigned char *mem,unsigned int *time1,unsigned int *time2,unsigned int *time3);
readCompare:
prolog
pushl	%edx
pushl	%ebx
pushl	%edi
pushl	%ecx
xchgl	%edx,%ecx
mfence

call rdtscTime


//clflush	8(%ebp)
call rdtscTime
call rdtscTime
mfence
movl	8(%ebp),%ecx


//clflush	8(%ebp)
//clflush	72(%ebp)
mfence

//pushl	$1024
pushl	$128
pushl	%ecx
//call	flushMemTest
//call	gl_clflush_cache_range
//wbinvd
addl	$8,%esp


movl	8(%ebp),%ecx


//timeA
pushl	%ecx
call	testSpeed
addl	$4,%esp
movl	12(%ebp),%ebx
movl	%eax,(%ebx)



movl	%cr0,%eax	//no-fill mod
orl	$0x40000000,%eax
movl	%eax,%cr0



//timeB
pushl	%ecx
call	testSpeed
addl	$4,%esp
movl	16(%ebp),%ebx
movl	%eax,(%ebx)

//timeC
pushl	$1024
pushl	%ecx
//call	clflush_cache_range
//call	flushMemTest
wbinvd
addl	$8,%esp

movl	8(%ebp),%ecx

pushl	%ecx
call	testSpeed
addl	$4,%esp
movl	20(%ebp),%ebx
movl	%eax,(%ebx)

call rdtscTime

movl	%cr0,%ecx
andl	$0x9FFFFFFF,%ecx
movl	%ecx,%cr0



popl	%ecx
popl	%edi
popl	%ebx
popl	%edx
epilog
*/
