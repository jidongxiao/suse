.file "test_asm.S"

.macro prolog
pushl	%ebp
movl	%esp,%ebp
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
pushl	%ecx
pushl	%ebx
pushl	%edx
pushl	%eax
movl	%cr4,%eax
pushl	%eax

//movl	8(%ebp),%ebx
//movl	12(%ebp),%ebx

//prepare
movl	%cr0,%eax	//no-fill mod
orl	$0x40000000,%eax
movl	%eax,%cr0

wbinvd		//invd
//flush tlb

movl	$IA32_MTRR_DEF_TYPE,%ecx
xorl	%edx,%edx
movl	$0x000,%eax
wrmsr

//begin set
movl	$IA32_MTRR_FIX4K_E0000,%ecx
rdmsr

//andl	$0xFFFFFF00,%eax
//orl	%ebx,%eax
/*
movl	$IA32_MTRR_FIX4K_E0000,%ecx
movl	8(%ebp),%edx
movl	12(%ebp),%eax
wrmsr

movl	$IA32_MTRR_FIX4K_E8000,%ecx
movl	8(%ebp),%edx
movl	12(%ebp),%eax
wrmsr
*/
movl	$IA32_MTRR_FIX4K_F0000,%ecx
movl	8(%ebp),%edx
movl	12(%ebp),%eax
wrmsr

movl	$IA32_MTRR_FIX4K_F8000,%ecx
movl	8(%ebp),%edx
movl	12(%ebp),%eax
wrmsr



//post
wbinvd
//flush tlb



movl	$IA32_MTRR_DEF_TYPE,%ecx
xorl	%edx,%edx
movl	$0xc06,%eax
wrmsr


movl	%cr0,%ecx
andl	$0x9FFFFFFF,%ecx
movl	%ecx,%cr0

popl	%eax
movl	%eax,%cr4
popl	%eax
popl	%edx
popl	%ebx
popl	%ecx
epilog



mtrr_fun://unsigned long long mtrr_fun()
prolog
pushl	%ebx
movl	$0x1,%eax
cpuid
popl	%ebx
epilog


mtrr_cap_fun://unsigned long long mtrr_cap_fun()
prolog
pushl	%ebx
movl	$IA32_MTRRCAP,%ecx
rdmsr
popl	%ebx
epilog


mtrr_def_fun://unsigned long long mtrr_def_fun();
prolog
pushl	%ebx
movl	$IA32_MTRR_DEF_TYPE,%ecx
rdmsr
popl	%ebx
epilog

mtrr_def_set_fun://unsigned long long mtrr_def_set_fun();
prolog
pushl	%ebx
movl	$IA32_MTRR_DEF_TYPE,%ecx
xorl	%edx,%edx
movl	$0xc06,%eax
wrmsr
popl	%ebx
epilog


mtrr_fixed_fun://unsigned long long mtrr_fixed_fun(unsigned int index);
prolog
pushl	%ebx
pushl	%ecx

movl	8(%ebp),%ecx
rdmsr

popl	%ecx
popl	%ebx
epilog



add:
prolog
pushl	%ebx
movl	8(%ebp),%eax
add	12(%ebp),%eax
add	$100,%eax
movl	16(%ebp),%ebx
movl	%eax,(%ebx)
popl	%ebx
epilog

enter_no_fill:
prolog
movl	%cr0,%eax	//no-fill mod
orl	$0x40000000,%eax
movl	%eax,%cr0
epilog


exit_no_fill:
prolog

movl	%cr0,%ecx
andl	$0x9FFFFFFF,%ecx
movl	%ecx,%cr0
epilog

invd_t:
prolog
pushl	%ebx
pushl	%ecx
movl	8(%ebp),%eax

movl	$0x12,%ebx
wbinvd
mfence
sfence
lfence
//movl	(%eax),%ecx
movl	%ebx,(%eax)

//invd
//mfence

popl	%ecx
popl	%ebx
epilog



//int safeCall1(void *para0,void *fun, void *newStack); para: para0 point to a struct para, fun to to be called funtion, newStack is the new stack
safeCall1:
prolog
//pusha
//pushf
pushl	%ebx
movl	16(%ebp),%eax	//eax->new stack top

//constuct new stack and save esp ebp ret
movl	%ebp,(%eax)	//save ebp
movl	%esp,-4(%eax)	//save esp
movl	%ebp,%ebx	//ebx->old ebp

movl	%eax,%ebp	//ebp ->  new stack top
movl	%eax,%esp	
subl	$4,%esp		//esp

pushl	8(%ebx)		//para0
call	12(%ebx)	//fun

//restore stack, common
movl	%ebp,%ebx
movl	(%ebx),%ebp
movl	-4(%ebx),%esp
popl	%ebx
//popf
//popa

epilog

//safeCall(int para1,int para2,int *para3,void *newStack); para point to int int and int *
safeCall:
prolog
movl	20(%ebp),%eax	//new stack address,eax 		4*4 + 4,change

//constuct new stack and save esp ebp ret


movl	%ebp,(%eax)	//save ebp
movl	%ebx,-4(%eax)	//save ebx

movl	%ebp,%ebx	//ebx->old statck

movl	%eax,%ebp
subl	$4,%ebp
movl	%ebp,%esp		//esp -> saved ebx; ebp ->  saved ebx


pushl	16(%ebx)		//para3				change according to paras
pushl	12(%ebx)		//para2		
pushl	8(%ebx)			//prar1	
//pushl	$3		//para3				change according to paras
//pushl	$2		//para2		
//pushl	$1		//prar1		
//call	add1

//restore stack, common
movl	%ebp,%esp	///esp -> saved ebx; ebp ->  saved ebx

popl	%ebx
popl	%ebp
////movl	%esp,%ebx
////movl	(%ebx),%esp
//movl	(%esp),%esp
//movl	%ebp,%esp
movl	20(%ebp),%eax
epilog


/*int enter_no_stack(void *)*/
enter_no_stack:
movl	(%esp),%eax	//ret address
movl	4(%esp),%ebx	//new stack address
//constuct new stack
movl	%esp,(%ebx)	//save esp
movl	%ebp,-4(%ebx)	//save ebp
movl	%eax,-8(%ebx)	//ret add

movl	%ebx,%ebp
movl	%ebx,%esp
subl	$4,%ebp
subl	$8,%esp		//esp -> ret address; ebp -> saved esp
ret


/*void restore_no_stack()*/
restore_no_stack:
popl	%eax		//ret address
popl	%ebp
movl	%esp,%ebx
movl	(%ebx),%esp
movl	%eax,(%esp)
ret


/*char* getData(void)*/
getData:
prolog
mov	$msg,%eax
epilog

/*unsigned int getCR0(void)*/
getCR0:
prolog
movl	%cr0,%eax
epilog

/*unsigned int readMem(void *p,int size)*/
readMem:
prolog
pushl %esi
pushl %ecx
movl 8(%ebp),%esi
cld
movl	12(%ebp),%ecx
rep lodsl
popl %ecx
popl %esi
epilog


/*unsigned int writeMem(void *p,int size)*/
writeMem:
prolog
pushl %edi
pushl %ecx
movl 8(%ebp),%edi
cld
movl	12(%ebp),%ecx
xorl %eax,%eax
rep stosl
popl %ecx
popl %edi
epilog






/*unsigned int flushMemTest(unsigned char *base,int size)*/
flushMemTest:
prolog
pushl %esi
pushl %edi
pushl %ecx

cld
movl	8(%ebp), %esi
movl	12(%ebp), %ecx
shr	$6,%ecx

mfence
loopstart:

clflush	(%esi)
addl	$64,%esi
dec	%ecx
jnz	loopstart
mfence

popl %ecx
popl %edi
popl %esi

epilog


/*unsigned int prepareMemAndDisCache(unsigned char *base,int size)	return cr0*/ 
prepareMemAndDisCache:
prolog
pushl %esi
pushl %ebx
pushl %edi
pushl %ecx


movl	%cr0,%eax	//normal mode
andl	$0x9FFFFFFF,%eax
movl	%eax,%cr0


cld		//fill cache with 0x12345678
movl	8(%ebp), %edi
movl	12(%ebp), %ecx
shr	$2,%ecx
movl	$0xFFFFFFFF,%eax
rep	stosl

wbinvd


movl	8(%ebp), %esi
movl	12(%ebp), %ecx

cld		//validate cache with mem access
shr	$2,%ecx
rep	lodsl

/*



cld		//fill cache with 0x12345678
movl	8(%ebp), %edi
movl	12(%ebp), %ecx
shr	$2,%ecx
movl	$0x00000000,%eax
rep	stosl

pushl	$0x3
movl	8(%ebp),%edi
//call	_jiecheng
movl	%eax,(%edi)
addl	$4,%esp

*/
//movl	%cr0,%eax	//no-fill mod
//orl	$0x40000000,%eax
//movl	%eax,%cr0

popl %ecx
popl %edi
popl %ebx
popl %esi

epilog


/*void disCache(void *)
disCache:
prolog
pushl	%eax
movl	%cr0,%eax	//no-fill mod
orl	$0x40000000,%eax
movl	%eax,%cr0

wbinvd
popl	%eax
epilog

*/
/*void enaCache(void *)
enaCache:
prolog
pushl	%eax
movl	%cr0,%eax
andl	$0x9FFFFFFF,%eax
movl	%eax,%cr0
popl	%eax
epilog
*/
//unsigned int readAddr(unsigned char *mem)
readAddr:
prolog
pushl	%edx
pushl	%ebx
pushl	%edi

rdtsc
rdtsc
rdtsc
wbinvd

cld		//refill
movl	8(%ebp), %edi
movl	$1024, %ecx
rep	stosl

cld		//refill
movl	8(%ebp), %edi
movl	$1024, %ecx
rep	stosl

cld		//refill
movl	8(%ebp), %edi
movl	$1024, %ecx
rep	stosl

//movl	%cr0,%eax	//no-fill mod
//orl	$0x40000000,%eax
//movl	%eax,%cr0

movl	8(%ebp),%edi
movl	$1, %ecx

cld
rdtsc
movl	%eax,%ebx
rep	stosl
rdtsc
sub	%ebx,%eax

mov	%eax,%ebx
//wbinvd
//call	enaCache
mov	%ebx,%eax

popl	%edi
popl	%ebx
popl	%edx
epilog


//unsigned int readAddrInv(unsigned char *mem)
readAddrInv:
prolog
pushl	%edx
pushl	%ebx
pushl	%edi

rdtsc
rdtsc
rdtsc

movl	8(%ebp),%edi
movl	$1, %ecx
wbinvd
wbinvd
wbinvd


cld
rdtsc
movl	%eax,%ebx
rep	stosl
rdtsc
sub	%ebx,%eax

popl	%edi
popl	%ebx
popl	%edx
epilog


//unsigned int rdtscTime(void);

rdtscTime:
prolog
pushl	%ebx
pushl	%ecx


rdtsc
lfence
movl	%eax,%ebx

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
subl	%ebx,%eax

popl	%ecx
popl	%ebx
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
pushl	%ebx
pushl	%ecx
pushl	%edx
pushl	%edi


movl	8(%ebp),%edx
movl	%esp,(%edx)

movl	%esp,%ebx
rdtscp
movl	%eax,%edi
movl	(%ebx),%edx
lfence
movl	-64(%ebx),%edx
lfence
movl	-2*64(%ebx),%edx
lfence
movl	-3*64(%ebx),%edx
lfence
movl	-4*64(%ebx),%edx
lfence
movl	-5*64(%ebx),%edx
lfence
movl	-6*64(%ebx),%edx
lfence
movl	-7*64(%ebx),%edx
lfence
rdtscp
subl	%edi,%eax




popl	%edi
popl	%edx
popl	%ecx
popl	%ebx
epilog

//unsigned int testSpeed(unsigned char *mem)
testSpeed:
prolog
pushl	%ebx
pushl	%ecx
pushl	%edx
pushl	%edi

movl	8(%ebp),%ebx
rdtsc
lfence
movl	%eax,%edi
movl	(%ebx),%edx
lfence
movl	64(%ebx),%edx
lfence
movl	2*64(%ebx),%edx
lfence
movl	3*64(%ebx),%edx
lfence
movl	4*64(%ebx),%edx
lfence
movl	5*64(%ebx),%edx
lfence
movl	6*64(%ebx),%edx
lfence
movl	7*64(%ebx),%edx
lfence
rdtsc
lfence
subl	%edi,%eax

popl	%edi
popl	%edx
popl	%ecx
popl	%ebx
epilog




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
