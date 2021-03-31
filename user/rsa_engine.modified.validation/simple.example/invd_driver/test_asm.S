.file "test_asm.S"

.macro prolog
push	%rbp
mov	%rsp,%rbp
.endm

.macro epilog
leave
ret
.endm
