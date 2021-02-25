 .text
    .globl stack_switch
    .type stack_switch, @function
stack_switch:
    pushq %rbp
     movq %rsp, %rbp

     movq 32(%rbp), %rax

     movq %rbp, (%rax)

     movq %rbp, -8(%rax)

     movq %rbp, %rbx

     movq %rax, %rbp
     movq %rax, %rsp
     subq $8, %rsp

     pushq 16(%rbx)
     callq 24(%rbx)

     movq %rbp, %rbx
     movq (%rbx), %rsp
     movq -8(%rbx), %rsp

     leaveq
     retq
