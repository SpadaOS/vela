.intel_syntax noprefix
.global _start
.text
# Every syscall has three movable NOPs. This image must actually install
# islands, so per-thread register/FP/flags storage is exercised directly.
.macro call_linux
    syscall
    nop
    nop
    nop
.endm
_start:
    mov r12, 0x123456789abcdef
    mov qword ptr [rsp-120], 0x7654321
    pcmpeqb xmm0, xmm0
    stc
    mov eax, 39
    call_linux
    jnc failure
    test rax, rax
    jz failure
    cmp qword ptr [rsp-120], 0x7654321
    jne failure
    movq rbx, xmm0
    cmp rbx, -1
    jne failure
    mov rbx, 0x123456789abcdef
    cmp rbx, r12
    jne failure
    # A child resumed from an island fork must preserve flags and SIMD too.
    stc
    mov eax, 57
    call_linux
    jnc failure
    movq rbx, xmm0
    cmp rbx, -1
    jne failure
    test rax, rax
    jz child
    js failure
    mov rdi, rax
    lea rsi, [rip+status]
    xor edx, edx
    xor r10d, r10d
    mov eax, 61
    call_linux
    cmp dword ptr [rip+status], 0
    jne failure
    # Two native guest threads repeatedly enter the same island stubs.
    lea rsi, [rip+worker_stack_end]
    mov edi, 0x50f00
    xor edx, edx
    xor r10d, r10d
    xor r8d, r8d
    mov eax, 56
    call_linux
    test rax, rax
    jz worker
    js failure
    mov r13, 0x333333333
    mov r14d, 500
parent_loop:
    mov eax, 39
    call_linux
    mov rbx, 0x333333333
    cmp r13, rbx
    jne failure
    dec r14d
    jne parent_loop
await_worker:
    cmp dword ptr [rip+done], 1
    je success
    mov eax, 24
    call_linux
    jmp await_worker
worker:
    mov r13, 0x777777777
    mov r14d, 500
worker_loop:
    mov eax, 39
    call_linux
    mov rbx, 0x777777777
    cmp r13, rbx
    jne failure
    dec r14d
    jne worker_loop
    mov dword ptr [rip+done], 1
child:
    xor edi, edi
    mov eax, 60
    call_linux
success:
    xor edi, edi
    mov eax, 231
    call_linux
failure:
    mov edi, 1
    mov eax, 231
    call_linux
.bss
.align 16
status: .skip 4
done: .skip 4
.align 16
worker_stack: .skip 65536
worker_stack_end:
