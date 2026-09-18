    .intel_syntax noprefix
    # guest/src/hello.S —— v0 门禁 guest（规格 8.1）
    # 在 Linux/WSL 交叉编译：
    #   clang -static-pie -nostdlib -o hello hello.S
    #   gcc   -static-pie -nostdlib -o hello hello.S
    # 产物应为 ELF 64-bit LSB pie executable，覆盖 guest/hello。
    # 本机无交叉环境时可用 `cargo run -p vela-cli --bin vela-mkhello -- guest/hello`
    # 生成等价的最小合法 ELF（由 vela-loader 测试保证与编译产物语义一致）。

    .global _start

_start:
    mov rax, 1          # SYS_write
    mov rdi, 1
    lea rsi, [rip + msg]
    mov rdx, msg_len
    syscall
    mov rax, 60         # SYS_exit
    xor rdi, rdi
    syscall

msg:
    .ascii "hello from linux elf\n"
    .equ msg_len, . - msg
