//! vela-mkhello：生成最小合法 Linux x86_64 静态 PIE ELF（打印 "hello from linux elf"）。
//! 用于没有 Linux/musl 交叉编译环境时生成 guest/hello（规格 8.1 允许的生成器路径）。
//! 用 musl-gcc/clang 重编请看 guest/README.md。

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: vela-mkhello <output-file>");
        std::process::exit(2);
    }
    let elf = build_min_hello();
    if let Err(e) = std::fs::write(&args[1], &elf) {
        eprintln!("vela-mkhello: write {}: {e}", args[1]);
        std::process::exit(1);
    }
    println!("wrote {} ({} bytes)", args[1], elf.len());
}

/// 构造单 PT_LOAD（R|X、p_offset==p_vaddr 平铺布局）的最小 ET_DYN ELF：
/// ELF 头(64) + 程序头(56) + 机器码 + 消息字符串。两条 `syscall` 会被
/// vela-loader patch 成 UD2，由 VEH 进入 dispatch。
pub fn build_min_hello() -> Vec<u8> {
    const CODE_OFF: usize = 0x78;
    const MSG: &[u8] = b"hello from linux elf\n"; // 21 字节

    // ---- 机器码（等价于 guest/src/hello.S）
    let mut c: Vec<u8> = Vec::new();
    c.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]); // mov rax, 1  (SYS_write)
    c.extend_from_slice(&[0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00]); // mov rdi, 1
    c.extend_from_slice(&[0x48, 0x8D, 0x35, 0, 0, 0, 0]); // lea rsi, [rip+disp32]（后填）
    c.extend_from_slice(&[0x48, 0xC7, 0xC2, (MSG.len() as u8), 0x00, 0x00, 0x00]); // mov rdx, 21
    c.extend_from_slice(&[0x0F, 0x05]); // syscall
    c.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00]); // mov rax, 60 (SYS_exit)
    c.extend_from_slice(&[0x48, 0x31, 0xFF]); // xor rdi, rdi
    c.extend_from_slice(&[0x0F, 0x05]); // syscall
    c.extend_from_slice(MSG);

    let lea_at = CODE_OFF + 14; // 两条 mov(7B) 之后
    let msg_at = CODE_OFF + c.len() - MSG.len();
    let next_after_lea = (lea_at + 7) as i32;
    let disp = (msg_at as i32) - next_after_lea;

    // ---- 文件：ELF 头(64) + 程序头(56) + 机器码
    let total = CODE_OFF + c.len();
    let mut e = vec![0u8; total];

    e[0..4].copy_from_slice(b"\x7fELF");
    e[4] = 2; // ELFCLASS64
    e[5] = 1; // ELFDATA2LSB
    e[6] = 1; // EV_CURRENT
    e[16..18].copy_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
    e[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
    e[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    e[0x18..0x20].copy_from_slice(&(CODE_OFF as u64).to_le_bytes()); // e_entry
    e[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
    e[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    e[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    e[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes()); // e_phnum

    let ph = 0x40;
    e[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    e[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    // p_offset(8)=0 / p_vaddr(16)=0 / p_paddr(24)=0：全零
    e[ph + 32..ph + 40].copy_from_slice(&(total as u64).to_le_bytes()); // p_filesz
    e[ph + 40..ph + 48].copy_from_slice(&(total as u64).to_le_bytes()); // p_memsz
    e[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align

    e[CODE_OFF..CODE_OFF + c.len()].copy_from_slice(&c);
    e[lea_at + 3..lea_at + 7].copy_from_slice(&disp.to_le_bytes());
    e
}
