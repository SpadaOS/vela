//! 共享测试辅助（规格 3：tests/common.rs）。
//! crate 测试通过 `#[path = "../../tests/common.rs"]` 引入。

/// 与 vela-mkhello 相同字节的最小静态 PIE ELF（hello from linux elf）。
pub fn build_min_hello() -> Vec<u8> {
    const CODE_OFF: usize = 0x78;
    const MSG: &[u8] = b"hello from linux elf\n";

    let mut c: Vec<u8> = Vec::new();
    c.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00]); // mov rax, 1
    c.extend_from_slice(&[0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00]); // mov rdi, 1
    c.extend_from_slice(&[0x48, 0x8D, 0x35, 0, 0, 0, 0]); // lea rsi, [rip+disp]
    c.extend_from_slice(&[0x48, 0xC7, 0xC2, (MSG.len() as u8), 0x00, 0x00, 0x00]); // mov rdx, 21
    c.extend_from_slice(&[0x0F, 0x05]); // syscall
    c.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00]); // mov rax, 60
    c.extend_from_slice(&[0x48, 0x31, 0xFF]); // xor rdi, rdi
    c.extend_from_slice(&[0x0F, 0x05]); // syscall
    c.extend_from_slice(MSG);

    let lea_at = CODE_OFF + 14;
    let msg_at = CODE_OFF + c.len() - MSG.len();
    let disp = (msg_at as i32) - ((lea_at + 7) as i32);

    let total = CODE_OFF + c.len();
    let mut e = vec![0u8; total];
    e[0..4].copy_from_slice(b"\x7fELF");
    e[4] = 2;
    e[5] = 1;
    e[6] = 1;
    e[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    e[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    e[20..24].copy_from_slice(&1u32.to_le_bytes());
    e[0x18..0x20].copy_from_slice(&(CODE_OFF as u64).to_le_bytes());
    e[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    e[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    e[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    e[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());

    let ph = 0x40;
    e[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    e[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    e[ph + 32..ph + 40].copy_from_slice(&(total as u64).to_le_bytes());
    e[ph + 40..ph + 48].copy_from_slice(&(total as u64).to_le_bytes());
    e[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    e[CODE_OFF..CODE_OFF + c.len()].copy_from_slice(&c);
    e[lea_at + 3..lea_at + 7].copy_from_slice(&disp.to_le_bytes());
    e
}
