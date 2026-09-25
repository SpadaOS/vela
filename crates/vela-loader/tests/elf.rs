//! ELF 解析与 patch 单元测试（规格 9.1）。纯内存操作，无大内存开销。

#[path = "../../../tests/common.rs"]
mod common;

use vela_loader::{parse, patch_syscalls, LoadError};
use vela_sys::HostProt;

#[test]
fn patcher_rewrites_syscall_to_ud2() {
    // 0F 05 ×2 + 干扰数据
    let mut buf = vec![0x90, 0x0F, 0x05, 0xCC, 0x0F, 0x05, 0x48];
    let mut sites = Vec::new();
    let n = patch_syscalls(&mut buf, 0x1000, &mut sites);
    assert_eq!(n, 2);
    assert_eq!(buf, vec![0x90, 0x0F, 0x0B, 0xCC, 0x0F, 0x0B, 0x48]);
    assert_eq!(sites, vec![0x1001, 0x1004]);
}

#[test]
fn patcher_ignores_non_syscall() {
    let mut buf = vec![0x0F, 0x0B, 0x05, 0x0F, 0x05];
    let mut sites = Vec::new();
    let n = patch_syscalls(&mut buf, 0, &mut sites);
    assert_eq!(n, 1);
    assert_eq!(buf, vec![0x0F, 0x0B, 0x05, 0x0F, 0x0B]);
    assert_eq!(sites, vec![0x3]);
}

#[test]
fn patcher_never_touches_syscall_inside_displacement() {
    // `48 8d 05 e9 0f 05 00` = lea rax,[rip+0x50fe9]——位移字节里嵌着
    // 0F 05（CI busybox ash makestrspace 现场：裸字节扫描把位移改成
    // e9 0f 0b 00，lea 目标偏移 +0x60000，读 ash_ptr_to_globals
    // _memstack 变成野地址 0x40106ac8 → AV）。线性走查必须认出整条
    // lea 并完整跳过。
    let orig = vec![0x48, 0x8d, 0x05, 0xe9, 0x0f, 0x05, 0x00];
    let mut buf = orig.clone();
    let mut sites = Vec::new();
    let n = patch_syscalls(&mut buf, 0x4000_0000, &mut sites);
    assert_eq!(n, 0);
    assert_eq!(buf, orig);
}

#[test]
fn patcher_walks_over_common_encodings() {
    // mov rax,1 / syscall / call rel32 / jmp rel8 / test + 末尾 REX 截断
    let mut buf = vec![
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax,1 (mod=3, imm32)
        0x0F, 0x05, // syscall → patch
        0xE8, 0x01, 0x00, 0x00, 0x00, // call rel32（rel32 内无 0F 05）
        0xEB, 0xF9, // jmp rel8
        0x48, // 截断 REX：不可解码，滑过
    ];
    let mut sites = Vec::new();
    let n = patch_syscalls(&mut buf, 0x1000, &mut sites);
    assert_eq!(n, 1);
    assert_eq!(sites, vec![0x1007]);
    assert_eq!(&buf[7..9], &[0x0F, 0x0B]);
}

#[test]
fn parse_accepts_min_pie() {
    let bytes = common::build_min_hello();
    let info = parse(&bytes).expect("parse ok");
    assert_eq!(info.entry, 0x78);
    assert_eq!(info.phoff, 0x40);
    assert_eq!(info.phnum, 1);
    assert_eq!(info.loads.len(), 1);
    assert_eq!(info.loads[0].flags & 1, 1); // PF_X
}

#[test]
fn parse_rejects_pe() {
    let pe = b"MZ\x90\x00\x03\x00\x00\x00this is not an elf at all";
    assert_eq!(parse(pe), Err(LoadError::NotElf));
}

#[test]
fn parse_rejects_32bit() {
    let mut bytes = common::build_min_hello();
    bytes[4] = 1; // ELFCLASS32
    assert_eq!(parse(&bytes), Err(LoadError::WrongClass));
}

#[test]
fn parse_rejects_big_endian() {
    let mut bytes = common::build_min_hello();
    bytes[5] = 2; // ELFDATA2MSB
    assert_eq!(parse(&bytes), Err(LoadError::WrongEndian));
}

#[test]
fn parse_rejects_wrong_machine() {
    let mut bytes = common::build_min_hello();
    bytes[18] = 40; // EM_ARM
    assert_eq!(parse(&bytes), Err(LoadError::WrongMachine));
}

#[test]
fn parse_rejects_non_pie() {
    let mut bytes = common::build_min_hello();
    bytes[16] = 2; // ET_EXEC
    assert_eq!(parse(&bytes), Err(LoadError::WrongType));
}

#[test]
fn parse_accepts_musl_interp_and_extracts_path() {
    let bytes = common::build_min_dyn_hello("/lib/ld-musl-x86_64.so.1");
    let info = parse(&bytes).expect("parse ok");
    assert_eq!(info.interp.as_deref(), Some("/lib/ld-musl-x86_64.so.1"));
    assert_eq!(info.loads.len(), 1);
}

#[test]
fn parse_rejects_non_musl_interp() {
    let bytes = common::build_min_dyn_hello("/lib64/ld-linux-x86-64.so.2");
    assert!(matches!(
        parse(&bytes),
        Err(LoadError::UnsupportedInterp(_))
    ));
}

#[test]
fn parse_static_pie_has_no_interp() {
    let bytes = common::build_min_hello();
    assert_eq!(parse(&bytes).expect("parse ok").interp, None);
}

#[cfg(windows)]
#[test]
fn load_maps_and_patches_min_hello() {
    use vela_sys::windows::WindowsHost;
    let host = WindowsHost::new();
    let img = vela_loader::load(&common::build_min_hello(), &host, 0).expect("load ok");
    // 平铺布局：p_offset==p_vaddr ⇒ 各虚拟地址直接加 bias
    assert_eq!(img.entry, img.bias + 0x78);
    assert_eq!(img.phdr, img.bias + 0x40);
    assert_eq!(img.segments.len(), 1);
    assert_eq!(img.exec_ranges.len(), 1);
    // syscall 已被 patch 成 UD2：0F 05 → 0F 0B（第二个字节变化）
    let seg = &img.segments[0];
    let b1 = unsafe { std::ptr::read_unaligned((seg.host_addr + 0x95) as *const u8) };
    let b2 = unsafe { std::ptr::read_unaligned((seg.host_addr + 0xA1) as *const u8) };
    assert_eq!((b1, b2), (0x0B, 0x0B));
    // 消息字符串原样在映射内
    let msg = unsafe { std::slice::from_raw_parts((seg.host_addr + 0xA2) as *const u8, 21) };
    assert_eq!(msg, b"hello from linux elf\n");
    let _ = HostProt::READ;
}
