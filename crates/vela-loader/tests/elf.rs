//! ELF 解析与 patch 单元测试（规格 9.1）。纯内存操作，无大内存开销。

#[path = "../../../tests/common.rs"]
mod common;

use vela_loader::{parse, patch_syscalls, LoadError};
use vela_sys::HostProt;

#[test]
fn patcher_rewrites_syscall_to_ud2() {
    // 0F 05 ×2 + 干扰数据
    let mut buf = vec![0x90, 0x0F, 0x05, 0xCC, 0x0F, 0x05, 0x48];
    let n = patch_syscalls(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(buf, vec![0x90, 0x0F, 0x0B, 0xCC, 0x0F, 0x0B, 0x48]);
}

#[test]
fn patcher_ignores_non_syscall() {
    let mut buf = vec![0x0F, 0x0B, 0x05, 0x0F, 0x05];
    let n = patch_syscalls(&mut buf);
    assert_eq!(n, 1);
    assert_eq!(buf, vec![0x0F, 0x0B, 0x05, 0x0F, 0x0B]);
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
fn parse_rejects_interp() {
    let mut bytes = common::build_min_hello();
    bytes[0x40] = 3; // 第一个 phdr 改成 PT_INTERP
    assert_eq!(parse(&bytes), Err(LoadError::DynamicBinary));
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
