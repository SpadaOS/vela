//! vela-loader：ELF64 解析、校验、加载与 syscall patch（规格 5.3）。
//! 支持 ELF64 / x86_64 / ET_DYN；PT_INTERP 仅接受 musl 解释器（白名单
//! 前缀 `ld-musl`，PLAN-0.0.4 T2.1），由 CLI 装载双映像。
//! 依赖方向：loader → runtime（LoadedImage 类型定义在 runtime）/ loader → sys（Host trait）。

use std::fmt;

use vela_runtime::mem::{LoadedImage, MemRange, Segment};
use vela_sys::{Host, HostError, HostProt};

const PAGE: u64 = 4096;
pub const PT_LOAD: u32 = 1;
pub const PT_INTERP: u32 = 3;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// ---------------------------------------------------------------- 错误

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    NotElf,
    Truncated,
    WrongClass,
    WrongEndian,
    WrongMachine,
    WrongType,
    /// PT_INTERP 存在但不是 musl 解释器（诚实拒绝，不做通用动态链接）。
    UnsupportedInterp(String),
    NoLoadSegments,
    BadLayout(&'static str),
    TooLarge,
    Host(HostError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::NotElf => write!(f, "not a Linux ELF64 image (bad magic)"),
            LoadError::Truncated => write!(f, "ELF headers truncated"),
            LoadError::WrongClass => write!(f, "not a 64-bit ELF (ELFCLASS64 required)"),
            LoadError::WrongEndian => write!(f, "not little-endian ELF (ELFDATA2LSB required)"),
            LoadError::WrongMachine => write!(f, "not x86_64 ELF (EM_X86_64 required)"),
            LoadError::WrongType => write!(
                f,
                "non-PIE or unsupported e_type (vela requires ET_DYN PIE)"
            ),
            LoadError::UnsupportedInterp(p) => write!(
                f,
                "unsupported interpreter '{p}' (only musl ld-musl-* is supported)"
            ),
            LoadError::NoLoadSegments => write!(f, "no PT_LOAD segments"),
            LoadError::BadLayout(m) => write!(f, "bad ELF layout: {m}"),
            LoadError::TooLarge => write!(f, "load span exceeds 1 GiB sanity limit"),
            LoadError::Host(e) => write!(f, "host map error: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<HostError> for LoadError {
    fn from(e: HostError) -> Self {
        LoadError::Host(e)
    }
}

// ---------------------------------------------------------------- 解析

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLoadSeg {
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfInfo {
    pub entry: u64,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub loads: Vec<RawLoadSeg>,
    /// PT_INTERP 内容（解释器路径，如 /lib/ld-musl-x86_64.so.1）。
    pub interp: Option<String>,
}

fn u16le(b: &[u8], off: usize) -> Result<u16, LoadError> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(LoadError::Truncated)
}

fn u32le(b: &[u8], off: usize) -> Result<u32, LoadError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(LoadError::Truncated)
}

fn u64le(b: &[u8], off: usize) -> Result<u64, LoadError> {
    b.get(off..off + 8)
        .map(|s| {
            let mut x = [0u8; 8];
            x.copy_from_slice(s);
            u64::from_le_bytes(x)
        })
        .ok_or(LoadError::Truncated)
}

/// 校验 ELF 头与 program headers。拒绝：非 ELF、32 位、大端、非 x86_64、
/// 非 ET_DYN（v0 强制 PIE）、含 PT_INTERP、无 PT_LOAD（规格 5.3）。
pub fn parse(bytes: &[u8]) -> Result<ElfInfo, LoadError> {
    if bytes.len() < 64 {
        return Err(LoadError::NotElf);
    }
    if bytes[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(LoadError::NotElf);
    }
    if bytes[4] != 2 {
        return Err(LoadError::WrongClass); // 仅 ELFCLASS64
    }
    if bytes[5] != 1 {
        return Err(LoadError::WrongEndian); // 仅 ELFDATA2LSB
    }
    let e_type = u16le(bytes, 16)?;
    let e_machine = u16le(bytes, 18)?;
    if e_machine != 62 {
        return Err(LoadError::WrongMachine);
    }
    if e_type != 3 {
        return Err(LoadError::WrongType); // v0 强制 PIE
    }
    let e_entry = u64le(bytes, 0x18)?;
    let e_phoff = u64le(bytes, 0x20)?;
    let e_phentsize = u16le(bytes, 0x36)?;
    let e_phnum = u16le(bytes, 0x38)?;
    if e_phentsize != 56 {
        return Err(LoadError::BadLayout("unsupported e_phentsize"));
    }
    if e_phnum == 0 || e_phnum > 1024 {
        return Err(LoadError::BadLayout("bad e_phnum"));
    }
    let phend = e_phoff
        .checked_add(e_phnum as u64 * 56)
        .ok_or(LoadError::Truncated)?;
    if phend > bytes.len() as u64 {
        return Err(LoadError::Truncated);
    }

    let mut loads = Vec::new();
    let mut interp: Option<String> = None;
    for i in 0..e_phnum as usize {
        let p = e_phoff as usize + i * 56;
        let p_type = u32le(bytes, p)?;
        if p_type == PT_INTERP {
            // 解释器路径：文件内 NUL 结尾字符串（PLAN-0.0.4 T2.1）
            let off = u64le(bytes, p + 8)?;
            let fsz = u64le(bytes, p + 32)?;
            let end = off
                .checked_add(fsz)
                .ok_or(LoadError::BadLayout("interp p_offset+p_filesz overflow"))?;
            if end > bytes.len() as u64 {
                return Err(LoadError::Truncated);
            }
            let raw = &bytes[off as usize..end as usize];
            let s = raw.split(|&b| b == 0).next().unwrap_or(&[]);
            interp = Some(String::from_utf8_lossy(s).into_owned());
            continue;
        }
        if p_type != PT_LOAD {
            continue;
        }
        let flags = u32le(bytes, p + 4)?;
        let offset = u64le(bytes, p + 8)?;
        let vaddr = u64le(bytes, p + 16)?;
        let filesz = u64le(bytes, p + 32)?;
        let memsz = u64le(bytes, p + 40)?;
        if offset
            .checked_add(filesz)
            .map(|end| end > bytes.len() as u64)
            .unwrap_or(true)
        {
            return Err(LoadError::BadLayout("p_offset+p_filesz out of file"));
        }
        if memsz < filesz {
            return Err(LoadError::BadLayout("p_memsz < p_filesz"));
        }
        if vaddr.checked_add(memsz).is_none() {
            return Err(LoadError::BadLayout("p_vaddr+p_memsz overflow"));
        }
        loads.push(RawLoadSeg {
            offset,
            vaddr,
            filesz,
            memsz,
            flags,
        });
    }
    if let Some(p) = &interp {
        // 白名单：仅 musl 解释器（ld-musl 前缀的 basename）。其余诚实拒绝，
        // 不假装支持通用 glibc 动态链接（规格 0：诚实的 ENOSYS 优于错误结果）
        let base = p.rsplit('/').next().unwrap_or(p);
        if !base.starts_with("ld-musl") {
            return Err(LoadError::UnsupportedInterp(p.clone()));
        }
    }
    if loads.is_empty() {
        return Err(LoadError::NoLoadSegments);
    }
    Ok(ElfInfo {
        entry: e_entry,
        phoff: e_phoff,
        phentsize: e_phentsize,
        phnum: e_phnum,
        loads,
        interp,
    })
}

// ---------------------------------------------------------------- patch

/// 最小 x86-64 指令长度解码（线性走查专用）：只求「长度正确或承认失败」，
/// 不做语义分析。返回 None = 不可解码（数据 / 未覆盖编码）。
/// 覆盖编译器产出代码的主流编码；SIB/disp/imm 与 0F 两字节表齐备。
fn insn_len(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    let mut o66 = false;
    loop {
        match b.get(i)? {
            0x66 => {
                o66 = true;
                i += 1;
            }
            0x67 | 0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => i += 1,
            _ => break,
        }
    }
    let mut rex_w = false;
    let p = *b.get(i)?;
    if p & 0xF0 == 0x40 {
        rex_w = p & 0x08 != 0;
        i += 1;
    }
    let op = *b.get(i)?;
    // 64 位模式下这些单字节操作码无效（未被前缀消化时）
    if matches!(
        op,
        0x06 | 0x07
            | 0x0E
            | 0x0F
            | 0x16
            | 0x17
            | 0x1E
            | 0x1F
            | 0x27
            | 0x2F
            | 0x37
            | 0x3F
            | 0x60
            | 0x61
            | 0x62
            | 0x82
            | 0xC4
            | 0xC5
            | 0x9A
            | 0xD4
            | 0xD5
            | 0xD6
            | 0xEA
            | 0xF1
    ) {
        return None;
    }
    // ModRM 系操作码（含随后 immediate 由调用方拼接）
    let modrm = |b: &[u8]| modrm_disp_len(b);
    // moffs64（A0-A3）：66 缩为 2
    let moffs = if o66 { 2 } else { 8 };
    let immz = if o66 { 2 } else { 4 };
    // tail = ModRM+disp 之外的立即数/相对量长度；total = 全指令长度，
    // 统一在出口做整体越界校验（截断指令按 None 处理，避免误吞后续字节）
    let total: usize = match op {
        // AL/AX, imm8
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C | 0xA8 => i + 1 + 1,
        // eAX, immz
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D | 0xA9 => i + 1 + immz,
        // moffs 形式
        0xA0..=0xA3 => i + 1 + moffs,
        0x68 => i + 1 + immz,
        0x6A => i + 1 + 1,
        0x69 => i + 1 + modrm(&b[i + 1..])? + immz,
        0x6B => i + 1 + modrm(&b[i + 1..])? + 1,
        0x70..=0x7F => i + 1 + 1,
        0x80 => i + 1 + modrm(&b[i + 1..])? + 1,
        0x81 => i + 1 + modrm(&b[i + 1..])? + immz,
        0x83 => i + 1 + modrm(&b[i + 1..])? + 1,
        0xB0..=0xB7 => i + 1 + 1,
        0xB8..=0xBF => {
            if rex_w {
                i + 1 + 8
            } else {
                i + 1 + immz
            }
        }
        0xC0 | 0xC1 | 0xC6 => i + 1 + modrm(&b[i + 1..])? + 1,
        0xC2 | 0xCA => i + 1 + 2,
        0xC7 => i + 1 + modrm(&b[i + 1..])? + immz,
        0xC8 => i + 1 + 3,
        0xCD => i + 1 + 1,
        0xD7
        | 0x90..=0x99
        | 0x9B..=0x9F
        | 0xA4..=0xA7
        | 0xAA..=0xAF
        | 0xC3
        | 0xC9
        | 0xCC
        | 0xCF
        | 0xEC..=0xEF
        | 0xF4
        | 0xF5
        | 0xF8..=0xFD => i + 1,
        0xE0..=0xE3 | 0xE4 | 0xE5 | 0xE6 | 0xE7 | 0xEB => i + 1 + 1,
        0xE8 | 0xE9 => i + 1 + 4,
        0xF6 => {
            let m = *b.get(i + 1)?;
            i + 1 + modrm(&b[i + 1..])? + if m & 0x38 == 0 { 1 } else { 0 }
        }
        0xF7 => {
            let m = *b.get(i + 1)?;
            i + 1 + modrm(&b[i + 1..])? + if m & 0x38 == 0 { immz } else { 0 }
        }
        // 0x00..=0x3F 的 ModRM 组（add/or/adc/sbb/and/sub/xor/cmp 两个方向）
        0x00..=0x03
        | 0x08..=0x0B
        | 0x10..=0x13
        | 0x18..=0x1B
        | 0x20..=0x23
        | 0x28..=0x2B
        | 0x30..=0x33
        | 0x38..=0x3B
        | 0x63
        | 0x84..=0x8F
        | 0xD0..=0xD3
        | 0xD8..=0xDF
        | 0xFE
        | 0xFF => i + 1 + modrm(&b[i + 1..])?,
        _ => return None, // 其余单字节：64 位无效/未覆盖
    };
    if total <= b.len() {
        Some(total)
    } else {
        None
    }
}

/// ModRM + SIB + displacement 长度（不含 immediate）。b 从 ModRM 字节开始。
fn modrm_disp_len(b: &[u8]) -> Option<usize> {
    let modrm = *b.first()?;
    let (m, rm) = (modrm >> 6, modrm & 7);
    let mut n = 1;
    if m != 3 && rm == 4 {
        // SIB 字节
        let sib = *b.get(n)?;
        n += 1;
        if sib & 7 == 5 && m == 0 {
            n += 4; // base=101, mod=0 → disp32
        }
    }
    match m {
        0 if rm == 5 => n += 4, // RIP 相对 / disp32 绝对
        1 => n += 1,
        2 => n += 4,
        _ => {}
    }
    Some(n)
}

/// 两字节操作码（0F xx）长度。b[0] == 0x0F。
fn insn_len_0f(b: &[u8]) -> Option<usize> {
    let op = *b.get(1)?;
    let modrm = |b: &[u8]| modrm_disp_len(b);
    let total: usize = match op {
        // syscall / ud2 / clts / invd / wbinvd / rdtsc 系：无操作数
        0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0B | 0x30..=0x37 | 0xA2 | 0xAA | 0xC8..=0xCF => 2,
        0x38 => {
            // 0F 38 xx modrm
            let _x = *b.get(2)?;
            3 + modrm(&b[3..])?
        }
        0x3A => {
            // 0F 3A xx modrm imm8
            let _x = *b.get(2)?;
            4 + modrm(&b[3..])?
        }
        0x80..=0x8F => 6,                                 // jcc rel32
        0x70..=0x73 | 0xBA | 0xC2 => modrm(&b[2..])? + 3, // + imm8
        0xA4 | 0xAC => modrm(&b[2..])? + 3,
        0x00..=0x03
        | 0x0D
        | 0x0F
        | 0x10..=0x2F
        | 0x40..=0x6F
        | 0x74..=0x7F
        | 0x90..=0x9F
        | 0xA3
        | 0xA5..=0xA7
        | 0xAB
        | 0xAD..=0xAF
        | 0xB0..=0xB7
        | 0xB9
        | 0xBB..=0xC1
        | 0xC3..=0xC7
        | 0xD0..=0xFF => 2 + modrm(&b[2..])?,
        _ => return None,
    };
    if total <= b.len() {
        Some(total)
    } else {
        None
    }
}

/// 线性指令走查扫描：只把「指令起点上的 `0F 05`」改写为 `0F 0B`（UD2）。
/// 裸字节扫描（≤0.0.6）会把其他指令内的 `0F 05`（如 lea rel32 位移
/// `e9 0f 05 00`）误当 syscall 破坏代码——busybox ash 的
/// makestrspace 现场即此（ash_ptr_to_globals_memstack 读 AV，
/// CI 产物 0x40055adf/0x40106ac8 精确复算证实）。
/// 不可解码处逐字节滑过并放弃该处 patch——漏点由运行时陷阱后端的
/// 裸 syscall 异常兜底自愈（vela-sys），宁可漏不可错。patch 点 VA 记入
/// `sites`（0.1.0 T2.1：岛页跳板只信这份清单）。返回 patch 数量。
pub fn patch_syscalls(code: &mut [u8], base: u64, sites: &mut Vec<u64>) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i + 1 < code.len() {
        let len = if code[i] == 0x0F {
            insn_len_0f(&code[i..])
        } else {
            insn_len(&code[i..])
        };
        match len {
            Some(l) => {
                if l == 2 && code[i] == 0x0F && code[i + 1] == 0x05 {
                    code[i + 1] = 0x0B;
                    sites.push(base + i as u64);
                    n += 1;
                }
                i += l;
            }
            // 不可解码：滑过一字节，本区域放弃 patch（诚实漏点）
            None => i += 1,
        }
    }
    n
}

// ---------------------------------------------------------------- 加载

/// 加载流程（规格 5.3 / 5.2）：
/// 1. 解析校验
/// 2. 计算页对齐跨度并整块 RW 映射（拷贝 + patch 需要写权限）
/// 3. 按 PT_LOAD 拷贝文件内容（bss 由 host.map 的零填充保证）
/// 4. patch 可执行段内的 syscall
/// 5. 按段收敛保护位（W^X，不长期 RWX）
pub fn load(bytes: &[u8], host: &dyn Host, hint: u64) -> Result<LoadedImage, LoadError> {
    let info = parse(bytes)?;
    let lo = info
        .loads
        .iter()
        .map(|s| s.vaddr)
        .min()
        .ok_or(LoadError::NoLoadSegments)?
        & !(PAGE - 1);
    let hi = info
        .loads
        .iter()
        .map(|s| s.vaddr + s.memsz)
        .max()
        .ok_or(LoadError::NoLoadSegments)?
        .div_ceil(PAGE)
        * PAGE;
    let span = (hi - lo) as usize;
    if span > (1 << 30) {
        return Err(LoadError::TooLarge);
    }

    // SAFETY: span>0；host.map 契约保证零填充可写内存
    let base =
        unsafe { host.map(hint as usize, span, HostProt::READ | HostProt::WRITE, true)? } as u64;
    let bias = base - lo;

    let mut segments = Vec::with_capacity(info.loads.len());
    let mut exec_ranges = Vec::new();
    let mut syscall_sites = Vec::new();
    for s in &info.loads {
        let dst = base + (s.vaddr - lo);
        if s.filesz > 0 {
            // SAFETY: dst..dst+filesz 是本函数刚映射的可写内存；src 在文件切片内
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(s.offset as usize),
                    dst as *mut u8,
                    s.filesz as usize,
                );
            }
        }
        let mut prot_bits = 0u8;
        if s.flags & PF_R != 0 {
            prot_bits |= 1;
        }
        if s.flags & PF_W != 0 {
            prot_bits |= 2;
        }
        if s.flags & PF_X != 0 {
            prot_bits |= 4;
            // patch 仅覆盖文件内容范围；bss 零页无指令
            // SAFETY: dst..dst+filesz 是本函数映射的可写内存
            let code = unsafe { std::slice::from_raw_parts_mut(dst as *mut u8, s.filesz as usize) };
            patch_syscalls(code, bias + s.vaddr, &mut syscall_sites);
            exec_ranges.push((bias + s.vaddr, bias + s.vaddr + s.memsz));
        }
        segments.push(Segment {
            vaddr: bias + s.vaddr,
            host_addr: dst as usize,
            file_size: s.filesz,
            mem_size: s.memsz,
            prot: prot_bits,
        });
    }

    // 按段收敛权限：RX / RW / R，不留长期 RWX（规格 5.2）
    for seg in &segments {
        let prot = HostProt::from_bits(seg.prot as u32);
        // SAFETY: 范围属于本函数映射的整块 reserve
        unsafe { host.protect(seg.host_addr, seg.mem_size as usize, prot)? };
    }

    // AT_PHDR：phdr 所在 PT_LOAD 的文件偏移 → 客户虚拟地址
    let phdr = {
        let mut phdr_va = bias + info.phoff;
        for s in &info.loads {
            if info.phoff >= s.offset && info.phoff < s.offset + s.filesz {
                phdr_va = bias + s.vaddr + (info.phoff - s.offset);
                break;
            }
        }
        phdr_va
    };

    Ok(LoadedImage {
        bias,
        entry: bias + info.entry,
        phdr,
        phnum: info.phnum,
        phentsize: info.phentsize,
        segments,
        exec_ranges,
        syscall_sites,
        span: MemRange::reserve(base, span as u64),
        interp: None,
    })
}
