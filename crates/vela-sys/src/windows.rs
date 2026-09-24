//! Windows 宿主实现：VirtualAlloc/VirtualProtect/VirtualFree、std 文件与控制台、
//! VEH（UD2 → dispatch）syscall 陷阱。所有 Win32 FFI 集中在本模块（规格 2.4）。

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use crate::file_ops;
use crate::{
    GuestRegs, Host, HostDir, HostError, HostFile, HostFileKind, HostFileOps, HostMem, HostOpen,
    HostPath, HostProc, HostProt, HostStat, HostTime, HostTls, HostTrap, PipeEnd, StdioHandles,
    TrapFn, TrapFrame,
};

// ---------------------------------------------------------------- Win32 FFI

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_DECOMMIT: u32 = 0x4000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

// 文件映射视图访问位（MapViewOfFileEx dwDesiredAccess）
const FILE_MAP_COPY: u32 = 0x0000_0001;
const FILE_MAP_READ: u32 = 0x0000_0004;
const FILE_MAP_EXECUTE: u32 = 0x0020_0000;

/// Windows 分配粒度：VirtualAlloc 基址与 MapViewOfFileEx 的 lpBaseAddress /
/// 文件偏移都必须对齐到它。x64 平台文档保证 64K；若未来变化需换 GetSystemInfo。
const ALLOC_GRANULARITY: usize = 0x1_0000;

const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(
        lpAddress: *mut c_void,
        dwSize: usize,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;
    fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
    fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;
    fn CreateFileMappingW(
        hFile: *mut c_void,
        lpAttributes: *mut c_void,
        flProtect: u32,
        dwMaximumSizeHigh: u32,
        dwMaximumSizeLow: u32,
        lpName: *const u16,
    ) -> *mut c_void;
    fn MapViewOfFileEx(
        hFileMappingObject: *mut c_void,
        dwDesiredAccess: u32,
        dwFileOffsetHigh: u32,
        dwFileOffsetLow: u32,
        dwNumberOfBytesToMap: usize,
        lpBaseAddress: *mut c_void,
    ) -> *mut c_void;
    fn UnmapViewOfFile(lpBaseAddress: *mut c_void) -> i32;
    #[link_name = "CloseHandle"]
    fn CloseHandle(hObject: isize) -> i32;
    fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
    fn AddVectoredExceptionHandler(
        First: u32,
        Handler: Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32>,
    ) -> *mut c_void;
    fn RemoveVectoredExceptionHandler(Handler: *mut c_void) -> u32;
    fn GetLastError() -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    /// RtlGenRandom 的旧导出名；返回 0 表示失败。
    fn SystemFunction036(RandomBuffer: *mut c_void, RandomBufferLength: u32) -> u8;
}

/// x64 CONTEXT 覆盖视图：只声明我们关心的字段 + 尾部不透明区。
/// 字段偏移与 Win32 CONTEXT 一致（rax=0x78 … rip=0xF8），总大小 0x4D0。
/// 内核要求 CONTEXT 16 字节对齐（XSAVE 域）——NtContinue 直接使用本结构。
#[repr(C, align(16))]
pub struct Context {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub e_flags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    /// FltSave / VectorRegister / Debug 控制等，保持总大小 0x4D0。
    pub tail: [u8; 0x4D0 - 0x100],
}

// GuestRegs 与 CONTEXT 的 RAX..RIP 连续段零拷贝重解释的前提（T1.1）。
const _: () = assert!(std::mem::offset_of!(Context, rax) == 0x78);
const _: () = assert!(std::mem::offset_of!(Context, rip) == 0xF8);
const _: () = assert!(std::mem::offset_of!(Context, e_flags) == 0x44);
const _: () = assert!(std::mem::size_of::<GuestRegs>() == 0x88); // 17×u64（含 rip）

#[repr(C)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub inner: *mut ExceptionRecord,
    pub address: *mut c_void,
    pub num_params: u32,
    pub _pad: u32,
    pub info: [usize; 15],
}

#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut Context,
}

// ---------------------------------------------------------------- VEH 陷阱

const MAX_GUEST_RANGES: usize = 32;
/// start==0 视为空槽（客户基址来自 VirtualAlloc，永远非 0）。
static RANGE_START: [AtomicU64; MAX_GUEST_RANGES] = [const { AtomicU64::new(0) }; MAX_GUEST_RANGES];
static RANGE_END: [AtomicU64; MAX_GUEST_RANGES] = [const { AtomicU64::new(0) }; MAX_GUEST_RANGES];
static TRAP_FN: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicU32 = AtomicU32::new(0);

/// 用新范围集合整体替换已登记范围（PLAN-0.0.5 T1.1：execve 原地重注册）。
/// 前缀覆盖 + 尾部清零，无分配无递归；超过 MAX_GUEST_RANGES 响亮警告。
pub fn replace_guest_exec_ranges(ranges: &[(u64, u64)]) {
    let n = ranges.len().min(MAX_GUEST_RANGES);
    for (i, (s, e)) in ranges.iter().take(n).enumerate() {
        RANGE_START[i].store(*s, Ordering::Relaxed);
        RANGE_END[i].store(*e, Ordering::Relaxed);
    }
    for slot in RANGE_START[n..MAX_GUEST_RANGES].iter() {
        slot.store(0, Ordering::Relaxed);
    }
    for slot in RANGE_END[n..MAX_GUEST_RANGES].iter() {
        slot.store(0, Ordering::Relaxed);
    }
    if ranges.len() > MAX_GUEST_RANGES {
        eprintln!(
            "[vela] warn: exec range table full ({MAX_GUEST_RANGES}), {} ranges NOT registered",
            ranges.len() - MAX_GUEST_RANGES
        );
    }
}

/// 注册 syscall dispatch 回调并安装 VEH（HostTrap::install_trap 的实现体）。
fn install_trap_impl(f: TrapFn) -> Result<(), HostError> {
    TRAP_FN.store(f as usize, Ordering::Relaxed);
    if INSTALLED.swap(1, Ordering::SeqCst) == 1 {
        return Ok(());
    }
    // SAFETY: veh_handler 是有效的 extern "system" 回调
    let h = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
    if h.is_null() {
        let e = file_ops::os_to_errno(unsafe { GetLastError() } as i32);
        Err(HostError::Other(e))
    } else {
        Ok(())
    }
}

fn guest_range_containing(rip: usize) -> Option<(usize, usize)> {
    // 槽按登记顺序填充，遇到空槽即可提前退出（PLAN-0.0.3 T1.3：
    // VEH 热路径每 syscall 调用一次，省掉尾部 30 槽 × 2 次原子 load）
    for (s, e) in RANGE_START.iter().zip(RANGE_END.iter()) {
        let s = s.load(Ordering::Relaxed) as usize;
        if s == 0 {
            break; // 空槽 = 已登记范围的尾部
        }
        let e = e.load(Ordering::Relaxed) as usize;
        if rip >= s && rip + 2 <= e {
            return Some((s, e));
        }
    }
    None
}

/// 方法 C（规格 5.3 已拍板）：UD2 (#UD) → VEH → dispatch → 改写上下文续跑。
unsafe extern "system" fn veh_handler(ep: *mut ExceptionPointers) -> i32 {
    // SAFETY: Windows 保证异常回调参数在回调期间有效
    let ep = unsafe { &*ep };
    let rec = unsafe { &*ep.exception_record };
    // 诊断：客户区内的 AV 记录后放行（second-chance 会正常终止进程）。
    // 无条件打印：崩溃必须始终有解释（stderr 不污染客户 stdout）。
    if rec.exception_code == 0xC000_0005 {
        // SAFETY: 同上
        let ctx = unsafe { &mut *ep.context_record };
        if guest_range_containing(ctx.rip as usize).is_some() {
            // soft-tls（--soft-tls）：fs 前缀 mov 的软件模拟（T4.1）。
            // 重入防护：模拟自身的访存再 AV（TLS 区未映射）不允许递归。
            if SOFT_TLS_ENABLED.load(Ordering::Relaxed) == 1
                && IN_SOFT_EMULATE.swap(1, Ordering::SeqCst) == 0
            {
                let emulated = unsafe { emulate_fs_mov(ctx) };
                IN_SOFT_EMULATE.store(0, Ordering::SeqCst);
                if emulated {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            // SAFETY: rip 在客户映射内（已确认），读 16 字节仅用于诊断
            let bytes = unsafe { std::slice::from_raw_parts(ctx.rip as *const u8, 16) };
            let hb: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
            // fs 段前缀（0x64，可被冗余 66 前缀垫开）开头的 AV，且本机不支持
            // FSGSBASE：几乎必然是客户 TLS 访问（fs 基址未能切换），给出明确
            // 原因而不是裸崩溃
            let skip66 = bytes.iter().take_while(|&&b| b == 0x66).count();
            let fs_prefixed = bytes.get(skip66).map(|&b| b == 0x64).unwrap_or(false);
            let fs_hint = if !fs_base_supported() && fs_prefixed {
                " [hint: FSGSBASE unavailable - guest TLS (fs) cannot be switched; TLS-dependent programs cannot run here]"
            } else {
                ""
            };
            eprintln!(
                "[vela] AV in guest rip={:#x} addr={:#x} op={} rax={:#x} rcx={:#x} rdx={:#x} bytes={}{}",
                ctx.rip,
                { rec.info[1] },
                rec.info[0],
                ctx.rax,
                ctx.rcx,
                ctx.rdx,
                hb.join(" "),
                fs_hint
            );
            // 客户段内的 AV 一律致命：first-chance 放行只会落到不可控的
            // second-chance 崩溃（0xC0000005 原始码）。这里以 Linux 语义规范化
            // 退出码 128+SIGSEGV(11)=139，stdio 经 atexit 正常冲刷。
            std::process::exit(139);
        }
        // 宿主侧 AV（vela 自身代码）：打印诊断后放行（second-chance 终止，
        // 但崩溃始终有解释——spec 12）
        {
            let ctx = unsafe { &*ep.context_record };
            eprintln!(
                "[vela] host-side AV rip={:#x} addr={:#x} op={}",
                ctx.rip,
                { rec.info[1] },
                rec.info[0]
            );
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if rec.exception_code != STATUS_ILLEGAL_INSTRUCTION
        && rec.exception_code != STATUS_PRIVILEGED_INSTRUCTION
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: 同上
    let ctx_ptr = ep.context_record;
    let ctx = unsafe { &mut *ctx_ptr };
    let rip = ctx.rip as usize;
    // FS commit stub：预切后的 ud2+ret，直接跳过 ud2 让 ret 返回调用者。
    // 必须在 guest range 过滤之前判断（stub 位于 vela.exe 自身代码段）。
    let commit_stub = vela_fs_commit_stub as *const () as usize;
    if rip >= commit_stub && rip < commit_stub + 4 {
        ctx.rip = rip as u64 + 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    let Some(_range) = guest_range_containing(rip) else {
        // rip 在已注册的 UD2 之外：exec-range 表与执行现场脱节
        //（典型：fork 恢复/execve 重载后注册表未覆盖新入口）
        eprintln!(
            "[vela] UD2 outside guest ranges at rip={:#x} (stale exec-range registration)",
            rip
        );
        return EXCEPTION_CONTINUE_SEARCH;
    };
    // 客户段内的 #GP（特权指令）：与 AV 同样致命，给出 rip/字节便于定位
    // （M2 排障：wrfsbase 等在 CR4.FSGSBASE 关闭时触发 #GP）
    if rec.exception_code == STATUS_PRIVILEGED_INSTRUCTION {
        // SAFETY: rip 在客户映射内（已确认），读 16 字节仅用于诊断
        let bytes = unsafe { std::slice::from_raw_parts(rip as *const u8, 16) };
        let hb: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "[vela] privileged instruction in guest rip={:#x} bytes={} (hint: privileged opcode executed by guest; if this is rdfsbase/wrfsbase, CR4.FSGSBASE is off)",
            rip,
            hb.join(" ")
        );
        std::process::exit(139);
    }
    // 确认该位置确为 patch 点（UD2），避免吞掉客户真实的非法指令
    // SAFETY: rip..rip+2 已确认位于客户可执行映射内
    let code = unsafe { std::slice::from_raw_parts(rip as *const u8, 2) };
    if code != [0x0F, 0x0B] {
        let hb: Vec<String> = unsafe { std::slice::from_raw_parts(rip as *const u8, 16) }
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        eprintln!(
            "[vela] ILLEGAL_INSTRUCTION at rip={:#x} is NOT a patch point: bytes={hb:?} (execution ran off-script — check fork/execve rip restore)",
            rip
        );
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let raw = TRAP_FN.load(Ordering::Relaxed);
    if raw == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: 由 CLI 在进入客户前注册的有效函数指针
    let tf: TrapFn = unsafe { std::mem::transmute(raw) };
    let nr = ctx.rax;
    // Linux syscall 约定：第 4 参在 R10 而非 RCX（规格 5.3）
    let args = [ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10, ctx.r8, ctx.r9];
    // 寄存器视图：GuestRegs 零拷贝重解释 CONTEXT 的 RAX..RIP 连续段
    // （布局断言锁定）；回调对 regs 的写回直接落入 CONTEXT。
    // SAFETY: ctx 指向内核提供的有效 CONTEXT，回调期间有效；GuestRegs
    // 布局与该连续段一致（上方 const 断言）。regs（&mut）与 opaque（&）
    // 指向同一 CONTEXT 是刻意的双视图：寄存器段独占写、全量字节独占读，
    // 二者生命周期均限于本回调，无并发访问者。
    let regs = unsafe { &mut *(std::ptr::addr_of_mut!((*ctx_ptr).rax) as *mut GuestRegs) };
    let e_flags = ctx.e_flags as u64;
    let mut frame = TrapFrame::new(regs, e_flags, ctx_ptr as *const u8, 0x4D0);
    // SAFETY: 回调由 CLI 注册，内部仅操作客户进程状态与异常上下文
    let _ret = unsafe { tf(nr, &args, &mut frame) };
    // syscall 模拟（rax/rcx/r11/rip 推进）与控制流改写均由回调完成
    EXCEPTION_CONTINUE_EXECUTION
}

/// 控制台输出切 UTF-8（规格 7.2）。
pub fn set_console_utf8() {
    // SAFETY: 无参数约束
    unsafe { SetConsoleOutputCP(65001) };
}

// ------------------------------------------------------- Soft TLS（--soft-tls）
//
// FSGSBASE 缺失的环境（Hyper-V/云 VM/VBS，PLAN-0.0.4 T4.1/T4.2）：客户的
// arch_prctl(SET_FS) 只记录基址、FS 段寄存器无法真实切换，客户任何 fs 前缀
// 访问都会 AV。--soft-tls 开启后，VEH 对客户段内 fs 前缀的 mov 指令做软件
// 模拟：以记录的客户 TLS 基址计算有效地址、代为读写内存、Rip 前进。
// 覆盖 musl 实际发射的有限形态（mov r, fs:[mem] / mov fs:[mem], r）；
// 未覆盖形态仍按致命路径退出并输出指令字节。诊断/CI 可用，性能不承诺。

static SOFT_TLS_ENABLED: AtomicU32 = AtomicU32::new(0);
/// 客户侧 TLS 基址（proc.fs_base 由 CLI 在每次 syscall 陷阱时同步）。
static SOFT_TLS_BASE: AtomicU64 = AtomicU64::new(0);
/// 模拟重入防护：模拟自身的读写若再触发 AV（TLS 区未映射等），不允许递归。
static IN_SOFT_EMULATE: AtomicU32 = AtomicU32::new(0);
static SOFT_TLS_WARNED: AtomicU32 = AtomicU32::new(0);

pub fn enable_soft_tls() {
    SOFT_TLS_ENABLED.store(1, Ordering::Relaxed);
}

pub fn set_soft_tls_base(v: u64) {
    SOFT_TLS_BASE.store(v, Ordering::Relaxed);
}

/// fs 前缀 mov 的解码结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FsMov {
    /// 指令总长（Rip 前进量）。
    len: usize,
    /// true = 读内存入寄存器（8b），false = 写寄存器入内存（89）。
    load: bool,
    /// REX.R/B 扩展后的寄存器编号（0..15）。
    reg: usize,
    /// 内存操作数描述（不含 FS 基址）：RIP 相对时 effective = rip_next + disp，
    /// 否则 effective = base + idx*scale + disp（各分量可为 0）。
    rip_rel: bool,
    base: usize,
    idx: usize,
    scale: usize,
    disp: i64,
}

/// 解码 `[66]* 64 [REX] 8b/89 modrm [sib] [disp]`。不认识/非内存形态返回 None。
/// 0x66 前缀容忍：musl 汇编常用冗余 66 做对齐填充（实测 file-io 的 getcwd
/// 路径 `66 66 66 64 48 8b …`）——有 REX.W 时操作数仍为 64 位，语义不变。
fn decode_fs_mov(b: &[u8]) -> Option<FsMov> {
    let mut i = 0;
    while i < b.len() && b[i] == 0x66 {
        i += 1;
    }
    if i >= b.len() || b[i] != 0x64 {
        return None;
    }
    i += 1;
    let mut rex = 0u8;
    if i < b.len() && b[i] & 0xF0 == 0x40 {
        rex = b[i];
        i += 1;
    }
    let rex_w = rex & 0x08 != 0;
    if !rex_w {
        return None; // 仅 64 位操作数（musl 只发 64 位 TLS 访问）
    }
    if i >= b.len() {
        return None;
    }
    let op = b[i];
    i += 1;
    let (load, reg_ext) = match op {
        0x8b => (true, (rex & 0x04) != 0),
        0x89 => (false, (rex & 0x04) != 0),
        _ => return None,
    };
    if i >= b.len() {
        return None;
    }
    let modrm = b[i];
    i += 1;
    let mode = modrm >> 6;
    let reg = (((modrm >> 3) & 7) as usize) | if reg_ext { 8 } else { 0 };
    // SIB 存在性由 modrm.rm == 4 决定（REX.B 扩展之前）
    let raw_rm = (modrm & 7) as usize;
    let mut rm = raw_rm;
    if rex & 0x01 != 0 {
        rm |= 8;
    }
    let mut m = FsMov {
        len: i,
        load,
        reg,
        rip_rel: false,
        base: 0,
        idx: usize::MAX, // usize::MAX = 无变址
        scale: 1,
        disp: 0,
    };
    match mode {
        3 => return None, // 寄存器对寄存器，不会 AV
        0 => {
            if rm == 5 {
                // RIP 相对
                if i + 4 > b.len() {
                    return None;
                }
                m.rip_rel = true;
                m.disp = i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as i64;
                i += 4;
            } else {
                if raw_rm == 4 {
                    // SIB
                    if i >= b.len() {
                        return None;
                    }
                    let sib = b[i];
                    i += 1;
                    m.scale = 1 << (sib >> 6);
                    let idx_raw = ((sib >> 3) & 7) as usize;
                    // SIB idx=4 且无 REX.X = 无变址
                    if idx_raw != 4 || rex & 0x02 != 0 {
                        m.idx = idx_raw | if rex & 0x02 != 0 { 8 } else { 0 };
                    }
                    let base_raw = (sib & 7) as usize;
                    if base_raw == 5 {
                        // mod=00 + SIB base=5：编码上必有 disp32。
                        // REX.B=0 → disp32 绝对（fs:0 形态，无基址）；
                        // REX.B=1 → 基址 r13 + disp32。
                        if i + 4 > b.len() {
                            return None;
                        }
                        m.disp = i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as i64;
                        i += 4;
                        if rex & 0x01 != 0 {
                            m.base = 13;
                        }
                        m.idx = usize::MAX; // 绝对形态忽略变址（musl 不发射）
                    } else {
                        m.base = base_raw | if rex & 0x01 != 0 { 8 } else { 0 };
                    }
                } else {
                    m.base = rm;
                }
            }
        }
        1 => {
            // x86 编码顺序：modrm → SIB → disp8
            let mut rm2 = (modrm & 7) as usize;
            if rm2 == 4 {
                if i >= b.len() {
                    return None;
                }
                let sib = b[i];
                i += 1;
                m.scale = 1 << (sib >> 6);
                m.idx = (((sib >> 3) & 7) as usize) | if rex & 0x02 != 0 { 8 } else { 0 };
                rm2 = (sib & 7) as usize | if rex & 0x01 != 0 { 8 } else { 0 };
            }
            if i >= b.len() {
                return None;
            }
            m.disp = b[i] as i8 as i64;
            i += 1;
            m.base = rm2;
        }
        2 => {
            // x86 编码顺序：modrm → SIB → disp32
            let mut rm2 = (modrm & 7) as usize;
            if rm2 == 4 {
                if i >= b.len() {
                    return None;
                }
                let sib = b[i];
                i += 1;
                m.scale = 1 << (sib >> 6);
                m.idx = (((sib >> 3) & 7) as usize) | if rex & 0x02 != 0 { 8 } else { 0 };
                rm2 = (sib & 7) as usize | if rex & 0x01 != 0 { 8 } else { 0 };
            }
            if i + 4 > b.len() {
                return None;
            }
            m.disp = i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as i64;
            i += 4;
            m.base = rm2;
        }
        _ => return None,
    }
    m.len = i;
    Some(m)
}

/// ctx 中编号 0..15 的 64 位寄存器（rax..r15，与 Context 字段顺序一致）。
unsafe fn ctx_reg(ctx: &mut Context, idx: usize) -> u64 {
    // SAFETY: rax..r15 在 Context 中连续排列（repr(C)，偏移 0x78..0xF0）
    let base = std::ptr::addr_of_mut!(ctx.rax);
    unsafe { *(base.add(idx)) }
}

/// soft-tls 模拟：成功时写回寄存器/内存并前进 Rip，返回 true。
unsafe fn emulate_fs_mov(ctx: &mut Context) -> bool {
    let rip = ctx.rip as usize;
    // SAFETY: rip 在客户映射内（调用方已用 exec range 确认）
    let bytes = unsafe { std::slice::from_raw_parts(rip as *const u8, 16) };
    let Some(m) = decode_fs_mov(bytes) else {
        return false;
    };
    let fs = SOFT_TLS_BASE.load(Ordering::Relaxed);
    if fs == 0 {
        return false; // arch_prctl(SET_FS) 尚未发生：不是可模拟的 TLS 访问
    }
    let rip_next = (rip + m.len) as u64;
    let effective: u64 = if m.rip_rel {
        (rip_next as i64).wrapping_add(m.disp) as u64
    } else {
        let mut a: i64 = m.disp;
        if m.base != 0 {
            a = a.wrapping_add(unsafe { ctx_reg(ctx, m.base) } as i64);
        }
        if m.idx != usize::MAX {
            a = a
                .wrapping_add((unsafe { ctx_reg(ctx, m.idx) }.wrapping_mul(m.scale as u64)) as i64);
        }
        (fs as i64).wrapping_add(a) as u64
    };
    if SOFT_TLS_WARNED.swap(1, Ordering::Relaxed) == 0 {
        eprintln!(
            "[vela] soft-tls: emulating fs-prefixed access at {:#x} (slow path; diagnostics/CI only, no performance promise)",
            rip
        );
    }
    // SAFETY: TLS 区由客户自行映射；地址无效时嵌套 AV 由重入防护兜底
    if m.load {
        let v = unsafe { (effective as *const u64).read_unaligned() };
        unsafe {
            *(std::ptr::addr_of_mut!(ctx.rax).add(m.reg)) = v;
        }
    } else {
        let v = unsafe { ctx_reg(ctx, m.reg) };
        unsafe { (effective as *mut u64).write_unaligned(v) };
    }
    ctx.rip = rip_next;
    true
}

// ------------------------------------------------------- FS 基址（客户 TLS）
//
// 关键事实（本机实测）：在 VEH 处理器内执行 wrfsbase 会被 NtContinue 还原
// （内核保存/恢复异常现场的用户 FS 基址）。因此 FS 切换必须发生在异常完全
// 返回之后的纯用户态：
//   dispatch 记录 fs_apply_pending → trap 改写 CONTEXT：Rip 指向 vela.exe 内的
//   trampoline（wrfsbase r10; jmp rcx）→ 客户在无内核参与的情况下完成切换；
//   之后的每次异常，内核保存/恢复的都已是客户基址，保持稳定。
// VELA 自身代码不使用 FS（Windows x64 用户态 TEB 在 GS），切换后无需恢复。

// 0=未探测 1=可用 2=不可用
static FS_BASE_MODE: AtomicU32 = AtomicU32::new(0);
static VELA_PROBE_ACTIVE: AtomicU32 = AtomicU32::new(0);
// 以下两个会被探测汇编直接读写（原子仅防编译器跨 extern 调用折叠读取）
#[no_mangle]
static VELA_PROBE_OUT: AtomicU32 = AtomicU32::new(0);
#[no_mangle]
static VELA_PROBE_RESUME: AtomicUsize = AtomicUsize::new(0);
/// trampoline 命中标记（调试用）：stub 执行时由汇编写 1。
#[no_mangle]
pub static VELA_STUB_HIT: AtomicU64 = AtomicU64::new(0);

// 探测：wrfsbase 成功 → OUT=1；#UD → probe_ud_handler 置 OUT=0 并跳到 fail 标签。
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl vela_probe_fs_start",
    "vela_probe_fs_start:",
    "    lea rax, [rip + vela_probe_fs_fail]",
    "    mov QWORD PTR [rip + VELA_PROBE_RESUME], rax",
    "    xor eax, eax",
    "    wrfsbase rax",
    "    mov DWORD PTR [rip + VELA_PROBE_OUT], 1",
    "vela_probe_fs_fail:",
    "    ret",
);

// FS 切换 trampoline：r10 = 新基址，rcx = 客户返回地址。
// 在异常返回后的用户态执行，基址不再被内核还原。
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl vela_set_fs_stub",
    "vela_set_fs_stub:",
    "    mov QWORD PTR [rip + VELA_STUB_HIT], 1",
    "    wrfsbase r10",
    "    jmp rcx",
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn vela_probe_fs_start();
    static vela_set_fs_stub: u8;
}

fn cpu_has_fsgsbase() -> bool {
    // __cpuid 是 std 中的安全内置函数
    if std::arch::x86_64::__cpuid(0).eax < 7 {
        return false;
    }
    std::arch::x86_64::__cpuid(7).ebx & (1 << 1) != 0
}

/// 探测期间的一次性 #UD 处理器：只认 PROBE_ACTIVE 且未注册主 trap 时的场景。
unsafe extern "system" fn probe_ud_handler(ep: *mut ExceptionPointers) -> i32 {
    if VELA_PROBE_ACTIVE.load(Ordering::Relaxed) == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: Windows 保证异常回调参数在回调期间有效
    let rec = unsafe { &*(*ep).exception_record };
    if rec.exception_code != STATUS_ILLEGAL_INSTRUCTION {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: 同上
    let ctx = unsafe { &mut *(*ep).context_record };
    VELA_PROBE_OUT.store(0, Ordering::Relaxed);
    let resume = VELA_PROBE_RESUME.load(Ordering::Relaxed);
    if resume == 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ctx.rip = resume as u64;
    EXCEPTION_CONTINUE_EXECUTION
}

#[cfg(target_arch = "x86_64")]
unsafe fn run_fs_probe() -> bool {
    VELA_PROBE_OUT.store(0, Ordering::Relaxed);
    VELA_PROBE_ACTIVE.store(1, Ordering::Relaxed);
    // SAFETY: probe_ud_handler 是有效的 VEH 回调
    let h = unsafe { AddVectoredExceptionHandler(1, Some(probe_ud_handler)) };
    // SAFETY: 探测函数只含 wrfsbase；#UD 由 probe_ud_handler 恢复到 fail 标签
    unsafe { vela_probe_fs_start() };
    if !h.is_null() {
        // SAFETY: h 来自配对注册
        unsafe { RemoveVectoredExceptionHandler(h) };
    }
    VELA_PROBE_ACTIVE.store(0, Ordering::Relaxed);
    VELA_PROBE_OUT.load(Ordering::Relaxed) == 1
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn run_fs_probe() -> bool {
    false
}

/// 运行时探测 wrfsbase（CPU FSGSBASE + OS 启用 CR4.FSGSBASE）。幂等。
/// 建议 CLI 在进入客户前调用一次；未调用时首次 set_fs_base 会惰性探测。
pub fn probe_fs_base_support() -> bool {
    match FS_BASE_MODE.load(Ordering::Relaxed) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let ok = if cpu_has_fsgsbase() {
        // SAFETY: 探测函数与处理器配对
        unsafe { run_fs_probe() }
    } else {
        false
    };
    FS_BASE_MODE.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
    ok
}

/// 查询 FS 基址切换能力（缓存探测结果）。
pub fn fs_base_supported() -> bool {
    probe_fs_base_support()
}

/// FS 切换 trampoline 的宿主地址（vela.exe 自身代码段）。
/// 客户恢复执行时 Rip 指向它：`wrfsbase r10; jmp rcx`。
pub fn set_fs_stub_addr() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // 只取符号地址，不解引用（extern static 的 addr_of! 无需 unsafe）
        std::ptr::addr_of!(vela_set_fs_stub) as usize
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

/// trampoline 是否被实际执行过（调试观测）。
pub fn stub_hit() -> bool {
    VELA_STUB_HIT.load(Ordering::Relaxed) == 1
}

/// 读取当前线程 FS 基址（需 FSGSBASE；不支持时返回 None）。
pub fn read_fs_base() -> Option<u64> {
    if !fs_base_supported() {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        let v: u64;
        // SAFETY: 已探测确认 FSGSBASE 可用
        unsafe { core::arch::asm!("rdfsbase {0}", out(reg) v) };
        Some(v)
    }
    #[cfg(not(target_arch = "x86_64"))]
    None
}

/// 直接设置当前线程 FS 基址（用户态 wrfsbase，无内核还原问题；
/// 仅用于进入客户前的预切场景，VEH 处理器内请勿调用）。
pub fn set_thread_fs_base_now(v: u64) -> Result<(), HostError> {
    if !fs_base_supported() {
        return Err(HostError::Unimplemented);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: 已探测确认 FSGSBASE 可用；VELA 自身不依赖 FS
    unsafe {
        core::arch::asm!("wrfsbase {0}", in(reg) v)
    };
    #[cfg(not(target_arch = "x86_64"))]
    let _ = v;
    Ok(())
}

/// 预切后强制一次内核侧 FS 基址刷新：触发一个被 VEH 吞掉的 UD2，
/// NtContinue 返回时内核按当前（已预切的）基址重建保存值。
/// 此后内核偶发还原的也是客户侧基址而非陈旧宿主值/0。
pub fn commit_fs_base_after_preset() {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: vela_fs_commit_stub 只含 ud2 与 ret；UD2 由已注册的 probe 处理器吸收
    unsafe {
        vela_fs_commit_stub()
    };
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl vela_fs_commit_stub",
    "vela_fs_commit_stub:",
    "    ud2",
    "    ret",
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn vela_fs_commit_stub();
}

#[derive(Debug)]
pub struct WindowsHost {
    start: Instant,
}

impl WindowsHost {
    pub fn new() -> Self {
        WindowsHost {
            start: Instant::now(),
        }
    }
}

impl Default for WindowsHost {
    fn default() -> Self {
        Self::new()
    }
}

fn protect_flag(p: HostProt) -> Result<u32, HostError> {
    Ok(match p.bits() {
        0 => PAGE_NOACCESS,
        1 => PAGE_READONLY,
        2 | 3 => PAGE_READWRITE,
        4 => PAGE_EXECUTE,
        5 => PAGE_EXECUTE_READ,
        6 | 7 => PAGE_EXECUTE_READWRITE, // W+X：v0 接受（见规格 5.2 W^X 说明）
        _ => return Err(HostError::Invalid),
    })
}

impl HostMem for WindowsHost {
    unsafe fn map(
        &self,
        hint: usize,
        len: usize,
        _prot: HostProt,
        anon: bool,
    ) -> Result<usize, HostError> {
        if !anon {
            return Err(HostError::Unimplemented); // v0 仅匿名映射（规格 2.1）
        }
        if len == 0 {
            return Err(HostError::Invalid);
        }
        let flags = MEM_COMMIT | MEM_RESERVE;
        // SAFETY: len>0；分配仅作用于本进程地址空间
        let mut p = unsafe { VirtualAlloc(hint as *mut c_void, len, flags, PAGE_READWRITE) };
        if p.is_null() && hint != 0 {
            // PIE 客户可接受任意基址（规格 14）：hint 冲突则让系统自选
            p = unsafe { VirtualAlloc(std::ptr::null_mut(), len, flags, PAGE_READWRITE) };
        }
        if p.is_null() {
            Err(HostError::NoMemory)
        } else {
            Ok(p as usize)
        }
    }

    unsafe fn protect(&self, addr: usize, len: usize, prot: HostProt) -> Result<(), HostError> {
        if len == 0 {
            return Ok(());
        }
        let flag = protect_flag(prot)?;
        let mut old = 0u32;
        // SAFETY: addr..addr+len 属于已提交页面（调用方保证）
        if unsafe { VirtualProtect(addr as *mut c_void, len, flag, &mut old) } == 0 {
            Err(HostError::Invalid)
        } else {
            Ok(())
        }
    }

    unsafe fn unmap(&self, addr: usize, _len: usize) -> Result<(), HostError> {
        // Windows 仅能按 reserve 基址整块释放（规格 5.2）；runtime 已按整块登记
        // SAFETY: addr 为 VirtualAlloc 返回的基址，失败由调用方按 best-effort 处理
        if unsafe { VirtualFree(addr as *mut c_void, 0, MEM_RELEASE) } == 0 {
            Err(HostError::Invalid)
        } else {
            Ok(())
        }
    }

    unsafe fn map_file(
        &self,
        file: &HostFile,
        offset: u64,
        len: usize,
        hint: usize,
        prot: HostProt,
    ) -> Result<usize, HostError> {
        if len == 0 {
            return Err(HostError::Invalid);
        }
        if !offset.is_multiple_of(ALLOC_GRANULARITY as u64) {
            return Err(HostError::Invalid);
        }
        if hint != 0 && !hint.is_multiple_of(ALLOC_GRANULARITY) {
            return Err(HostError::Invalid);
        }
        let crate::HostFile(HostFileKind::Disk { file, .. }) = file else {
            return Err(HostError::Invalid); // stdio / 匿名句柄无文件背书
        };
        // MAP_PRIVATE：写入绝不回写文件。可写视图一律走 COW（PAGE_*WRITECOPY +
        // FILE_MAP_COPY）；此时绝不可再对该视图 VirtualProtect 成 PAGE_READWRITE，
        // 那会关闭 COW 并把后续写入穿透到宿主文件（runtime 层已规避）。
        let (map_prot, view_access) = match (
            prot.contains(HostProt::WRITE),
            prot.contains(HostProt::EXEC),
        ) {
            (true, true) => (PAGE_EXECUTE_WRITECOPY, FILE_MAP_COPY | FILE_MAP_EXECUTE),
            (true, false) => (PAGE_WRITECOPY, FILE_MAP_COPY),
            (false, true) => (PAGE_EXECUTE_READ, FILE_MAP_READ | FILE_MAP_EXECUTE),
            (false, false) => (PAGE_READONLY, FILE_MAP_READ),
        };
        // SAFETY: file 为有效打开的宿主文件句柄；其余参数均为文档允许的取值
        let handle = unsafe {
            CreateFileMappingW(
                file.0.as_raw_handle(),
                std::ptr::null_mut(),
                map_prot,
                0,
                0,
                std::ptr::null(),
            )
        };
        if handle.is_null() || handle as isize == -1 {
            return Err(HostError::Other(file_ops::os_to_errno(
                unsafe { GetLastError() } as i32,
            )));
        }
        // 视图创建失败也要释放映射对象（视图本身持有引用，先建视图再关句柄）
        let base = unsafe {
            MapViewOfFileEx(
                handle,
                view_access,
                (offset >> 32) as u32,
                offset as u32,
                len,
                hint as *mut c_void,
            )
        };
        let closed = unsafe { CloseHandle(handle as isize) } != 0;
        if base.is_null() || !closed {
            if !base.is_null() {
                // SAFETY: base 来自配对的 MapViewOfFileEx
                unsafe { UnmapViewOfFile(base) };
            }
            // hint 冲突 / 资源不足：交给 runtime 走读入私有副本回退
            return Err(HostError::NoMemory);
        }
        Ok(base as usize)
    }

    unsafe fn unmap_view(&self, addr: usize) -> Result<(), HostError> {
        // SAFETY: addr 为 MapViewOfFileEx 返回的视图基址（MemRegistry 登记保证）
        if unsafe { UnmapViewOfFile(addr as *mut c_void) } == 0 {
            Err(HostError::Invalid)
        } else {
            Ok(())
        }
    }

    unsafe fn decommit(&self, addr: usize, len: usize) -> Result<(), HostError> {
        if len == 0 {
            return Ok(());
        }
        // SAFETY: addr..addr+len 属于本宿主分配的 reserve（调用方保证）
        if unsafe { VirtualFree(addr as *mut c_void, len, MEM_DECOMMIT) } == 0 {
            Err(HostError::Invalid)
        } else {
            Ok(())
        }
    }
}

impl HostFileOps for WindowsHost {
    fn open(&self, path: &HostPath, opt: HostOpen) -> Result<HostFile, HostError> {
        file_ops::open(path, opt)
    }
    fn open_dir(&self, path: &HostPath) -> Result<HostDir, HostError> {
        file_ops::open_dir(path)
    }
    fn mkdir(&self, path: &HostPath) -> Result<(), HostError> {
        file_ops::mkdir(path)
    }
    fn remove(&self, path: &HostPath, dir: bool) -> Result<(), HostError> {
        file_ops::remove(path, dir)
    }
    fn rename(&self, old: &HostPath, new: &HostPath) -> Result<(), HostError> {
        file_ops::rename(old, new)
    }
    fn sync_file(&self, f: &HostFile, data_only: bool) -> Result<(), HostError> {
        file_ops::sync_file(f, data_only)
    }
    fn dup_file(&self, f: &HostFile) -> Result<HostFile, HostError> {
        file_ops::dup_file(f)
    }
    fn read(&self, f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError> {
        file_ops::read(f, buf)
    }
    fn write(&self, f: &HostFile, buf: &[u8]) -> Result<usize, HostError> {
        file_ops::write(f, buf)
    }
    fn seek(&self, f: &HostFile, off: i64, whence: i32) -> Result<u64, HostError> {
        file_ops::seek(f, off, whence)
    }
    fn stat_path(&self, path: &HostPath) -> Result<HostStat, HostError> {
        file_ops::stat_path(path)
    }
    fn stat_file(&self, f: &HostFile) -> Result<HostStat, HostError> {
        file_ops::stat_file(f)
    }
    fn set_len(&self, f: &HostFile, len: u64) -> Result<(), HostError> {
        file_ops::set_len(f, len)
    }
    fn set_readonly_file(&self, f: &HostFile, readonly: bool) -> Result<(), HostError> {
        file_ops::set_readonly(f, readonly)
    }
    fn close(&self, f: HostFile) -> Result<(), HostError> {
        file_ops::close(f)
    }
    fn stdio(&self) -> StdioHandles {
        file_ops::stdio()
    }
    fn create_pipe(&self) -> Result<(HostFile, HostFile), HostError> {
        file_ops::create_pipe()
    }
}

impl HostTime for WindowsHost {
    fn monotonic_ns(&self) -> u64 {
        file_ops::monotonic_ns(&self.start)
    }
    fn realtime(&self) -> (i64, u32) {
        file_ops::realtime()
    }
    fn random(&self, buf: &mut [u8]) -> Result<(), HostError> {
        if buf.is_empty() {
            return Ok(());
        }
        // SAFETY: 指针/长度来自调用方切片
        let ok = unsafe { SystemFunction036(buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
        if ok == 0 {
            let e = file_ops::os_to_errno(unsafe { GetLastError() } as i32);
            Err(HostError::Other(e))
        } else {
            Ok(())
        }
    }
}

impl HostTls for WindowsHost {
    fn set_fs_base(&self, _v: u64) -> Result<(), HostError> {
        // 仅报告能力；真正的 FS 切换由 CLI 的 trampoline 在异常返回后完成
        // （处理器内 wrfsbase 会被 NtContinue 还原，见本模块 FS 注释）。
        if fs_base_supported() {
            Ok(())
        } else {
            Err(HostError::Unimplemented)
        }
    }
}

impl Host for WindowsHost {
    fn thread_exit(&self, code: i32) -> ! {
        // v0 单线程模型：线程退出即进程退出（规格 2.1）
        std::process::exit(code)
    }
    fn process_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
}

// ---------------------------------------------------------------- HostTrap / HostProc（0.1.0 T1.1/T1.2）

impl HostTrap for WindowsHost {
    fn install_trap(&self, f: TrapFn) -> Result<(), HostError> {
        install_trap_impl(f)
    }

    fn replace_exec_ranges(&self, ranges: &[(u64, u64)]) {
        replace_guest_exec_ranges(ranges);
    }

    unsafe fn enter_guest(&self, entry: u64, rsp: u64) -> ! {
        // SAFETY: entry/rsp 由调用方保证来自已映射登记的客户映像；不返回
        unsafe { vela_enter_guest(entry, rsp) }
    }

    fn fs_base_supported(&self) -> bool {
        fs_base_supported()
    }
    fn preset_fs_base(&self, v: u64) -> Result<(), HostError> {
        set_thread_fs_base_now(v)
    }
    fn commit_fs_base(&self) {
        commit_fs_base_after_preset();
    }
    fn read_fs_base(&self) -> Option<u64> {
        read_fs_base()
    }
    fn fs_trampoline_addr(&self) -> usize {
        set_fs_stub_addr()
    }
    fn enable_soft_tls(&self) {
        enable_soft_tls();
    }
    fn set_soft_tls_base(&self, v: u64) {
        set_soft_tls_base(v);
    }
    fn soft_tls_stub_hit(&self) -> bool {
        stub_hit()
    }
}

impl HostProc for WindowsHost {
    fn shared_section(&self, size: u64) -> Result<isize, HostError> {
        create_shared_section(size)
    }
    unsafe fn map_section_anywhere(&self, sec: isize) -> Result<usize, HostError> {
        // SAFETY: sec 为 create_shared_section 返回的有效 section
        map_section_anywhere(sec, 0)
    }
    unsafe fn map_section_at(&self, sec: isize, base: u64) -> Result<usize, HostError> {
        // SAFETY: sec 有效；base 为空闲地址（调用方保证）
        map_section_at(sec, base, 0)
    }
    fn unmap_section_view(&self, addr: usize) -> Result<(), HostError> {
        unmap_section_view(addr)
    }
    fn set_inherit(&self, handle: isize) -> Result<(), HostError> {
        set_handle_inherit(handle)
    }
    fn spawn_self(&self, cmdline: &str) -> Result<(u32, isize), HostError> {
        let c = create_child_process(cmdline)?;
        Ok((c.pid, c.handle))
    }
    fn wait(&self, proc: isize, timeout_ms: u32) -> Result<Option<u32>, HostError> {
        wait_child(proc, timeout_ms)
    }
    fn kill(&self, proc: isize, code: u32) -> Result<(), HostError> {
        terminate_child(proc, code)
    }
    fn open_process(&self, pid: u32) -> Result<isize, HostError> {
        open_process_handle(pid)
    }
    fn close_handle(&self, handle: isize) {
        close_handle(handle);
    }
    fn create_inherit_pipe(&self) -> Result<(isize, isize), HostError> {
        create_inherit_pipe()
    }
    fn pipe_write_all(&self, h: isize, data: &[u8]) -> Result<(), HostError> {
        pipe_write_all(h, data)
    }
    fn pipe_read_exact(&self, h: isize, buf: &mut [u8]) -> Result<(), HostError> {
        pipe_read_exact(h, buf)
    }
    fn pipe_end_from_raw(&self, h: isize, is_read: bool) -> PipeEnd {
        pipe_from_raw_handle(h, is_read)
    }
    fn fork_child_context(&self, frame: &TrapFrame) -> Vec<u8> {
        // 父 CONTEXT 全量快照（含 XSAVE：子进程必须继承浮点/向量现场）
        let mut b = frame.opaque_bytes().to_vec();
        assert_eq!(b.len(), 0x4D0, "CONTEXT snapshot size");
        // 模拟 syscall 副作用：Rax=0（子返回值）、Rip/Rcx=返回地址、R11=RFLAGS
        let ret = frame.regs.rip + 2;
        b[0xF8..0x100].copy_from_slice(&ret.to_le_bytes()); // rip
        b[0x78..0x80].copy_from_slice(&0u64.to_le_bytes()); // rax
        b[0x80..0x88].copy_from_slice(&ret.to_le_bytes()); // rcx
        b[0xD0..0xD8].copy_from_slice(&frame.e_flags.to_le_bytes()); // r11
                                                                     // context_flags = CONTEXT_ALL（0x10003F）：VEH 的 flags 带异常请求位，
                                                                     // NtContinue 按位恢复——必须显式要求全量（Control|Integer|Segments|
                                                                     // FloatingPoint|DebugRegisters | CONTEXT_AMD64），否则 NtContinue 返回。
        b[0x30..0x34].copy_from_slice(&0x0010_003Fu32.to_le_bytes());
        b
    }
    unsafe fn resume_child(&self, ctx: &[u8]) -> ! {
        // SAFETY: ctx 来自 fork_child_context（0x4D0 完整 CONTEXT）；
        // 客户栈/代码/堆已按快照恢复并登记（调用方保证）
        unsafe { continue_with_bytes(ctx) }
    }
}

/// 注入完整 CONTEXT 后进入客户（fork 子进程恢复现场；不返回）。
/// 字节接口（HostProc::resume_child 的实现体）：0x4D0 完整 CONTEXT，
/// 16 字节对齐由栈上副本保证（NtContinue 的 XSAVE 域要求）。
unsafe fn continue_with_bytes(bytes: &[u8]) -> ! {
    assert_eq!(bytes.len(), 0x4D0, "fork child CONTEXT size");
    #[link(name = "ntdll")]
    extern "system" {
        fn NtContinue(ctx: *mut Context, alert: i32) -> i32;
    }
    let mut aligned: Context = unsafe { std::mem::zeroed() };
    // SAFETY: 同类型字节拷贝；对齐由 aligned 自身的 repr(C, align(16)) 保证。
    // 元数据字节缓冲无对齐保证，不能直接重解释——先落到对齐副本再交给内核。
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut aligned as *mut Context as *mut u8,
            0x4D0,
        );
        NtContinue(&mut aligned as *mut Context, 0)
    };
    unreachable!("NtContinue returned")
}

// Win64 ABI：参数在 rcx(entry)/rdx(rsp)。Vela 自身汇编边界用 Win64；客户内部用 SysV（规格 6）。
// （0.1.0 T1.1 自 CLI guest_start.rs 迁入：切入客户属于 HostTrap 契约。）
#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".globl vela_enter_guest",
    "vela_enter_guest:",
    "    mov rsp, rdx",
    "    xor ebp, ebp",
    "    xor ebx, ebx",
    "    jmp rcx",
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    fn vela_enter_guest(entry: u64, rsp: u64) -> !;
}

// ---------------------------------------------------------------- 进程与跨进程内存（0.0.6 M1：用户态 fork）

/// CreateProcess 产物：pid 与常驻 hProcess（wait4/kill 用）。
pub struct ChildProcess {
    pub pid: u32,
    pub handle: isize,
}

pub fn current_pid() -> u32 {
    // SAFETY: 无参数 API
    unsafe { GetCurrentProcessId() }
}

/// 创建 inheritable 匿名管道（fork 元数据通道），返回 (写端, 读端)。
pub fn create_inherit_pipe() -> Result<(isize, isize), HostError> {
    let (r, w) = file_ops::pipe_handles()?;
    Ok((w, r))
}

/// 由原始句柄构造管道端（fork 元数据管道的 CLI 侧读写包装）。
pub fn pipe_from_raw_handle(h: isize, _is_read: bool) -> crate::PipeEnd {
    crate::PipeEnd(crate::PipeEndInner::Handle(h))
}

pub fn close_handle(h: isize) {
    if h != 0 {
        // SAFETY: h 来自 CreateProcess/CreateFileMapping/CreatePipe 的成功返回
        unsafe { CloseHandle2(h) };
    }
}

pub fn set_handle_inherit(h: isize) -> Result<(), HostError> {
    const HANDLE_FLAG_INHERIT: u32 = 0x1;
    // SAFETY: h 为调用方持有的有效句柄
    if unsafe { SetHandleInformation2(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    Ok(())
}

/// 创建命名无关的页文件 backed section（跨进程共享内存）。
/// 注意：flProtect 用 PAGE_EXECUTE_READWRITE——section 视图的保护由
/// section 对象决定，子进程需在恢复的代码页上执行（fork 快照场景）。
pub fn create_shared_section(size: u64) -> Result<isize, HostError> {
    // SAFETY: INVALID_HANDLE_VALUE + 空名字 = 页文件 backed；size > 0
    let h = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null_mut(), // 默认安全属性；继承靠 SetHandleInformation
            PAGE_EXECUTE_READWRITE,
            (size >> 32) as u32,
            size as u32,
            std::ptr::null(),
        )
    } as isize;
    if h == 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    Ok(h)
}

/// 任意基址映射（父进程拷贝快照用）。
pub fn map_section_anywhere(h: isize, _size: u64) -> Result<usize, HostError> {
    // SAFETY: h 为有效 section；offset 0/0 + bytes 0 = 全 section 映射
    let p = unsafe {
        MapViewOfFileEx(
            h as *mut c_void,
            0x6, // FILE_MAP_READ | FILE_MAP_WRITE
            0,
            0,
            0,
            std::ptr::null_mut(),
        )
    } as usize;
    if p == 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    Ok(p)
}

/// 固定基址映射（子进程把快照放回客户原地址——fork 语义的指针一致性前提）。
/// desiredAccess 含 FILE_MAP_EXECUTE（0x20）：view 保护由 desiredAccess 决定，
/// 恢复的代码页必须可执行（section 对象已为 RWX）。
pub fn map_section_at(h: isize, base: u64, _len: u64) -> Result<usize, HostError> {
    // SAFETY: base 在子进程为空闲地址（新进程首个映射）；对齐由父侧区间保证
    let p = unsafe {
        MapViewOfFileEx(
            h as *mut c_void,
            0x26, // FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE
            0,
            0,
            0,
            base as *mut c_void,
        )
    } as usize;
    if p == 0 || p != base as usize {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    Ok(p)
}

pub fn unmap_section_view(addr: usize) -> Result<(), HostError> {
    // SAFETY: addr 来自 MapViewOfFileEx 成功返回
    if unsafe { UnmapViewOfFile(addr as *mut c_void) } == 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    Ok(())
}

/// spawn vela 子进程（fork 协议）。句柄继承由调用方预先 SetHandleInformation。
pub fn create_child_process(cmdline: &str) -> Result<ChildProcess, HostError> {
    #[repr(C)]
    struct ProcessInformation {
        h_process: isize,
        h_thread: isize,
        pid: u32,
        tid: u32,
    }
    let mut cmd: Vec<u16> = cmdline.encode_utf16().collect();
    cmd.push(0);
    // STARTUPINFOW（x64 = 104 字节）全零 + cb = 104；其余字段不需要
    let mut si = [0u8; 104];
    si[0..4].copy_from_slice(&104u32.to_le_bytes());
    let mut pi = ProcessInformation {
        h_process: 0,
        h_thread: 0,
        pid: 0,
        tid: 0,
    };
    // SAFETY: cmd 以 NUL 结尾；si.cb 正确；pi 输出
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles = TRUE —— fork 协议前提
            0, // 无特殊标志：继承控制台（客户 stdout 直通）
            std::ptr::null(),
            std::ptr::null(),
            si.as_ptr() as *const c_void,
            &mut pi as *mut ProcessInformation as *mut c_void,
        )
    };
    if ok == 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    // 线程句柄用完即关；进程句柄归调用方（wait4/kill）
    unsafe { CloseHandle2(pi.h_thread) };
    Ok(ChildProcess {
        pid: pi.pid,
        handle: pi.h_process,
    })
}

/// 等待子进程。timeout_ms = INFINITE(0xFFFFFFFF) 阻塞 / 0 轮询。
/// Ok(None) = 超时；Ok(Some(code)) = 退出码。
pub fn wait_child(h: isize, timeout_ms: u32) -> Result<Option<u32>, HostError> {
    // SAFETY: h 为 CreateProcess 返回的进程句柄
    let w = unsafe { WaitForSingleObject(h as *mut c_void, timeout_ms) };
    if w == 0x0000_0080 {
        return Err(HostError::Invalid); // WAIT_ABANDONED：不应出现在进程句柄
    }
    if w == 0x0000_0102 {
        return Ok(None); // WAIT_TIMEOUT
    }
    if w != 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    let mut code: u32 = 0;
    // SAFETY: h 有效；code 输出指针
    if unsafe { GetExitCodeProcess(h as *mut c_void, &mut code) } == 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    Ok(Some(code))
}

/// 终止子进程（kill SIGKILL/SIGTERM 的诚实近似）。
pub fn terminate_child(h: isize, code: u32) -> Result<(), HostError> {
    // SAFETY: h 为有效进程句柄
    if unsafe { TerminateProcess(h as *mut c_void, code) } == 0 {
        return Err(HostError::Other(file_ops::os_to_errno(
            unsafe { GetLastError() } as i32,
        )));
    }
    Ok(())
}

/// 按 pid 打开进程（kill 的 pid 形态；不存在 → NotFound）。
pub fn open_process_handle(pid: u32) -> Result<isize, HostError> {
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    // SAFETY: pid 为客户传入的进程 id
    let h = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    } as isize;
    if h == 0 {
        let e = unsafe { GetLastError() };
        if e == 87 {
            return Err(HostError::Invalid);
        }
        return Err(HostError::NotFound);
    }
    Ok(h)
}

/// 元数据管道写入（isize 句柄；阻塞直到全部写入）。
pub fn pipe_write_all(h: isize, data: &[u8]) -> Result<(), HostError> {
    if let Some(raw) = file_ops::pipe_write_raw(h, data) {
        eprintln!("[vela] fork: meta pipe WriteFile raw error {raw}");
        return Err(HostError::Other(file_ops::os_to_errno(raw as i32)));
    }
    Ok(())
}

/// 元数据管道读取（精确 n 字节）。
pub fn pipe_read_exact(h: isize, buf: &mut [u8]) -> Result<(), HostError> {
    let mut off = 0;
    while off < buf.len() {
        let got = match file_ops::pipe_read_raw(h, &mut buf[off..]) {
            Ok(g) => g,
            Err(raw) => return Err(HostError::Other(file_ops::os_to_errno(raw as i32))),
        };
        if got == 0 {
            return Err(HostError::NotFound); // 父端意外关闭
        }
        off += got;
    }
    Ok(())
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateProcessW(
        app: *const u16,
        cmd: *mut u16,
        proc_attr: *const c_void,
        thread_attr: *const c_void,
        inherit_handles: i32,
        flags: u32,
        env: *const c_void,
        cwd: *const u16,
        si: *const c_void,
        pi: *mut c_void,
    ) -> i32;
    fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
    fn GetExitCodeProcess(h: *mut c_void, code: *mut u32) -> i32;
    fn TerminateProcess(h: *mut c_void, code: u32) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn GetCurrentProcessId() -> u32;
    #[link_name = "SetHandleInformation"]
    fn SetHandleInformation2(h: isize, mask: u32, flags: u32) -> i32;
    #[link_name = "CloseHandle"]
    fn CloseHandle2(h: isize) -> i32;
}

const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

#[cfg(test)]
mod soft_tls_tests {
    //! decode_fs_mov 覆盖 musl 实际发射的形态（T4.1）。
    use super::*;

    #[test]
    fn decodes_fs0_sib_absolute() {
        // mov rcx, fs:[0]（本次 hello-dyn 崩溃形态）
        let m = decode_fs_mov(&[0x64, 0x48, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert!(m.load);
        assert_eq!(m.reg, 1); // rcx
        assert!(!m.rip_rel);
        assert_eq!(m.base, 0);
        assert_eq!(m.disp, 0);
        assert_eq!(m.len, 9);
        // mov rax, fs:[0]
        let m = decode_fs_mov(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(m.reg, 0);
        assert_eq!(m.len, 9);
    }

    #[test]
    fn decodes_rip_relative_and_write() {
        // mov rax, fs:[rip+0x10]：64 48 8b 05 10 00 00 00
        let m = decode_fs_mov(&[0x64, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00]).unwrap();
        assert!(m.rip_rel);
        assert_eq!(m.reg, 0);
        assert_eq!(m.len, 8);
        // mov fs:[0], rax（写）：64 48 89 04 25 00 00 00 00
        let m = decode_fs_mov(&[0x64, 0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert!(!m.load);
        assert_eq!(m.reg, 0);
        // r8 目标（REX.R）：64 4c 8b 04 25 00 00 00 00 → reg=8
        let m = decode_fs_mov(&[0x64, 0x4c, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(m.reg, 8);
    }

    #[test]
    fn rejects_unsupported_forms() {
        // 非 fs 前缀
        assert!(decode_fs_mov(&[0x48, 0x8b, 0x0c, 0x25]).is_none());
        // fs 前缀但 32 位操作数（无 REX.W）
        assert!(decode_fs_mov(&[0x64, 0x8b, 0x0c, 0x25]).is_none());
        // fs 前缀但非 mov（lea 8d）
        assert!(decode_fs_mov(&[0x64, 0x48, 0x8d, 0x05, 0, 0, 0, 0]).is_none());
        // 寄存器对寄存器（mod=3）
        assert!(decode_fs_mov(&[0x64, 0x48, 0x8b, 0xc8]).is_none());
        // 截断
        assert!(decode_fs_mov(&[0x64, 0x48, 0x8b]).is_none());
    }
}

#[cfg(test)]
mod soft_tls_table_tests {
    //! T5.1（PLAN-0.0.5）：decode_fs_mov 形态回归资产——表驱动，
    //! 覆盖 musl 发射的全部解码维度（REX/ModRM/SIB/disp/读写）。

    use super::*;

    /// (字节, 期望 len, 期望 reg, 期望 rip_rel, 期望 disp)
    const LOAD_CASES: &[(&[u8], usize, usize, bool, i64)] = &[
        // musl 真实形态：mov rcx, fs:0（SIB 绝对）
        (
            &[0x64, 0x48, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x00, 0x00],
            9,
            1,
            false,
            0,
        ),
        // mov rax, fs:0
        (
            &[0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00],
            9,
            0,
            false,
            0,
        ),
        // mov r8, fs:0（REX.R 扩展）
        (
            &[0x64, 0x4c, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00],
            9,
            8,
            false,
            0,
        ),
        // mov r15, fs:0（REX.R+B）
        (
            &[0x64, 0x4f, 0x8b, 0x3c, 0x25, 0x00, 0x00, 0x00, 0x00],
            9,
            15,
            false,
            0,
        ),
        // mov rax, fs:[rip+0x10]
        (
            &[0x64, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00],
            8,
            0,
            true,
            0x10,
        ),
        // mov rax, fs:[rip-4]
        (
            &[0x64, 0x48, 0x8b, 0x05, 0xfc, 0xff, 0xff, 0xff],
            8,
            0,
            true,
            -4,
        ),
        // mov rax, fs:[rbx+8]（mod=01，基址 rbx）
        (&[0x64, 0x48, 0x8b, 0x43, 0x08], 5, 0, false, 8),
        // mov rax, fs:[rbx+0x1234]（mod=02 disp32）
        (
            &[0x64, 0x48, 0x8b, 0x83, 0x34, 0x12, 0x00, 0x00],
            8,
            0,
            false,
            0x1234,
        ),
        // mov rax, fs:[rsp+8]（mod=01 SIB，基址 rsp）
        (&[0x64, 0x48, 0x8b, 0x44, 0x24, 0x08], 6, 0, false, 8),
        // mov rax, fs:[r12*4+0x40]（mod=01 SIB 变址 r12、无基址 → disp8+idx）
        (&[0x64, 0x48, 0x8b, 0x44, 0xa5, 0x40], 6, 0, false, 0x40),
        // 冗余 66 前缀填充 + fs（file-io 实测 getcwd 路径）
        (
            &[
                0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
            ],
            12,
            0,
            false,
            0,
        ),
    ];

    /// 写形态：mov fs:[mem], reg
    const STORE_CASES: &[(&[u8], usize)] = &[
        // mov fs:[0], rax
        (&[0x64, 0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00], 9),
        // mov fs:[rbx], rdi
        (&[0x64, 0x48, 0x89, 0x3b], 4),
    ];

    #[test]
    fn table_load_forms_decode() {
        for (bytes, len, reg, rip_rel, disp) in LOAD_CASES {
            let m = decode_fs_mov(bytes).unwrap_or_else(|| panic!("decode fail {bytes:?}"));
            assert!(m.load, "{bytes:?}");
            assert_eq!(m.len, *len, "{bytes:?}");
            assert_eq!(m.reg, *reg, "{bytes:?}");
            assert_eq!(m.rip_rel, *rip_rel, "{bytes:?}");
            if !*rip_rel {
                assert_eq!(m.disp, *disp, "{bytes:?}");
            }
        }
    }

    #[test]
    fn table_store_forms_decode() {
        for (bytes, len) in STORE_CASES {
            let m = decode_fs_mov(bytes).unwrap_or_else(|| panic!("decode fail {bytes:?}"));
            assert!(!m.load, "{bytes:?}");
            assert_eq!(m.len, *len, "{bytes:?}");
        }
    }
}

#[cfg(test)]
mod file_map_tests {
    //! 文件映射（PLAN-0.0.4 T1.1）：读一致、COW 不回写、对齐校验。
    use super::*;
    use crate::{HostOpen, HostPath};

    fn temp_payload(
        len: usize,
        name: &str,
    ) -> (WindowsHost, HostFile, std::path::PathBuf, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!("vela_mapfile_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        std::fs::write(&p, &payload).unwrap();
        let host = WindowsHost::new();
        let f = host
            .open(
                &HostPath(p.clone()),
                HostOpen {
                    read: true,
                    ..Default::default()
                },
            )
            .unwrap();
        (host, f, p, payload)
    }

    #[test]
    fn read_view_matches_file_content() {
        let (host, f, _p, payload) = temp_payload(0x3_0000, "read.bin"); // 192K，含跨 64K 偏移
                                                                         // offset 0 系统自选基址
        let base = unsafe { host.map_file(&f, 0, 0x2000, 0, HostProt::READ) }.unwrap();
        assert_eq!(base % ALLOC_GRANULARITY, 0);
        // SAFETY: base 为 map_file 返回的有效视图
        let s = unsafe { std::slice::from_raw_parts(base as *const u8, 0x2000) };
        assert_eq!(s, &payload[..0x2000]);
        unsafe { host.unmap_view(base) }.unwrap();
        // offset 64K 对齐 + 固定 hint
        let base2 =
            unsafe { host.map_file(&f, 0x1_0000, 0x1000, 0x2_0000, HostProt::READ) }.unwrap();
        assert_eq!(base2, 0x2_0000);
        // SAFETY: 同上
        let s2 = unsafe { std::slice::from_raw_parts(base2 as *const u8, 0x1000) };
        assert_eq!(s2, &payload[0x1_0000..0x1_1000]);
        unsafe { host.unmap_view(base2) }.unwrap();
    }

    #[test]
    fn cow_write_is_private_and_never_touches_file() {
        let (host, f, p, payload) = temp_payload(0x1_0000, "cow.bin");
        // PROT_READ|PROT_WRITE → PAGE_WRITECOPY COW 视图
        let base =
            unsafe { host.map_file(&f, 0, 0x1_0000, 0, HostProt::READ | HostProt::WRITE) }.unwrap();
        // SAFETY: base 为本测试独占的 COW 视图
        let s = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, 0x1_0000) };
        assert_eq!(&s[..16], &payload[..16]);
        s[..16].copy_from_slice(&[0xAB; 16]);
        // 读回一致（COW 私有页生效）
        assert_eq!(&s[..16], &[0xAB; 16]);
        assert_eq!(&s[16..32], &payload[16..32]);
        // 释放视图后宿主文件必须原样
        unsafe { host.unmap_view(base) }.unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), payload);
    }

    #[test]
    fn rejects_misaligned_offset_and_hint() {
        let (host, f, _p, _payload) = temp_payload(0x2_0000, "align.bin");
        assert_eq!(
            unsafe { host.map_file(&f, 0x1000, 0x1000, 0, HostProt::READ) },
            Err(HostError::Invalid)
        );
        assert_eq!(
            unsafe { host.map_file(&f, 0, 0x1000, 0x1004, HostProt::READ) },
            Err(HostError::Invalid)
        );
    }
}
