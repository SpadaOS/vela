//! Windows 宿主实现：VirtualAlloc/VirtualProtect/VirtualFree、std 文件与控制台、
//! VEH（UD2 → dispatch）syscall 陷阱。所有 Win32 FFI 集中在本模块（规格 2.4）。

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use crate::file_ops;
use crate::{Host, HostError, HostFile, HostOpen, HostPath, HostProt, HostStat, StdioHandles};

// ---------------------------------------------------------------- Win32 FFI

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAlloc(lpAddress: *mut c_void, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut c_void;
    fn VirtualProtect(lpAddress: *mut c_void, dwSize: usize, flNewProtect: u32, lpflOldProtect: *mut u32) -> i32;
    fn VirtualFree(lpAddress: *mut c_void, dwSize: usize, dwFreeType: u32) -> i32;
    fn SetConsoleOutputCP(wCodePageID: u32) -> i32;
    fn AddVectoredExceptionHandler(
        First: u32,
        Handler: Option<unsafe extern "system" fn(*mut ExceptionPointers) -> i32>,
    ) -> *mut c_void;
    fn RemoveVectoredExceptionHandler(Handler: *mut c_void) -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    /// RtlGenRandom 的旧导出名；返回 0 表示失败。
    fn SystemFunction036(RandomBuffer: *mut c_void, RandomBufferLength: u32) -> u8;
}

/// x64 CONTEXT 覆盖视图：只声明我们关心的字段 + 尾部不透明区。
/// 字段偏移与 Win32 CONTEXT 一致（rax=0x78 … rip=0xF8），总大小 0x4D0。
#[repr(C)]
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

/// VEH 回调注入的业务函数：nr、args、rip、可变 CONTEXT → syscall 返回值。
/// 回调负责写回 Rax、模拟 syscall 副作用（Rip+=2、Rcx、R11），
/// 需要改变控制流（如 FS trampoline）时可直接改写 ctx.rip。
pub type TrapFn = unsafe extern "system" fn(nr: u64, args: &[u64; 6], rip: u64, ctx: &mut Context) -> i64;

const MAX_GUEST_RANGES: usize = 32;
/// start==0 视为空槽（客户基址来自 VirtualAlloc，永远非 0）。
static RANGE_START: [AtomicU64; MAX_GUEST_RANGES] = [const { AtomicU64::new(0) }; MAX_GUEST_RANGES];
static RANGE_END: [AtomicU64; MAX_GUEST_RANGES] = [const { AtomicU64::new(0) }; MAX_GUEST_RANGES];
static TRAP_FN: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicU32 = AtomicU32::new(0);

/// 登记 VEH 需要识别的客户可执行地址范围（Rip 过滤用）。
pub fn add_guest_exec_range(start: u64, end: u64) {
    for (s, e) in RANGE_START.iter().zip(RANGE_END.iter()) {
        if s.load(Ordering::Relaxed) == 0 {
            s.store(start, Ordering::Relaxed);
            e.store(end, Ordering::Relaxed);
            return;
        }
    }
}

/// 注册 syscall dispatch 回调。
pub fn set_trap_fn(f: TrapFn) {
    TRAP_FN.store(f as usize, Ordering::Relaxed);
}

/// 安装 VEH。重复调用幂等。
pub fn install_syscall_trap() -> Result<(), HostError> {
    if INSTALLED.swap(1, Ordering::SeqCst) == 1 {
        return Ok(());
    }
    // SAFETY: veh_handler 是有效的 extern "system" 回调
    let h = unsafe { AddVectoredExceptionHandler(1, Some(veh_handler)) };
    if h.is_null() {
        Err(HostError::Other(0))
    } else {
        Ok(())
    }
}

fn guest_range_containing(rip: usize) -> Option<(usize, usize)> {
    for (s, e) in RANGE_START.iter().zip(RANGE_END.iter()) {
        let s = s.load(Ordering::Relaxed) as usize;
        let e = e.load(Ordering::Relaxed) as usize;
        if s != 0 && rip >= s && rip + 2 <= e {
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
            // SAFETY: rip 在客户映射内（已确认），读 16 字节仅用于诊断
            let bytes = unsafe { std::slice::from_raw_parts(ctx.rip as *const u8, 16) };
            let hb: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
            // fs 段前缀（0x64）开头的 AV，且本机不支持 FSGSBASE：几乎必然是
            // 客户 TLS 访问（fs 基址未能切换），给出明确原因而不是裸崩溃
            let fs_hint = if !fs_base_supported() && bytes.first() == Some(&0x64) {
                " [hint: FSGSBASE unavailable - guest TLS (fs) cannot be switched; TLS-dependent programs cannot run here]"
            } else {
                ""
            };
            eprintln!(
                "[vela] AV in guest rip={:#x} addr={:#x} op={} rax={:#x} rcx={:#x} rdx={:#x} bytes={}{}",
                ctx.rip,
                rec.info[1] as usize,
                rec.info[0],
                ctx.rax,
                ctx.rcx,
                ctx.rdx,
                hb.join(" "),
                fs_hint
            );
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if rec.exception_code != STATUS_ILLEGAL_INSTRUCTION {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // SAFETY: 同上
    let ctx = unsafe { &mut *ep.context_record };
    let rip = ctx.rip as usize;
    // FS commit stub：预切后的 ud2+ret，直接跳过 ud2 让 ret 返回调用者。
    // 必须在 guest range 过滤之前判断（stub 位于 vela.exe 自身代码段）。
    let commit_stub = vela_fs_commit_stub as usize;
    if rip >= commit_stub && rip < commit_stub + 4 {
        ctx.rip = rip as u64 + 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    let Some(_range) = guest_range_containing(rip) else {
        return EXCEPTION_CONTINUE_SEARCH;
    };
    // 确认该位置确为 patch 点（UD2），避免吞掉客户真实的非法指令
    // SAFETY: rip..rip+2 已确认位于客户可执行映射内
    let code = unsafe { std::slice::from_raw_parts(rip as *const u8, 2) };
    if code != [0x0F, 0x0B] {
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
    // SAFETY: 回调由 CLI 注册，内部仅操作客户进程状态与异常上下文
    let _ret = unsafe { tf(nr, &args, rip as u64, ctx) };
    // syscall 模拟（rax/rcx/r11/rip 推进）与控制流改写均由回调完成
    EXCEPTION_CONTINUE_EXECUTION
}

/// 控制台输出切 UTF-8（规格 7.2）。
pub fn set_console_utf8() {
    // SAFETY: 无参数约束
    unsafe { SetConsoleOutputCP(65001) };
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
    unsafe { core::arch::asm!("wrfsbase {0}", in(reg) v) };
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
    unsafe { vela_fs_commit_stub() };
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
        WindowsHost { start: Instant::now() }
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

impl Host for WindowsHost {
    unsafe fn map(&self, hint: usize, len: usize, _prot: HostProt, anon: bool) -> Result<usize, HostError> {
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

    fn open(&self, path: &HostPath, opt: HostOpen) -> Result<HostFile, HostError> {
        file_ops::open(path, opt)
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
    fn close(&self, f: HostFile) -> Result<(), HostError> {
        file_ops::close(f)
    }
    fn stdio(&self) -> StdioHandles {
        file_ops::stdio()
    }
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
            Err(HostError::Other(0))
        } else {
            Ok(())
        }
    }
    fn set_fs_base(&self, _v: u64) -> Result<(), HostError> {
        // 仅报告能力；真正的 FS 切换由 CLI 的 trampoline 在异常返回后完成
        // （处理器内 wrfsbase 会被 NtContinue 还原，见本模块 FS 注释）。
        if fs_base_supported() {
            Ok(())
        } else {
            Err(HostError::Unimplemented)
        }
    }
    fn thread_exit(&self, code: i32) -> ! {
        // v0 单线程模型：线程退出即进程退出（规格 2.1）
        std::process::exit(code)
    }
    fn process_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
}
