//! vela-runtime：维护 GuestProcess 并实现 Linux syscall 语义翻译（规格 5.4）。
//! 本 crate 禁止 `cfg(target_os)` 与任何 Windows/SpadaOS 类型——宿主差异全部走 `vela_sys::Host`。

pub mod mem;
pub mod syscalls;

pub use mem::{InterpImage, LoadedImage, MemRange, Segment};
pub use syscalls::dispatch;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use vela_abi as abi;
use vela_sys::{GuestRegs, Host, HostDir, HostError, HostFile, HostProt};

use crate::mem::MemRegistry;

// ---------------------------------------------------------------- fd 表

/// 管道端 fd（0.0.6 M1 T1.1：pipe2 下沉为宿主管道）。
/// IO/close 全部经 HostFileOps（Windows = 真实阻塞管道 + 可继承句柄，
/// 跨 fork 传递；测试宿主 = 内存管道）。端别仅在错误语义上区分：
/// 读端不可写（EBADF）、写端不可读（EBADF）。
#[derive(Debug)]
pub enum GuestFd {
    Host(HostFile),
    /// 目录快照句柄（O_DIRECTORY 打开；getdents64 消费）。
    HostDir(HostDir),
    /// 管道读端。
    PipeRead(HostFile),
    /// 管道写端。
    PipeWrite(HostFile),
    Null,
    Zero,
    Epoll(std::sync::Arc<std::sync::Mutex<EpollState>>),
    Reserved,
}

impl GuestFd {
    /// 是否持有宿主资源（close 时需要动作）。
    pub fn is_pipe(&self) -> bool {
        matches!(self, GuestFd::PipeRead(_) | GuestFd::PipeWrite(_))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EpollWatch {
    pub events: u32,
    pub data: u64,
}

#[derive(Debug, Default)]
pub struct EpollState {
    pub watches: BTreeMap<(i32, u64), EpollWatch>,
    pub cursor: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SignalDisposition {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

#[derive(Debug)]
pub struct SignalState {
    pub dispositions: [SignalDisposition; 64],
    pub blocked: u64,
    pub pending: u64,
}

/// A software signal frame saved at a trap safe point.  The host trap layer
/// owns the live register reference; the runtime keeps the previous snapshot
/// so `rt_sigreturn` can hand it back without depending on a Windows CONTEXT.
#[derive(Clone, Debug)]
pub struct SignalFrame {
    pub regs: GuestRegs,
    pub e_flags: u64,
    pub blocked: u64,
    pub rsp: u64,
    pub fp_state: Vec<u8>,
    pub alt_stack: Option<(u64, u64, i32)>,
}

impl Default for SignalState {
    fn default() -> Self {
        Self {
            dispositions: [SignalDisposition::default(); 64],
            blocked: 0,
            pending: 0,
        }
    }
}

impl SignalState {
    pub fn ignored(&self, sig: usize) -> bool {
        let handler = self.dispositions[sig - 1].handler;
        handler == abi::SIG_IGN || handler == abi::SIG_DFL && matches!(sig, 17 | 18 | 23 | 28)
    }

    pub fn reset_for_exec(&mut self) {
        for disposition in &mut self.dispositions {
            if disposition.handler != abi::SIG_IGN {
                *disposition = SignalDisposition::default();
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct FdTable {
    table: BTreeMap<i32, GuestFd>,
    /// 每 fd 的标志记账（fcntl）：bit0 = FD_CLOEXEC，bits 8..24 = status flags
    /// （O_APPEND/O_NONBLOCK/O_ACCMODE），其余保留。
    flags: BTreeMap<i32, u32>,
    identities: BTreeMap<i32, u64>,
    next_identity: u64,
}

impl FdTable {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_stdio(host: &dyn Host) -> Self {
        let s = host.stdio();
        let mut t = BTreeMap::new();
        t.insert(0, GuestFd::Host(s.stdin));
        t.insert(1, GuestFd::Host(s.stdout));
        t.insert(2, GuestFd::Host(s.stderr));
        // Linux stdio 以 O_RDWR 打开字符设备
        let mut f = FdTable {
            table: t,
            flags: BTreeMap::new(),
            ..FdTable::default()
        };
        for fd in 0..3 {
            f.flags.insert(fd, (abi::O_RDWR as u32) << 8);
            f.next_identity += 1;
            f.identities.insert(fd, f.next_identity);
        }
        f
    }

    pub fn get(&self, fd: i32) -> Option<&GuestFd> {
        self.table.get(&fd)
    }

    /// 全表遍历（fork 快照序列化用）。
    pub fn iter(&self) -> impl Iterator<Item = (i32, &GuestFd)> {
        self.table.iter().map(|(k, v)| (*k, v))
    }

    pub fn remove(&mut self, fd: i32) -> Option<GuestFd> {
        self.flags.remove(&fd);
        self.identities.remove(&fd);
        self.table.remove(&fd)
    }

    /// 分配最小可用 fd。
    pub fn alloc_fd(&mut self, entry: GuestFd) -> i32 {
        let mut fd = 0;
        while self.table.contains_key(&fd) {
            fd += 1;
        }
        self.table.insert(fd, entry);
        self.next_identity += 1;
        self.identities.insert(fd, self.next_identity);
        fd
    }

    /// 强制占用指定 fd（dup2 语义）；已存在条目由调用方先 remove。
    pub fn insert_at(&mut self, fd: i32, entry: GuestFd) {
        self.flags.remove(&fd);
        self.table.insert(fd, entry);
        self.next_identity += 1;
        self.identities.insert(fd, self.next_identity);
    }

    pub fn identity(&self, fd: i32) -> Option<u64> {
        self.identities.get(&fd).copied()
    }
    pub fn source_for_identity(&self, identity: u64) -> Option<&GuestFd> {
        self.identities
            .iter()
            .find(|(_, value)| **value == identity)
            .and_then(|(fd, _)| self.get(*fd))
    }
    pub fn link_dup(&mut self, source: i32, target: i32) {
        if let Some(identity) = self.identity(source) {
            self.identities.insert(target, identity);
        }
    }

    /// Close an fd and invalidate epoll watches that refer to its number.
    pub fn remove_with_watch_cleanup(&mut self, fd: i32) -> Option<GuestFd> {
        let identity = self.identity(fd);
        let removed = self.remove(fd);
        if identity.is_some_and(|id| self.identities.values().any(|value| *value == id)) {
            return removed;
        }
        for entry in self.table.values() {
            if let GuestFd::Epoll(state) = entry {
                if let Ok(mut state) = state.lock() {
                    state.watches.retain(|(_, id), _| Some(*id) != identity);
                }
            }
        }
        removed
    }

    /// 记账 fd 标志（open 时记录客户传入 flags 的编码）。
    pub fn set_flags(&mut self, fd: i32, v: u32) {
        self.flags.insert(fd, v);
    }

    pub fn get_flags(&self, fd: i32) -> Option<u32> {
        self.flags.get(&fd).copied()
    }

    pub fn clone_flags_for_dup(&self, oldfd: i32) -> u32 {
        self.flags.get(&oldfd).copied().unwrap_or(0) & !1
    }

    /// 更新 flags（F_SETFL/F_SETFD）；未记账的 fd 以 0 起始。
    pub fn update_flags(&mut self, fd: i32, f: impl FnOnce(u32) -> u32) {
        let old = self.flags.get(&fd).copied().unwrap_or(0);
        let value = f(old);
        self.flags.insert(fd, value);
        if old >> 8 != value >> 8 {
            if let Some(identity) = self.identity(fd) {
                let aliases = self
                    .identities
                    .iter()
                    .filter(|(_, id)| **id == identity)
                    .map(|(fd, _)| *fd)
                    .collect::<Vec<_>>();
                for alias in aliases {
                    let flags = self.flags.entry(alias).or_default();
                    *flags = (*flags & 0xff) | (value & !0xff);
                }
            }
        }
    }

    /// execve（PLAN-0.0.4 T3.1/T3.2）：关闭所有带 FD_CLOEXEC 的 fd，
    /// 其余（管道等）跨重载保留。Host fd（含管道端）调 host.close——
    /// 管道对象在全部端句柄关闭后由 OS 回收，EOF/EPIPE 语义由 OS 维持。
    /// 返回关闭数量。
    pub fn close_cloexec(&mut self, host: &dyn Host) -> usize {
        let clo: Vec<i32> = self
            .flags
            .iter()
            .filter(|(_, f)| *f & 1 != 0)
            .map(|(fd, _)| *fd)
            .collect();
        let mut n = 0;
        for fd in clo {
            if let Some(gf) = self.remove_with_watch_cleanup(fd) {
                n += 1;
                match gf {
                    GuestFd::Host(h) | GuestFd::PipeRead(h) | GuestFd::PipeWrite(h) => {
                        let _ = host.close(h);
                    }
                    _ => {}
                }
            }
        }
        n
    }
}

/// Shared trap state, including the host adapter supplied by the embedding
/// CLI. One guard owns address-space, descriptor and child-table mutations.
/// Dispatch may only make bounded attempts while this guard is held.
pub struct ProcessShared<S>(Mutex<S>);

impl<S> ProcessShared<S> {
    pub fn new(state: S) -> Self {
        Self(Mutex::new(state))
    }
    pub fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, S>> {
        self.0.lock()
    }
}

/// Per-thread state that is intentionally independent from `ProcessShared`.
pub struct GuestThread {
    pub tid: u32,
    pub fs_base: AtomicU64,
    pub gs_base: AtomicU64,
    pub soft_tls_base: AtomicU64,
    pub clear_tid: AtomicU64,
    pub robust_list: AtomicU64,
    pub stack: Option<MemRange>,
    pub exited: AtomicBool,
    pub exit_code: Mutex<Option<i32>>,
    pub signals: Mutex<ThreadSignalState>,
}

impl GuestThread {
    pub fn new(tid: u32, stack: Option<MemRange>, tls: u64) -> Arc<Self> {
        Arc::new(Self {
            tid,
            fs_base: AtomicU64::new(tls),
            gs_base: AtomicU64::new(0),
            soft_tls_base: AtomicU64::new(tls),
            clear_tid: AtomicU64::new(0),
            robust_list: AtomicU64::new(0),
            stack,
            exited: AtomicBool::new(false),
            exit_code: Mutex::new(None),
            signals: Mutex::new(ThreadSignalState::default()),
        })
    }

    pub fn mark_exit(&self, code: i32) {
        if let Ok(mut slot) = self.exit_code.lock() {
            *slot = Some(code);
        }
        self.exited.store(true, Ordering::Release);
    }
}

#[derive(Default)]
pub struct ThreadSignalState {
    pub blocked: u64,
    pub frames: Vec<SignalFrame>,
    pub restore: Option<SignalFrame>,
    pub alt_stack: Option<(u64, u64, i32)>,
}

/// Current thread binding for a bounded dispatch under ProcessShared's guard.
/// The legacy syscall adapter is hydrated from the registered GuestThread;
/// no thread-private signal or TLS state is shared across guard handoffs.
pub struct GuestContext;
impl GuestContext {
    pub fn enter(proc: &mut GuestProcess, tid: u32) {
        if proc.tid == tid && proc.threads.contains_key(&tid) {
            return;
        }
        if let Some(old) = proc.threads.get(&proc.tid) {
            old.fs_base.store(proc.fs_base, Ordering::Release);
            old.gs_base.store(proc.gs_base, Ordering::Release);
            old.clear_tid
                .store(proc.clear_tid.unwrap_or(0), Ordering::Release);
            let mut state = old.signals.lock().unwrap_or_else(|p| p.into_inner());
            state.blocked = proc.signals.blocked;
            state.frames = std::mem::take(&mut proc.signal_frames);
            state.restore = proc.signal_restore.take();
            state.alt_stack = proc.alt_stack.take();
        }
        let current = proc
            .threads
            .entry(tid)
            .or_insert_with(|| GuestThread::new(tid, None, 0))
            .clone();
        proc.tid = tid;
        proc.fs_base = current.fs_base.load(Ordering::Acquire);
        proc.gs_base = current.gs_base.load(Ordering::Acquire);
        proc.clear_tid = match current.clear_tid.load(Ordering::Acquire) {
            0 => None,
            addr => Some(addr),
        };
        proc.fs_apply_pending = None;
        let mut state = current.signals.lock().unwrap_or_else(|p| p.into_inner());
        proc.signals.blocked = state.blocked;
        proc.signal_frames = std::mem::take(&mut state.frames);
        proc.signal_restore = state.restore.take();
        proc.alt_stack = state.alt_stack.take();
    }
}

// ---------------------------------------------------------------- 进程

/// mprotect 运行时账本条目（PLAN-0.1.0 T3.2）：成功应用的保护变更，
/// fork 恢复时按「映像段 + 账本」收敛（0.0.6 只按映像段的诚实近似补全）。
#[derive(Clone, Copy, Debug)]
pub struct ProtOverride {
    pub start: u64,
    pub len: u64,
    /// Linux PROT_* 位（bit0=R bit1=W bit2=X）。
    pub prot: u8,
}

pub struct GuestProcess {
    pub pid: u32,
    /// Linux thread id. The initial thread uses the process id.
    pub tid: u32,
    /// Address supplied by `set_tid_address`; a terminating thread stores 0
    /// here and wakes waiters through the futex backend.
    pub clear_tid: Option<u64>,
    /// 父进程 pid（0.0.6 M1：fork 时由元数据传递；普通启动 = 宿主派生值）。
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub fs_base: u64,
    pub gs_base: u64,
    /// 待应用的 FS 基址：宿主支持时由 SET_FS 记录，CLI 在异常返回后
    /// 通过 trampoline 实际切换（wrfsbase 在异常处理器内会被内核还原）。
    pub fs_apply_pending: Option<u64>,
    pub brk_start: u64,
    pub brk: u64,
    /// 堆预留（连续匿名块），None 表示未初始化。
    pub heap: Option<MemRange>,
    pub fds: FdTable,
    pub load: LoadedImage,
    pub mem: MemRegistry,
    /// Linux 风格路径（规格 5.4）。
    pub cwd: String,
    /// 客户→宿主路径映射表（vela-fs）。默认 legacy：`/mnt/c → C:\`。
    pub fs: vela_fs::FsMap,
    /// mprotect 运行时账本（T3.2；按应用顺序追加，fork 元数据传递）。
    pub prot_ledger: Vec<ProtOverride>,
    pub signals: SignalState,
    pub signal_frames: Vec<SignalFrame>,
    pub signal_restore: Option<SignalFrame>,
    pub alt_stack: Option<(u64, u64, i32)>,
    pub threads: BTreeMap<u32, Arc<GuestThread>>,
    pub thread_pending: BTreeMap<u32, u64>,
    pub notified_children: std::collections::BTreeSet<u32>,
    /// Dispatch performs a bounded attempt; the CLI releases its state guard
    /// before retrying a would-block result.
    pub nonblocking_step: bool,
}

impl GuestProcess {
    /// Check the effective permission at every page, including the latest
    /// mmap/mprotect override. Called only while the process guard is held.
    pub fn can_access(&self, addr: u64, len: usize, required: u8) -> bool {
        if len == 0 {
            return true;
        }
        if len > isize::MAX as usize || !self.mem.contains(addr, len as u64) {
            return false;
        }
        let end = addr + len as u64;
        let mut page = addr;
        while page < end {
            let mut prot = if self.load.interp.as_ref().is_some_and(|i| {
                i.exec_ranges
                    .iter()
                    .any(|(start, stop)| page >= *start && page < *stop)
            }) {
                5
            } else {
                3
            };
            if !self.load.segments.is_empty()
                && page >= self.load.span.start
                && page < self.load.span.start + self.load.span.len
            {
                prot = 0;
            }
            if self.load.interp.as_ref().is_some_and(|image| {
                page >= image.span.start && page < image.span.start + image.span.len
            }) {
                prot = 0;
            }
            if let Some(segment) = self
                .load
                .segments
                .iter()
                .chain(self.load.interp.iter().flat_map(|i| i.segments.iter()))
                .find(|s| {
                    page >= (s.vaddr & !4095) && page < (s.vaddr + s.mem_size).div_ceil(4096) * 4096
                })
            {
                prot = segment.prot;
            }
            if let Some(override_) = self
                .prot_ledger
                .iter()
                .rev()
                .find(|p| page >= p.start && page < p.start.saturating_add(p.len))
            {
                prot = override_.prot;
            }
            if prot & required != required {
                return false;
            }
            page = ((page & !4095) + 4096).min(end);
        }
        true
    }

    pub fn new(pid: u32, load: LoadedImage) -> Self {
        let mut memreg = MemRegistry::default();
        memreg.add(load.span);
        if let Some(i) = &load.interp {
            // 解释器映像同样纳入 EFAULT 检查与 munmap 记账（PLAN-0.0.4 T2.2）
            memreg.add(i.span);
        }
        GuestProcess {
            pid,
            tid: pid,
            clear_tid: None,
            ppid: 0,
            uid: 1000,
            gid: 1000,
            fs_base: 0,
            gs_base: 0,
            fs_apply_pending: None,
            brk_start: 0,
            brk: 0,
            heap: None,
            fds: FdTable::empty(),
            load,
            mem: memreg,
            cwd: "/mnt/c".to_string(),
            fs: vela_fs::FsMap::legacy(),
            prot_ledger: Vec::new(),
            signals: SignalState::default(),
            signal_frames: Vec::new(),
            signal_restore: None,
            alt_stack: None,
            threads: BTreeMap::new(),
            thread_pending: BTreeMap::new(),
            notified_children: Default::default(),
            nonblocking_step: false,
        }
    }

    pub fn discard_ignored_signals(&mut self) {
        let ignored = (1..=64)
            .filter(|sig| self.signals.ignored(*sig))
            .fold(0u64, |bits, sig| bits | (1 << (sig - 1)));
        self.signals.pending &= !ignored;
        for bits in self.thread_pending.values_mut() {
            *bits &= !ignored;
        }
    }

    pub fn attach_stdio(&mut self, host: &dyn Host) {
        self.fds = FdTable::with_stdio(host);
    }

    /// 预留连续堆区域并把断点置于区域起点（规格 5.4 brk 说明）。
    pub fn init_heap(&mut self, host: &dyn Host, hint: u64, size: u64) -> Result<u64, HostError> {
        let size_usize = usize::try_from(size).map_err(|_| HostError::NoMemory)?;
        if size == 0 {
            return Err(HostError::Invalid);
        }
        // SAFETY: host.map 契约保证返回零填充可写内存
        let addr = unsafe {
            host.map(
                hint as usize,
                size_usize,
                HostProt::READ | HostProt::WRITE,
                true,
            )
        }? as u64;
        let r = MemRange::reserve(addr, size);
        self.heap = Some(r);
        self.mem.add(r);
        self.brk_start = addr;
        self.brk = addr;
        Ok(addr)
    }
}

// ---------------------------------------------------------------- 客户内存访问

/// 读客户内存：同进程实现 + 映射登记校验（规格 5.4）。
pub fn read_guest(proc: &GuestProcess, addr: u64, len: usize) -> Result<Vec<u8>, i32> {
    if len > 16 * 1024 * 1024 {
        return Err(abi::EINVAL);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    if !proc.can_access(addr, len, 1) {
        return Err(abi::EFAULT);
    }
    // SAFETY: 同进程地址空间；区间已确认登记在客户映射内
    let mut bytes = vec![0; len];
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, bytes.as_mut_ptr(), len);
    }
    Ok(bytes)
}

/// Validate an output range without borrowing guest memory.
pub fn validate_guest_write(proc: &GuestProcess, addr: u64, len: usize) -> Result<(), i32> {
    if proc.can_access(addr, len, 2) {
        Ok(())
    } else {
        Err(abi::EFAULT)
    }
}

pub fn write_guest(proc: &GuestProcess, addr: u64, data: &[u8]) -> Result<(), i32> {
    if data.is_empty() {
        return Ok(());
    }
    if !proc.can_access(addr, data.len(), 2) {
        return Err(abi::EFAULT);
    }
    // SAFETY: 同上
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    Ok(())
}

/// 读取 NUL 结尾字符串（上限 4096 字节）。
/// 按页边界分块读取（T3.7）：每块先经 mem.contains 校验整块合法，再零拷贝
/// 扫描找 NUL——避免逐字节 trap 检查的开销；跨登记边界自动截短到合法长度。
pub fn read_cstr(proc: &GuestProcess, addr: u64) -> Result<String, i32> {
    let mut out: Vec<u8> = Vec::new();
    let mut cur = addr;
    loop {
        if out.len() >= 4096 {
            return Err(abi::ENAMETOOLONG);
        }
        let page_end = (cur | 0xFFF).checked_add(1).ok_or(abi::EFAULT)?; // 本页尾（含）
        let want = (page_end - cur).min((4096 - out.len()) as u64);
        // 在请求长度内找最大合法前缀（正常情况 want 即合法；跨界时退化）
        let mut n = want;
        while n > 0 && !proc.can_access(cur, n as usize, 1) {
            n -= 1;
        }
        if n == 0 {
            return Err(abi::EFAULT);
        }
        // SAFETY: [cur, cur+n) 已确认登记在客户映射内
        let slice = unsafe { std::slice::from_raw_parts(cur as *const u8, n as usize) };
        match slice.iter().position(|&b| b == 0) {
            Some(i) => {
                out.extend_from_slice(&slice[..i]);
                return String::from_utf8(out).map_err(|_| abi::EINVAL);
            }
            None => {
                out.extend_from_slice(slice);
                cur = cur.checked_add(n).ok_or(abi::EFAULT)?;
            }
        }
    }
}

/// HostError → Linux errno（取负由调用方处理）。
pub fn host_err_to_errno(e: &HostError) -> i32 {
    match e {
        HostError::NotFound => abi::ENOENT,
        HostError::Access => abi::EACCES,
        HostError::Invalid => abi::EINVAL,
        HostError::NoMemory => abi::ENOMEM,
        HostError::Exist => abi::EEXIST,
        HostError::TimedOut => abi::ETIMEDOUT,
        HostError::Unimplemented => abi::ENOSYS,
        HostError::Other(c) => *c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_dup_flags_drop_cloexec_but_keep_status_flags() {
        let mut fds = FdTable::empty();
        let fd = fds.alloc_fd(GuestFd::Null);
        fds.set_flags(fd, 1 | ((abi::O_NONBLOCK as u32) << 8));
        assert_eq!(fds.clone_flags_for_dup(fd), (abi::O_NONBLOCK as u32) << 8);
    }

    #[test]
    fn closing_fd_removes_epoll_watch() {
        let mut fds = FdTable::empty();
        let watched = fds.alloc_fd(GuestFd::Null);
        let state = std::sync::Arc::new(std::sync::Mutex::new(EpollState::default()));
        state.lock().unwrap().watches.insert(
            (watched, fds.identity(watched).unwrap()),
            EpollWatch {
                events: abi::EPOLLIN,
                data: 7,
            },
        );
        let _epfd = fds.alloc_fd(GuestFd::Epoll(state.clone()));
        assert!(fds.remove_with_watch_cleanup(watched).is_some());
        assert!(state.lock().unwrap().watches.is_empty());
    }

    #[test]
    fn exec_signal_reset_preserves_ignored_handlers() {
        let mut state = SignalState::default();
        state.dispositions[0].handler = abi::SIG_IGN;
        state.dispositions[1].handler = 0x1234;
        state.pending = 1 << 1;
        state.reset_for_exec();
        assert_eq!(state.dispositions[0].handler, abi::SIG_IGN);
        assert_eq!(state.dispositions[1].handler, abi::SIG_DFL);
        assert_eq!(state.pending, 1 << 1);
    }

    #[test]
    fn aliases_share_status_but_keep_cloexec_and_watch_identity() {
        let mut fds = FdTable::empty();
        let source = fds.alloc_fd(GuestFd::Null);
        let alias = fds.alloc_fd(GuestFd::Null);
        fds.link_dup(source, alias);
        fds.update_flags(source, |flags| flags | 1 | ((abi::O_NONBLOCK as u32) << 8));
        assert_eq!(fds.get_flags(alias).unwrap() & 1, 0);
        assert_ne!(
            fds.get_flags(alias).unwrap() >> 8 & abi::O_NONBLOCK as u32,
            0
        );
        let identity = fds.identity(source).unwrap();
        let state = Arc::new(Mutex::new(EpollState::default()));
        state.lock().unwrap().watches.insert(
            (source, identity),
            EpollWatch {
                events: abi::EPOLLIN,
                data: 1,
            },
        );
        fds.alloc_fd(GuestFd::Epoll(state.clone()));
        fds.remove_with_watch_cleanup(source);
        assert_eq!(state.lock().unwrap().watches.len(), 1);
        let reused = fds.alloc_fd(GuestFd::Null);
        assert_eq!(reused, source);
        assert_ne!(fds.identity(reused), Some(identity));
        fds.remove_with_watch_cleanup(alias);
        assert!(state.lock().unwrap().watches.is_empty());
    }
}
