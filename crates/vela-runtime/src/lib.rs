//! vela-runtime：维护 GuestProcess 并实现 Linux syscall 语义翻译（规格 5.4）。
//! 本 crate 禁止 `cfg(target_os)` 与任何 Windows/SpadaOS 类型——宿主差异全部走 `vela_sys::Host`。

pub mod mem;
pub mod syscalls;

pub use mem::{InterpImage, LoadedImage, MemRange, Segment};
pub use syscalls::dispatch;

use std::collections::BTreeMap;

use vela_abi as abi;
use vela_sys::{Host, HostDir, HostError, HostFile, HostProt};

use crate::mem::MemRegistry;

// ---------------------------------------------------------------- fd 表

/// 进程内管道（PLAN-0.0.4 T3.2）：pipe2 创建的 fd 对共享此缓冲。
/// v0 单线程无阻塞调度——空读且写端开着返回 -EAGAIN、满写返回 -EAGAIN。
#[derive(Debug, Default)]
pub struct Pipe {
    pub buf: std::cell::RefCell<Vec<u8>>,
    pub read_open: std::cell::Cell<bool>,
    pub write_open: std::cell::Cell<bool>,
    /// 环形缓冲容量（Linux 默认 64 KiB）。
    pub capacity: usize,
}

pub const PIPE_CAPACITY: usize = 64 * 1024;

#[derive(Debug)]
pub enum GuestFd {
    Host(HostFile),
    /// 目录快照句柄（O_DIRECTORY 打开；getdents64 消费）。
    HostDir(HostDir),
    /// 管道读端（clone 自共享 Pipe）。
    PipeRead(std::rc::Rc<Pipe>),
    /// 管道写端。
    PipeWrite(std::rc::Rc<Pipe>),
    Null,
    Zero,
    Reserved,
}

impl GuestFd {
    /// 是否持有宿主资源（close 时需要动作）。
    pub fn is_pipe(&self) -> bool {
        matches!(self, GuestFd::PipeRead(_) | GuestFd::PipeWrite(_))
    }
}

#[derive(Debug, Default)]
pub struct FdTable {
    table: BTreeMap<i32, GuestFd>,
    /// 每 fd 的标志记账（fcntl）：bit0 = FD_CLOEXEC，bits 8..24 = status flags
    /// （O_APPEND/O_NONBLOCK/O_ACCMODE），其余保留。
    flags: BTreeMap<i32, u32>,
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
        };
        for fd in 0..3 {
            f.flags.insert(fd, (abi::O_RDWR as u32) << 8);
        }
        f
    }

    pub fn get(&self, fd: i32) -> Option<&GuestFd> {
        self.table.get(&fd)
    }

    pub fn remove(&mut self, fd: i32) -> Option<GuestFd> {
        self.flags.remove(&fd);
        self.table.remove(&fd)
    }

    /// 分配最小可用 fd。
    pub fn alloc_fd(&mut self, entry: GuestFd) -> i32 {
        let mut fd = 0;
        while self.table.contains_key(&fd) {
            fd += 1;
        }
        self.table.insert(fd, entry);
        fd
    }

    /// 强制占用指定 fd（dup2 语义）；已存在条目由调用方先 remove。
    pub fn insert_at(&mut self, fd: i32, entry: GuestFd) {
        self.table.insert(fd, entry);
    }

    /// 记账 fd 标志（open 时记录客户传入 flags 的编码）。
    pub fn set_flags(&mut self, fd: i32, v: u32) {
        self.flags.insert(fd, v);
    }

    pub fn get_flags(&self, fd: i32) -> Option<u32> {
        self.flags.get(&fd).copied()
    }

    /// 更新 flags（F_SETFL/F_SETFD）；未记账的 fd 以 0 起始。
    pub fn update_flags(&mut self, fd: i32, f: impl FnOnce(u32) -> u32) {
        let v = self.flags.entry(fd).or_insert(0);
        *v = f(*v);
    }

    /// execve（PLAN-0.0.4 T3.1/T3.2）：关闭所有带 FD_CLOEXEC 的 fd，
    /// 其余（管道等）跨重载保留。Host fd 调 host.close；管道端标记关闭，
    /// 读端看到 EOF、写端看到 EPIPE。返回关闭数量。
    pub fn close_cloexec(&mut self, host: &dyn Host) -> usize {
        let clo: Vec<i32> = self
            .flags
            .iter()
            .filter(|(_, f)| *f & 1 != 0)
            .map(|(fd, _)| *fd)
            .collect();
        let mut n = 0;
        for fd in clo {
            if let Some(gf) = self.remove(fd) {
                n += 1;
                match gf {
                    GuestFd::Host(h) => {
                        let _ = host.close(h);
                    }
                    GuestFd::PipeRead(p) => p.read_open.set(false),
                    GuestFd::PipeWrite(p) => p.write_open.set(false),
                    _ => {}
                }
            }
        }
        n
    }
}

// ---------------------------------------------------------------- 进程

pub struct GuestProcess {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub fs_base: u64,
    pub gs_base: u64,
    /// 待应用的 FS 基址：宿主支持时由 SET_FS 记录，CLI 在异常返回后
    /// 通过 trampoline 实际切换（wrfsbase 在 VEH 处理器内会被内核还原）。
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
}

impl GuestProcess {
    pub fn new(pid: u32, load: LoadedImage) -> Self {
        let mut memreg = MemRegistry::default();
        memreg.add(load.span);
        if let Some(i) = &load.interp {
            // 解释器映像同样纳入 EFAULT 检查与 munmap 记账（PLAN-0.0.4 T2.2）
            memreg.add(i.span);
        }
        GuestProcess {
            pid,
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
        }
    }

    pub fn attach_stdio(&mut self, host: &dyn Host) {
        self.fds = FdTable::with_stdio(host);
    }

    /// 预留连续堆区域并把断点置于区域起点（规格 5.4 brk 说明）。
    pub fn init_heap(&mut self, host: &dyn Host, hint: u64, size: u64) -> Result<u64, HostError> {
        // SAFETY: host.map 契约保证返回零填充可写内存
        let addr = unsafe {
            host.map(
                hint as usize,
                size as usize,
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
pub fn read_guest<'a>(proc: &GuestProcess, addr: u64, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if !proc.mem.contains(addr, len as u64) {
        return Err(abi::EFAULT);
    }
    // SAFETY: 同进程地址空间；区间已确认登记在客户映射内
    Ok(unsafe { std::slice::from_raw_parts(addr as *const u8, len) })
}

/// 可变版本。v0 单线程且客户内存归 runtime 独占管理，无并发别名。
pub fn read_guest_mut<'a>(proc: &GuestProcess, addr: u64, len: usize) -> Result<&'a mut [u8], i32> {
    if len == 0 {
        return Ok(&mut []);
    }
    if !proc.mem.contains(addr, len as u64) {
        return Err(abi::EFAULT);
    }
    // SAFETY: 同上；v0 无并发访问者
    Ok(unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) })
}

pub fn write_guest(proc: &GuestProcess, addr: u64, data: &[u8]) -> Result<(), i32> {
    if data.is_empty() {
        return Ok(());
    }
    if !proc.mem.contains(addr, data.len() as u64) {
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
        let page_end = (cur | 0xFFF) + 1; // 本页尾（含）
        let want = (page_end - cur).min((4096 - out.len()) as u64);
        // 在请求长度内找最大合法前缀（正常情况 want 即合法；跨界时退化）
        let mut n = want;
        while n > 0 && !proc.mem.contains(cur, n) {
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
                cur += n;
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
        HostError::Unimplemented => abi::ENOSYS,
        HostError::Other(c) => *c,
    }
}
