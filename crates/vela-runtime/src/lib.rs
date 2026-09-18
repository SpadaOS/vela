//! vela-runtime：维护 GuestProcess 并实现 Linux syscall 语义翻译（规格 5.4）。
//! 本 crate 禁止 `cfg(target_os)` 与任何 Windows/SpadaOS 类型——宿主差异全部走 `vela_sys::Host`。

pub mod mem;
pub mod syscalls;

pub use mem::{LoadedImage, MemRange, Segment};
pub use syscalls::dispatch;

use std::collections::BTreeMap;

use vela_abi as abi;
use vela_sys::{Host, HostFile, HostError, HostProt};

use crate::mem::MemRegistry;

// ---------------------------------------------------------------- fd 表

#[derive(Debug)]
pub enum GuestFd {
    Host(HostFile),
    Null,
    Zero,
    Reserved,
}

#[derive(Debug, Default)]
pub struct FdTable {
    table: BTreeMap<i32, GuestFd>,
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
        FdTable { table: t }
    }

    pub fn get(&self, fd: i32) -> Option<&GuestFd> {
        self.table.get(&fd)
    }

    pub fn remove(&mut self, fd: i32) -> Option<GuestFd> {
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
}

// ---------------------------------------------------------------- 进程

pub struct GuestProcess {
    pub pid: u32,
    pub uid: u32,
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
}

impl GuestProcess {
    pub fn new(pid: u32, load: LoadedImage) -> Self {
        let mut memreg = MemRegistry::default();
        memreg.add(load.span);
        GuestProcess {
            pid,
            uid: 1000,
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
        }
    }

    pub fn attach_stdio(&mut self, host: &dyn Host) {
        self.fds = FdTable::with_stdio(host);
    }

    /// 预留连续堆区域并把断点置于区域起点（规格 5.4 brk 说明）。
    pub fn init_heap(&mut self, host: &dyn Host, hint: u64, size: u64) -> Result<u64, HostError> {
        // SAFETY: host.map 契约保证返回零填充可写内存
        let addr = unsafe { host.map(hint as usize, size as usize, HostProt::READ | HostProt::WRITE, true) }? as u64;
        let r = MemRange { start: addr, len: size };
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
pub fn read_cstr(proc: &GuestProcess, addr: u64) -> Result<String, i32> {
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0u64;
    loop {
        if i >= 4096 {
            return Err(abi::ENAMETOOLONG);
        }
        let b = read_guest(proc, addr + i, 1)?[0];
        if b == 0 {
            break;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| abi::EINVAL)
}

/// HostError → Linux errno（取负由调用方处理）。
pub fn host_err_to_errno(e: &HostError) -> i32 {
    match e {
        HostError::NotFound => abi::ENOENT,
        HostError::Access => abi::EACCES,
        HostError::Invalid => abi::EINVAL,
        HostError::NoMemory => abi::ENOMEM,
        HostError::Unimplemented => abi::ENOSYS,
        HostError::Other(c) => *c,
    }
}
