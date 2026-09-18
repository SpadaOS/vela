//! vela-sys：Host 抽象与各宿主实现。
//! 所有宿主差异（windows / linux_dev / spadaos）收敛在本 crate；
//! vela-runtime 及以上禁止出现 `cfg(target_os)` 与宿主类型（规格 2.4）。

use std::path::PathBuf;
use std::time::Duration;

// ---------------------------------------------------------------- 保护位

/// 宿主内存保护位（值与 Linux PROT_* 一致，便于直传）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostProt(u32);

impl HostProt {
    pub const READ: HostProt = HostProt(1);
    pub const WRITE: HostProt = HostProt(2);
    pub const EXEC: HostProt = HostProt(4);

    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn from_bits(b: u32) -> HostProt {
        HostProt(b & 0b111)
    }
    pub const fn contains(self, other: HostProt) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for HostProt {
    type Output = HostProt;
    fn bitor(self, rhs: HostProt) -> HostProt {
        HostProt(self.0 | rhs.0)
    }
}

// ---------------------------------------------------------------- 打开选项

#[derive(Clone, Copy, Debug, Default)]
pub struct HostOpen {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
}

// ---------------------------------------------------------------- 文件句柄

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPath(pub PathBuf);

/// 不透明文件句柄。Std* 变体归宿主生命周期管理，Disk 由 Drop 关闭。
#[derive(Debug)]
pub struct HostFile(pub HostFileKind);

#[derive(Debug)]
pub enum HostFileKind {
    StdIn,
    StdOut,
    StdErr,
    Disk(std::fs::File),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HostTid(pub u64);

// ---------------------------------------------------------------- 其他类型

#[derive(Debug)]
pub struct StdioHandles {
    pub stdin: HostFile,
    pub stdout: HostFile,
    pub stderr: HostFile,
}

#[derive(Clone, Debug)]
pub struct HostStat {
    pub size: i64,
    pub is_dir: bool,
    pub is_readonly: bool,
    pub mtime_ns: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    NotFound,
    Access,
    Invalid,
    NoMemory,
    Unimplemented,
    Other(i32),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostError::NotFound => write!(f, "not found"),
            HostError::Access => write!(f, "access denied"),
            HostError::Invalid => write!(f, "invalid argument"),
            HostError::NoMemory => write!(f, "out of memory"),
            HostError::Unimplemented => write!(f, "unimplemented on this host"),
            HostError::Other(e) => write!(f, "host error {e}"),
        }
    }
}

impl std::error::Error for HostError {}

// ---------------------------------------------------------------- Host trait

pub trait Host: Send + Sync + 'static {
    /// 分配匿名内存。anon=false 在 v0 未实现。返回的内存保证零填充。
    /// Windows 实现初始保护一律 RW（拷贝/patch 之后由 protect 收敛，规格 5.2）。
    unsafe fn map(&self, hint: usize, len: usize, prot: HostProt, anon: bool) -> Result<usize, HostError>;
    unsafe fn protect(&self, addr: usize, len: usize, prot: HostProt) -> Result<(), HostError>;
    /// 仅能整块释放 reserve 基址（Windows 限制，规格 5.2 表）。
    unsafe fn unmap(&self, addr: usize, len: usize) -> Result<(), HostError>;

    fn open(&self, path: &HostPath, opt: HostOpen) -> Result<HostFile, HostError>;
    fn read(&self, f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError>;
    fn write(&self, f: &HostFile, buf: &[u8]) -> Result<usize, HostError>;
    fn seek(&self, f: &HostFile, off: i64, whence: i32) -> Result<u64, HostError>;
    fn stat_path(&self, path: &HostPath) -> Result<HostStat, HostError>;
    fn close(&self, f: HostFile) -> Result<(), HostError>;

    fn stdio(&self) -> StdioHandles;

    fn monotonic_ns(&self) -> u64;
    fn realtime(&self) -> (i64, u32);
    fn random(&self, buf: &mut [u8]) -> Result<(), HostError>;

    /// 设置当前线程 FS 基址（客户 TLS，对应 arch_prctl(ARCH_SET_FS)）。
    /// 默认不支持；Windows 实现用 wrfsbase（需 CPU+OS 的 FSGSBASE 支持）。
    /// 不支持时 runtime 仅记录 fs_base 并照常返回 0（规格 5.1 允许）。
    fn set_fs_base(&self, v: u64) -> Result<(), HostError> {
        let _ = v;
        Err(HostError::Unimplemented)
    }

    fn thread_exit(&self, code: i32) -> !;
    fn process_exit(&self, code: i32) -> !;

    // v0 stub（规格 5.2）
    fn thread_create(&self, entry: extern "C" fn(*mut u8), arg: *mut u8) -> Result<HostTid, HostError> {
        let _ = (entry, arg);
        Err(HostError::Unimplemented)
    }
    fn futex_wait(&self, addr: *const u32, expected: u32, timeout: Option<Duration>) -> Result<(), HostError> {
        let _ = (addr, expected, timeout);
        Err(HostError::Unimplemented)
    }
    fn futex_wake(&self, addr: *const u32, n: u32) -> Result<u32, HostError> {
        let _ = (addr, n);
        Err(HostError::Unimplemented)
    }
}

// ---------------------------------------------------------------- 各宿主实现

/// 通用文件/时间操作（基于 std，跨 Windows 与 linux_dev 复用）。
pub(crate) mod file_ops;

pub mod spadaos;
#[cfg(windows)]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux_dev;
