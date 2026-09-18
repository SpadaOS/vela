//! vela-sys：Host 抽象与各宿主实现。
//! 所有宿主差异（windows / linux_dev / spadaos）收敛在本 crate；
//! vela-runtime 及以上禁止出现 `cfg(target_os)` 与宿主类型（规格 2.4）。

use std::path::{Path, PathBuf};
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
    /// O_EXCL：与 create 同用时新文件必须不存在（create_new 语义）。
    pub excl: bool,
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
    /// 打开时记录宿主路径：fstat 需要稳定的 ino（路径哈希），std::fs::File 不携带路径。
    Disk { file: std::fs::File, path: PathBuf },
}

// ---------------------------------------------------------------- 目录遍历

/// 目录条目（getdents64 组装用）。
#[derive(Clone, Debug)]
pub struct HostDirEntry {
    pub name: String,
    pub is_dir: bool,
    /// 与 stat 同源（路径哈希），保证 stat/getdents 一致。
    pub ino: u64,
}

/// 目录遍历句柄：open_dir 时对目录做一次性快照（按名称排序，保证确定性），
/// peek/advance 逐条消费。0.0.2 快照语义：不感知遍历期间的目录变化。
#[derive(Debug)]
pub struct HostDir {
    path: PathBuf,
    queue: std::sync::Mutex<std::collections::VecDeque<HostDirEntry>>,
}

impl HostDir {
    /// 测试与宿主实现共用构造。
    pub fn from_parts(path: PathBuf, entries: Vec<HostDirEntry>) -> HostDir {
        HostDir { path, queue: std::sync::Mutex::new(entries.into()) }
    }

    /// 宿主目录路径（openat dirfd 相对路径解析用）。
    pub fn host_path(&self) -> &Path {
        &self.path
    }

    /// 窥视下一条（不消费）；None = 目录读完。
    pub fn peek(&self) -> Result<Option<HostDirEntry>, HostError> {
        match self.queue.lock() {
            Ok(g) => Ok(g.front().cloned()),
            Err(p) => Ok(p.into_inner().front().cloned()),
        }
    }

    /// 消费当前条目（必须先 peek 成功）。
    pub fn advance(&self) {
        if let Ok(mut g) = self.queue.lock() {
            g.pop_front();
        }
    }
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
    // ---- 0.0.2：完整文件元数据（Linux stat 语义所需）----
    /// Linux st_mode：含 S_IF* 文件类型位与权限位（值与 Linux 一致）。
    pub mode: u32,
    pub nlink: u64,
    /// inode 号。约定：同进程内稳定，且 stat 与目录遍历结果一致即可
    /// （musl 不要求真实 inode），Windows 用 file_index/句柄哈希满足。
    pub ino: u64,
    /// 设备号。约定：同进程内稳定，同卷相同。
    pub dev: u64,
    pub atime_ns: i64,
    pub ctime_ns: i64,
}

impl HostStat {
    /// 字符设备元数据（/dev/null、/dev/zero、stdio）。
    pub fn char_device() -> HostStat {
        HostStat {
            size: 0,
            is_dir: false,
            is_readonly: false,
            mtime_ns: 0,
            mode: 0o0020000 | 0o666, // S_IFCHR | 0666
            nlink: 1,
            ino: 1,
            dev: 1,
            atime_ns: 0,
            ctime_ns: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    NotFound,
    Access,
    Invalid,
    NoMemory,
    /// 文件已存在（O_EXCL create_new 冲突）。
    Exist,
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
            HostError::Exist => write!(f, "file exists"),
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
    /// 打开目录做快照遍历（O_DIRECTORY 语义）。
    fn open_dir(&self, path: &HostPath) -> Result<HostDir, HostError>;
    fn read(&self, f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError>;
    fn write(&self, f: &HostFile, buf: &[u8]) -> Result<usize, HostError>;
    fn seek(&self, f: &HostFile, off: i64, whence: i32) -> Result<u64, HostError>;
    fn stat_path(&self, path: &HostPath) -> Result<HostStat, HostError>;
    /// 对已打开句柄取元数据（fstat 语义）；stdio 为字符设备。
    fn stat_file(&self, f: &HostFile) -> Result<HostStat, HostError>;
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
