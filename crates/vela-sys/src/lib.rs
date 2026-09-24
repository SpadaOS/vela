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

/// 匿名管道的一端（0.0.6 M1：pipe2 下沉为宿主管道，跨进程可继承）。
/// Windows 为真实句柄（ReadFile/WriteFile，阻塞语义）；内存实现供
/// 测试宿主/逻辑构建使用（空且写端开 → EAGAIN 假非阻塞）。
#[derive(Debug, Clone)]
pub struct PipeEnd(pub(crate) PipeEndInner);

#[derive(Debug, Clone)]
pub(crate) enum PipeEndInner {
    /// Windows HANDLE（inheritable；fork 后子进程同值）。
    Handle(isize),
    /// 内存管道（MockHost / linux_dev 逻辑测试）；bool = 是否读端。
    Mem(std::sync::Arc<PipeMem>, bool),
}

/// 磁盘文件的不透明 token（PLAN-0.1.0 T1.3）：宿主私有存储，
/// runtime/CLI 不得解包；对外仅暴露 `raw_handle` / 构造方法
/// （fork 协议的句柄序列化/重建）与文件路径查询。
#[derive(Debug)]
pub struct DiskFile(pub(crate) std::fs::File);

impl DiskFile {
    /// 构造（宿主实现与测试宿主用）。
    pub fn new(file: std::fs::File) -> Self {
        DiskFile(file)
    }
    /// 底层 std 文件（读写元数据用；测试宿主复用）。
    /// 注意：不得经它提取平台句柄做 fork 序列化——统一走 `raw_handle`。
    pub fn as_std_file(&self) -> &std::fs::File {
        &self.0
    }
    /// fork 协议序列化：底层宿主原始句柄（Windows HANDLE；继承后子进程同值）。
    #[cfg(windows)]
    pub fn raw_handle(&self) -> isize {
        use std::os::windows::io::AsRawHandle;
        self.0.as_raw_handle() as isize
    }
    /// fork 协议重建：由继承句柄构造磁盘文件 token（句柄所有权移交）。
    ///
    /// # Safety
    /// `h` 必须是调用方拥有所有权的有效文件句柄（继承而来的值）。
    #[cfg(windows)]
    pub unsafe fn from_raw_handle(h: isize) -> Self {
        use std::os::windows::io::FromRawHandle;
        DiskFile(std::fs::File::from_raw_handle(
            h as std::os::windows::io::RawHandle,
        ))
    }
}

/// 内存管道共享态（仅测试与逻辑构建路径使用）。
#[derive(Debug, Default)]
pub struct PipeMem {
    pub buf: std::sync::Mutex<Vec<u8>>,
    pub read_open: std::sync::atomic::AtomicBool,
    pub write_open: std::sync::atomic::AtomicBool,
}

impl PipeMem {
    pub fn new() -> Self {
        Self {
            buf: std::sync::Mutex::new(Vec::new()),
            read_open: std::sync::atomic::AtomicBool::new(true),
            write_open: std::sync::atomic::AtomicBool::new(true),
        }
    }
}

/// 内存管道端构造（测试宿主用；真实宿主用 create_pipe）。
pub fn pipe_mem_end(m: std::sync::Arc<PipeMem>, is_read: bool) -> PipeEnd {
    PipeEnd(PipeEndInner::Mem(m, is_read))
}

#[derive(Debug)]
pub enum HostFileKind {
    StdIn,
    StdOut,
    StdErr,
    /// 打开时记录宿主路径：fstat 需要稳定的 ino（路径哈希），std::fs::File 不携带路径。
    /// 文件本体为宿主私有 token（T1.3）。
    Disk {
        file: DiskFile,
        path: PathBuf,
    },
    /// 匿名管道一端（pipe2 产物；fstat = S_IFIFO）。
    Pipe(PipeEnd),
}

impl HostFileKind {
    /// std 变体的复制（dup 语义）；Disk 用 try_clone 由调用方处理。
    pub(crate) fn clone_kind(&self) -> HostFileKind {
        match self {
            HostFileKind::StdIn => HostFileKind::StdIn,
            HostFileKind::StdOut => HostFileKind::StdOut,
            HostFileKind::StdErr => HostFileKind::StdErr,
            HostFileKind::Pipe(e) => HostFileKind::Pipe(e.clone()),
            HostFileKind::Disk { .. } => unreachable!("dup_file handles Disk via try_clone"),
        }
    }
}

impl HostFile {
    /// fork 协议序列化：底层宿主原始句柄（磁盘文件与管道端有值）。
    #[cfg(windows)]
    pub fn raw_handle(&self) -> Option<isize> {
        match &self.0 {
            HostFileKind::Disk { file, .. } => Some(file.raw_handle()),
            HostFileKind::Pipe(e) => e.raw_handle(),
            _ => None,
        }
    }

    /// fork 协议序列化：磁盘文件的宿主路径。
    pub fn disk_path(&self) -> Option<&Path> {
        match &self.0 {
            HostFileKind::Disk { path, .. } => Some(path.as_path()),
            _ => None,
        }
    }

    /// fork 协议重建：由继承句柄构造磁盘文件 token（路径由元数据携带）。
    ///
    /// # Safety
    /// `h` 必须是调用方拥有所有权的有效文件句柄（继承而来的值）。
    #[cfg(windows)]
    pub unsafe fn disk_from_raw_handle(h: isize, path: PathBuf) -> HostFile {
        HostFile(HostFileKind::Disk {
            file: unsafe { DiskFile::from_raw_handle(h) },
            path,
        })
    }
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
        HostDir {
            path,
            queue: std::sync::Mutex::new(entries.into()),
        }
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

    /// 剩余条目快照（fork 元数据传递用；不消费队列）。
    pub fn clone_remaining(&self) -> Vec<HostDirEntry> {
        match self.queue.lock() {
            Ok(g) => g.clone().into(),
            Err(p) => p.into_inner().clone().into(),
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

// ---------------------------------------------------------------- Host trait 五组（SpadaOS 就绪）

// HOST.md 契约按 SpadaOS 内核能力分五组：map / file / time / thread / futex。
// 每组一个 supertrait，SpadaOS 实现者可逐组填实；`Host` 为集合 trait，
// runtime 只见 `&dyn Host`（规格 2.4：宿主差异全部收敛在本 crate）。
// 0.1.0 新增 trap / proc 两组（PLAN-0.1.0 T1.1/T1.2）：客户执行与
// 进程生命周期原语；目前唯一实现 windows（SpadaOS/macOS 走默认桩）。

/// 客户寄存器视图（宿主无关，PLAN-0.1.0 T1.1）：syscall 陷阱与故障路径
/// 共用的整数现场。字段顺序刻意与 Win64 CONTEXT 的 RAX..RIP 连续段一致
/// （windows.rs 有布局断言），VEH 路径零拷贝重解释；其他宿主布局自由。
#[repr(C)]
pub struct GuestRegs {
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
}

/// 一次 syscall 陷阱的完整现场：寄存器视图 + 宿主私有上下文。
/// `regs` 可写（dispatch 写回返回值/副作用），宿主上下文只读快照
/// （fork 协议经 `HostProc::fork_child_context` 解释）。
pub struct TrapFrame<'a> {
    pub regs: &'a mut GuestRegs,
    /// 陷阱时的 EFLAGS（syscall 约定 R11 = 旧 RFLAGS；只读）。
    pub e_flags: u64,
    opaque: *const u8,
    opaque_len: usize,
}

impl TrapFrame<'_> {
    pub(crate) fn new(
        regs: &mut GuestRegs,
        e_flags: u64,
        opaque: *const u8,
        opaque_len: usize,
    ) -> TrapFrame<'_> {
        TrapFrame {
            regs,
            e_flags,
            opaque,
            opaque_len,
        }
    }

    /// 宿主完整上下文的只读字节视图（布局宿主私有；Windows = CONTEXT
    /// 全量 0x4D0，含 XSAVE 状态——fork 快照正确性的前提）。仅在陷阱
    /// 回调执行期间有效。
    pub fn opaque_bytes(&self) -> &[u8] {
        // SAFETY: 构造自宿主异常上下文，回调期间有效
        unsafe { std::slice::from_raw_parts(self.opaque, self.opaque_len) }
    }
}

/// syscall dispatch 回调（宿主无关签名，PLAN-0.1.0 T1.1）：
/// 返回 syscall 结果；寄存器写回（Rax/Rcx/R11/Rip 推进、控制流改写）
/// 由回调直接操作 `frame.regs` 完成。
pub type TrapFn = unsafe extern "system" fn(nr: u64, args: &[u64; 6], frame: &mut TrapFrame) -> i64;

/// 组 6 trap：客户执行与 syscall 陷阱机制（VEH / 岛页 / 未来宿主机制）。
/// 默认全部未实现——仅真正能执行客户的宿主填实。
pub trait HostTrap: Send + Sync + 'static {
    /// 安装陷阱机制并注册 dispatch 回调。幂等。
    fn install_trap(&self, f: TrapFn) -> Result<(), HostError> {
        let _ = f;
        Err(HostError::Unimplemented)
    }

    /// 用新集合整体替换客户可执行范围（trap 过滤用；execve 原地重注册）。
    fn replace_exec_ranges(&self, ranges: &[(u64, u64)]) {
        let _ = ranges;
    }

    /// 切入客户（不返回）。
    ///
    /// # Safety
    /// entry/rsp 必须来自已映射且登记的客户映像；调用后宿主栈作废。
    unsafe fn enter_guest(&self, entry: u64, rsp: u64) -> ! {
        let _ = (entry, rsp);
        panic!("guest execution not supported on this host")
    }

    // ---- FS 基址机制（客户 TLS；0.1.0 唯一实现 windows）----

    /// FSGSBASE 能力探测（CPU + OS），结果缓存。
    fn fs_base_supported(&self) -> bool {
        false
    }
    /// 预切当前线程 FS 基址（仅进入客户前使用）。
    fn preset_fs_base(&self, v: u64) -> Result<(), HostError> {
        let _ = v;
        Err(HostError::Unimplemented)
    }
    /// 预切后强制一次内核侧 FS 基址刷新（吸收一次自身 UD2）。
    fn commit_fs_base(&self) {}
    /// 读取当前线程 FS 基址（不支持 → None）。
    fn read_fs_base(&self) -> Option<u64> {
        None
    }
    /// FS 切换 trampoline 的宿主地址（0 = 不可用）。
    fn fs_trampoline_addr(&self) -> usize {
        0
    }

    // ---- soft-tls（FSGSBASE 缺失环境的软件模拟）----

    fn enable_soft_tls(&self) {}
    fn set_soft_tls_base(&self, v: u64) {
        let _ = v;
    }
    /// trampoline 是否被实际执行过（诊断观测）。
    fn soft_tls_stub_hit(&self) -> bool {
        false
    }
}

/// 组 7 proc：进程生命周期原语（用户态 fork 协议的宿主侧，T1.2）。
/// 句柄 token 为 isize（宿主原始值，仅可传回同宿主方法；跨进程继承后同值）。
pub trait HostProc: Send + Sync + 'static {
    fn current_pid(&self) -> u32 {
        std::process::id()
    }

    // ---- 共享内存 section（fork 快照通道）----

    /// 页文件 backed section（跨进程共享，调用方负责置继承）。
    fn shared_section(&self, size: u64) -> Result<isize, HostError> {
        let _ = size;
        Err(HostError::Unimplemented)
    }
    /// 任意基址映射 section 视图（父侧拷贝快照用）。
    ///
    /// # Safety: 返回的视图由调用方独占使用（同进程）。
    unsafe fn map_section_anywhere(&self, sec: isize) -> Result<usize, HostError> {
        let _ = sec;
        Err(HostError::Unimplemented)
    }
    /// 固定基址映射（子进程回原地址——fork 指针一致性前提）。
    ///
    /// # Safety: base 必须为本进程空闲地址且区间足够容纳 section。
    unsafe fn map_section_at(&self, sec: isize, base: u64) -> Result<usize, HostError> {
        let _ = (sec, base);
        Err(HostError::Unimplemented)
    }
    fn unmap_section_view(&self, addr: usize) -> Result<(), HostError> {
        let _ = addr;
        Err(HostError::Unimplemented)
    }

    // ---- 句柄与子进程 ----

    /// 句柄置继承标志（fork 前提：pipe/section/disk fd）。
    fn set_inherit(&self, handle: isize) -> Result<(), HostError> {
        let _ = handle;
        Err(HostError::Unimplemented)
    }
    /// spawn 自身（命令行透传；句柄继承由调用方预先 set_inherit）。
    /// 返回 (pid, 进程句柄)。
    fn spawn_self(&self, cmdline: &str) -> Result<(u32, isize), HostError> {
        let _ = cmdline;
        Err(HostError::Unimplemented)
    }
    /// 等待子进程：timeout_ms = 0xFFFF_FFFF 阻塞 / 0 轮询；Ok(None) = 超时。
    fn wait(&self, proc: isize, timeout_ms: u32) -> Result<Option<u32>, HostError> {
        let _ = (proc, timeout_ms);
        Err(HostError::Unimplemented)
    }
    /// 终止子进程（kill SIGKILL/SIGTERM 的诚实近似）。
    fn kill(&self, proc: isize, code: u32) -> Result<(), HostError> {
        let _ = (proc, code);
        Err(HostError::Unimplemented)
    }
    /// 按 pid 打开进程（探测/kill 的 pid 形态；不存在 → NotFound）。
    fn open_process(&self, pid: u32) -> Result<isize, HostError> {
        let _ = pid;
        Err(HostError::Unimplemented)
    }
    fn close_handle(&self, handle: isize) {
        let _ = handle;
    }

    // ---- fork 元数据管道 ----

    /// inheritable 匿名管道，返回 (写端, 读端)。
    fn create_inherit_pipe(&self) -> Result<(isize, isize), HostError> {
        Err(HostError::Unimplemented)
    }
    fn pipe_write_all(&self, h: isize, data: &[u8]) -> Result<(), HostError> {
        let _ = (h, data);
        Err(HostError::Unimplemented)
    }
    fn pipe_read_exact(&self, h: isize, buf: &mut [u8]) -> Result<(), HostError> {
        let _ = (h, buf);
        Err(HostError::Unimplemented)
    }
    /// 由继承句柄构造管道端（fd 表重建）。
    fn pipe_end_from_raw(&self, h: isize, is_read: bool) -> PipeEnd {
        let _ = (h, is_read);
        unreachable!("pipe_end_from_raw not supported on this host")
    }

    // ---- fork 上下文 ----

    /// fork 子进程的恢复上下文（Linux「clone 返回 0」形态）：
    /// 父 trap 现场的宿主完整快照 + syscall 副作用改写（Rax=0、
    /// Rip/Rcx=返回地址、R11=RFLAGS、恢复所需 flags）。
    fn fork_child_context(&self, frame: &TrapFrame) -> Vec<u8> {
        let _ = frame;
        panic!("fork not supported on this host")
    }
    /// 注入完整上下文进入客户（fork 子进程恢复现场；不返回）。
    ///
    /// # Safety
    /// ctx 必须来自本宿主 `fork_child_context`；客户内存已按快照恢复并登记。
    unsafe fn resume_child(&self, ctx: &[u8]) -> ! {
        let _ = ctx;
        panic!("fork not supported on this host")
    }
}

/// 组 1 map：客户地址空间管理。
///
/// # Safety（组级约定）
/// - `map` 返回的内存归客户使用，调用方必须经 MemRegistry 登记后访问；
/// - `protect`/`unmap` 的 [addr, addr+len) 必须来自本宿主 `map` 的返回区间；
/// - `unmap` 后不得再访问该区间。
pub trait HostMem: Send + Sync + 'static {
    /// 分配匿名内存。anon=false 在 v0 未实现。返回的内存保证零填充。
    /// Windows 实现初始保护一律 RW（拷贝/patch 之后由 protect 收敛，规格 5.2）。
    unsafe fn map(
        &self,
        hint: usize,
        len: usize,
        prot: HostProt,
        anon: bool,
    ) -> Result<usize, HostError>;

    unsafe fn protect(&self, addr: usize, len: usize, prot: HostProt) -> Result<(), HostError>;

    /// 仅能整块释放 reserve 基址（Windows 限制，规格 5.2 表）。
    unsafe fn unmap(&self, addr: usize, len: usize) -> Result<(), HostError>;

    /// 文件映射（Linux MAP_PRIVATE 语义：读走文件、写 COW 私有页、不回写文件）。
    /// offset 与 hint（非 0 时）必须是宿主分配粒度的倍数（Windows 64K），
    /// 返回值可能不是调用方请求的地址——MAP_FIXED 语义由 runtime 层校验与回退。
    /// 默认未实现；实现方缺失时 runtime 自动退化为"匿名映射 + 读入文件内容"。
    ///
    /// # Safety（组级约定）
    /// - 返回的视图归客户使用，必须经 MemRegistry 以 FileView 登记后访问；
    /// - 解除必须用 `unmap_view`（与 `unmap` 原语不可互换）。
    unsafe fn map_file(
        &self,
        file: &HostFile,
        offset: u64,
        len: usize,
        hint: usize,
        prot: HostProt,
    ) -> Result<usize, HostError> {
        let _ = (file, offset, len, hint, prot);
        Err(HostError::Unimplemented)
    }

    /// 解除 `map_file` 返回的视图（Windows 侧为 UnmapViewOfFile）。
    unsafe fn unmap_view(&self, addr: usize) -> Result<(), HostError> {
        let _ = addr;
        Err(HostError::Unimplemented)
    }

    /// 解除区间提交（Windows MEM_DECOMMIT；reserve 保持有效）。
    /// execve 重载释放含 NOACCESS 页的堆块前先走这一步。默认未实现。
    unsafe fn decommit(&self, addr: usize, len: usize) -> Result<(), HostError> {
        let _ = (addr, len);
        Err(HostError::Unimplemented)
    }
}

/// 组 2 file：文件系统与 stdio。
pub trait HostFileOps: Send + Sync + 'static {
    fn open(&self, path: &HostPath, opt: HostOpen) -> Result<HostFile, HostError>;
    /// 打开目录做快照遍历（O_DIRECTORY 语义）。
    fn open_dir(&self, path: &HostPath) -> Result<HostDir, HostError>;
    /// 创建目录（mkdir 语义；父目录必须已存在，对应 0o755）。
    fn mkdir(&self, path: &HostPath) -> Result<(), HostError>;
    /// 删除文件（unlink）或空目录（rmdir）。
    fn remove(&self, path: &HostPath, dir: bool) -> Result<(), HostError>;
    /// 重命名/移动（rename 语义）。
    fn rename(&self, old: &HostPath, new: &HostPath) -> Result<(), HostError>;
    /// 刷新文件（fsync=sync_all / fdatasync=sync_data）。
    fn sync_file(&self, f: &HostFile, data_only: bool) -> Result<(), HostError>;
    /// 复制句柄（dup 语义；返回的新句柄与原句柄独立游标）。
    fn dup_file(&self, f: &HostFile) -> Result<HostFile, HostError>;
    fn read(&self, f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError>;
    fn write(&self, f: &HostFile, buf: &[u8]) -> Result<usize, HostError>;
    fn seek(&self, f: &HostFile, off: i64, whence: i32) -> Result<u64, HostError>;
    fn stat_path(&self, path: &HostPath) -> Result<HostStat, HostError>;
    /// 对已打开句柄取元数据（fstat 语义）；stdio 为字符设备。
    fn stat_file(&self, f: &HostFile) -> Result<HostStat, HostError>;
    /// 截断/扩展已打开文件到 len（ftruncate 语义；PLAN-0.0.5 M4）。
    fn set_len(&self, f: &HostFile, len: u64) -> Result<(), HostError> {
        let _ = (f, len);
        Err(HostError::Unimplemented)
    }
    /// 设置只读属性（fchmod 的 Windows 诚实近似：仅读写位，其余忽略）。
    fn set_readonly_file(&self, f: &HostFile, readonly: bool) -> Result<(), HostError> {
        let _ = (f, readonly);
        Err(HostError::Unimplemented)
    }
    fn close(&self, f: HostFile) -> Result<(), HostError>;
    fn stdio(&self) -> StdioHandles;
    /// 创建匿名管道（pipe2 语义），返回 (读端, 写端)。0.0.6 M1：
    /// Windows 实现 CreatePipe + 句柄 inheritable（fork 传递的前提）；
    /// 读写为真实阻塞语义（EOF = 写端全部关闭，EPIPE = 读端全部关闭）。
    /// 默认未实现（逻辑测试宿主可返回 Unimplemented）。
    fn create_pipe(&self) -> Result<(HostFile, HostFile), HostError> {
        Err(HostError::Unimplemented)
    }
}

/// 组 3 time：时间与熵（宿主环境信息；RNG 并入本组，见 PLAN-0.0.3 决策点 3）。
pub trait HostTime: Send + Sync + 'static {
    fn monotonic_ns(&self) -> u64;
    fn realtime(&self) -> (i64, u32);
    fn random(&self, buf: &mut [u8]) -> Result<(), HostError>;
}

/// 组 4 thread 的 TLS 面 + 组 5 futex 预留：SpadaOS 侧对应 TLS 寄存器切换与
/// 等待队列能力。v0.x 仅 set_fs_base 可用；thread_create/futex 为桩。
pub trait HostTls: Send + Sync + 'static {
    /// 设置当前线程 FS 基址（客户 TLS，对应 arch_prctl(ARCH_SET_FS)）。
    /// 默认不支持；Windows 实现用 wrfsbase（需 CPU+OS 的 FSGSBASE 支持）。
    /// 不支持时 runtime 仅记录 fs_base 并照常返回 0（规格 5.1 允许）。
    fn set_fs_base(&self, v: u64) -> Result<(), HostError> {
        let _ = v;
        Err(HostError::Unimplemented)
    }
}

/// 集合 trait：五组能力 + trap/proc（客户执行与进程原语）+ 线程生命周期桩。
pub trait Host: HostMem + HostFileOps + HostTime + HostTls + HostTrap + HostProc {
    fn thread_exit(&self, code: i32) -> !;
    fn process_exit(&self, code: i32) -> !;

    // 组 4/5 桩（规格 5.2 / 13）
    fn thread_create(
        &self,
        entry: extern "C" fn(*mut u8),
        arg: *mut u8,
    ) -> Result<HostTid, HostError> {
        let _ = (entry, arg);
        Err(HostError::Unimplemented)
    }
    fn futex_wait(
        &self,
        addr: *const u32,
        expected: u32,
        timeout: Option<Duration>,
    ) -> Result<(), HostError> {
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

#[cfg(target_os = "linux")]
pub mod linux_dev;
pub mod spadaos;
#[cfg(windows)]
pub mod windows;
