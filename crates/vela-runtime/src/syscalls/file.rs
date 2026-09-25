//! 文件与 IO 子系统（PLAN-0.1.0 T5.1）：读写/writev、open/close、工作目录、
//! stat 家族与 statx、目录遍历、fcntl/ioctl、定位读写/fsync/lseek、路径写
//! 操作、fd 复制、pipe2，以及 sysinfo/readlinkat/getrusage/prlimit64/utimensat。

use vela_abi as abi;
use vela_sys::{Host, HostError, HostFile, HostFileKind, HostOpen, HostPath, HostStat};

use crate::{
    host_err_to_errno, read_cstr, read_guest, read_guest_mut, write_guest, GuestFd, GuestProcess,
};

// ---------------------------------------------------------------- 读写

pub(super) fn sys_write(
    proc: &GuestProcess,
    host: &dyn Host,
    fd_raw: u64,
    buf: u64,
    len: u64,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    match proc.fds.get(fd) {
        None => -(abi::EBADF as i64),
        Some(GuestFd::Null) | Some(GuestFd::Zero) => len as i64,
        Some(GuestFd::Reserved) => -(abi::EBADF as i64),
        Some(GuestFd::HostDir(_)) => -(abi::EBADF as i64), // 不能 write 目录
        Some(GuestFd::PipeRead(_)) => -(abi::EBADF as i64), // 读端不可写
        // 管道写端与宿主文件同路径：EPIPE/容量语义由宿主管道给出
        //（0.0.6 M1：真实阻塞写，满则阻塞——单线程客户语义正确）
        Some(GuestFd::PipeWrite(f)) | Some(GuestFd::Host(f)) => {
            if len == 0 {
                return 0;
            }
            match read_guest(proc, buf, len as usize) {
                Ok(data) => host
                    .write(f, data)
                    .map(|n| n as i64)
                    .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
                Err(e) => -(e as i64),
            }
        }
    }
}

pub(super) fn sys_read(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd_raw: u64,
    buf: u64,
    len: u64,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    if len == 0 {
        return 0;
    }
    match proc.fds.get(fd) {
        None | Some(GuestFd::Reserved) => -(abi::EBADF as i64),
        Some(GuestFd::Null) => 0,
        Some(GuestFd::HostDir(_)) => -(abi::EISDIR as i64), // read 目录
        Some(GuestFd::Zero) => match write_zeros(proc, buf, len as usize) {
            Ok(()) => len as i64,
            Err(e) => -(e as i64),
        },
        // 管道读端：空管道真实阻塞（宿主管道语义），写端全关 → EOF（0）
        Some(GuestFd::PipeWrite(_)) => -(abi::EBADF as i64), // 写端不可读
        Some(GuestFd::PipeRead(f)) | Some(GuestFd::Host(f)) => {
            match read_guest_mut(proc, buf, len as usize) {
                Ok(dst) => host
                    .read(f, dst)
                    .map(|n| n as i64)
                    .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
                Err(e) => -(e as i64),
            }
        }
    }
}

fn write_zeros(proc: &GuestProcess, addr: u64, len: usize) -> Result<(), i32> {
    write_guest(proc, addr, &vec![0u8; len])
}

pub(super) fn sys_writev(
    proc: &GuestProcess,
    host: &dyn Host,
    fd_raw: u64,
    iov: u64,
    iovcnt_raw: u64,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    let iovcnt = iovcnt_raw as u32 as i32;
    if !(0..=1024).contains(&iovcnt) {
        return -(abi::EINVAL as i64);
    }
    if iovcnt == 0 {
        return 0;
    }
    match proc.fds.get(fd) {
        None | Some(GuestFd::Reserved) => -(abi::EBADF as i64),
        Some(GuestFd::HostDir(_)) => -(abi::EBADF as i64),
        Some(GuestFd::Null) | Some(GuestFd::Zero) => {
            // /dev/null 语义：校验可读后返回总长
            let mut total = 0i64;
            for i in 0..iovcnt as u64 {
                match read_guest(proc, iov + i * 16, 16) {
                    Ok(ent) => total += rd_u64(ent, 8) as i64,
                    Err(e) => return -(e as i64),
                }
            }
            total
        }
        Some(GuestFd::PipeRead(_)) => -(abi::EBADF as i64),
        // 管道写端走宿主管道（阻塞写 + OS 容量管理），与文件同路径
        Some(GuestFd::PipeWrite(f)) | Some(GuestFd::Host(f)) => {
            let mut total = 0i64;
            for i in 0..iovcnt as u64 {
                let ent = match read_guest(proc, iov + i * 16, 16) {
                    Ok(e) => e,
                    Err(e) => return -(e as i64),
                };
                let (base, len) = (rd_u64(ent, 0), rd_u64(ent, 8));
                if len == 0 {
                    continue;
                }
                let data = match read_guest(proc, base, len as usize) {
                    Ok(d) => d,
                    Err(e) => return -(e as i64),
                };
                match host.write(f, data) {
                    Ok(n) => total += n as i64,
                    Err(e) => return -(host_err_to_errno(&e) as i64),
                }
            }
            total
        }
    }
}

fn rd_u64(b: &[u8], off: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(x)
}

// ---------------------------------------------------------------- 文件

pub(super) fn sys_open(proc: &mut GuestProcess, host: &dyn Host, path_ptr: u64, flags: u64) -> i64 {
    open_common(proc, host, abi::AT_FDCWD, path_ptr, flags)
}

pub(super) fn sys_openat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    open_common(proc, host, a[0] as u32 as i32, a[1], a[2])
}

/// open/openat 公共路径解析与打开（flags 为 Linux 客户侧标志）。
fn open_common(
    proc: &mut GuestProcess,
    host: &dyn Host,
    dirfd: i32,
    path_ptr: u64,
    flags: u64,
) -> i64 {
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    // 解析为宿主路径：绝对路径走 vela-fs 翻译；相对路径按 dirfd（AT_FDCWD→cwd，
    // 目录 fd→其宿主目录）拼接。规格 2.4：进入 Host 的必须是宿主原生路径。
    let host_path = if path.starts_with('/') {
        match proc.fs.translate(&path) {
            Some(p) => p,
            None => return -(abi::ENOENT as i64),
        }
    } else if dirfd == abi::AT_FDCWD {
        match proc.fs.translate(&resolve_rel(proc, &path)) {
            Some(p) => p,
            None => return -(abi::ENOENT as i64),
        }
    } else {
        match proc.fds.get(dirfd) {
            Some(GuestFd::HostDir(d)) => {
                // 相对路径禁止 ".."（与 vela-fs 的逃逸防护一致）
                if path.split('/').any(|c| c == "..") {
                    return -(abi::EINVAL as i64);
                }
                let mut p = d.host_path().to_path_buf();
                for c in path.split('/') {
                    if !c.is_empty() && c != "." {
                        p.push(c);
                    }
                }
                p
            }
            Some(_) | None => return -(abi::EBADF as i64),
        }
    };
    let acc = flags & 0b11;
    let opt = HostOpen {
        read: acc == abi::O_RDONLY || acc == abi::O_RDWR,
        write: acc != abi::O_RDONLY,
        create: flags & abi::O_CREAT != 0,
        excl: flags & abi::O_EXCL != 0,
        truncate: flags & abi::O_TRUNC != 0,
        append: flags & abi::O_APPEND != 0,
    };
    let flag_bits = flags as u32;
    if flags & abi::O_DIRECTORY != 0 {
        match host.open_dir(&HostPath(host_path)) {
            Ok(d) => {
                let fd = proc.fds.alloc_fd(GuestFd::HostDir(d));
                proc.fds.set_flags(fd, encode_flags(flag_bits));
                fd as i64
            }
            Err(e) => -(host_err_to_errno(&e) as i64),
        }
    } else {
        match host.open(&HostPath(host_path), opt) {
            Ok(f) => {
                let fd = proc.fds.alloc_fd(GuestFd::Host(f));
                proc.fds.set_flags(fd, encode_flags(flag_bits));
                fd as i64
            }
            Err(e) => -(host_err_to_errno(&e) as i64),
        }
    }
}

/// fd 标志编码：bit0 = FD_CLOEXEC，bits 8..24 = status flags。
fn encode_flags(flags: u32) -> u32 {
    let mut v = 0u32;
    if flags & abi::O_CLOEXEC as u32 != 0 {
        v |= 1;
    }
    v | ((flags & 0x1_FFFF) << 8)
}

/// 编码 → Linux status flags（F_GETFL 返回值）。
fn decode_status(encoded: u32) -> u32 {
    (encoded >> 8) & 0x1_FFFF
}

/// 相对路径拼 cwd；绝对路径原样（vela-fs 只接受 Linux 风格路径）。
fn resolve_rel(proc: &GuestProcess, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{}/{}", proc.cwd.trim_end_matches('/'), path)
    }
}

// ---------------------------------------------------------------- 工作目录

/// getcwd(buf, size)：写入 cwd（含 NUL）。缓冲不足返回 -ERANGE。
pub(super) fn sys_getcwd(proc: &GuestProcess, buf: u64, size: u64) -> i64 {
    if size == 0 {
        return -(abi::EINVAL as i64);
    }
    let need = proc.cwd.len() + 1;
    if (size as usize) < need {
        return -(abi::ERANGE as i64);
    }
    let mut out = proc.cwd.clone().into_bytes();
    out.push(0);
    match write_guest(proc, buf, &out) {
        Ok(()) => buf as i64, // Linux getcwd 成功返回 buf 地址
        Err(e) => -(e as i64),
    }
}

/// chdir(path)：翻译并校验目标为存在目录后更新记账 cwd（不改宿主进程目录）。
/// `..` 由 vela-fs 统一拒绝（0.0.2 简化，见 PLAN-0.0.2 T2.2）。
pub(super) fn sys_chdir(proc: &mut GuestProcess, host: &dyn Host, path_ptr: u64) -> i64 {
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    let Some(host_path) = proc.fs.translate(&resolve_rel(proc, &path)) else {
        return -(abi::ENOENT as i64);
    };
    match host.stat_path(&HostPath(host_path)) {
        Ok(st) if st.is_dir => {}
        Ok(_) => return -(abi::ENOTDIR as i64),
        Err(e) => return -(host_err_to_errno(&e) as i64),
    }
    // 规范化客户侧 cwd：组件折叠（"." 去除）；目标必为已翻译合法路径
    let joined = resolve_rel(proc, &path);
    let comps: Vec<&str> = joined
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    proc.cwd = if comps.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", comps.join("/"))
    };
    0
}

// ---------------------------------------------------------------- stat 家族

pub(super) fn sys_stat(
    proc: &mut GuestProcess,
    host: &dyn Host,
    path_ptr: u64,
    statbuf: u64,
) -> i64 {
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    // v0 无 symlink 语义，lstat ≡ stat（NONGOALS：不做真实 symlink）
    let Some(host_path) = proc.fs.translate(&resolve_rel(proc, &path)) else {
        return -(abi::ENOENT as i64);
    };
    fill_stat(proc, host.stat_path(&HostPath(host_path)), statbuf)
}

pub(super) fn sys_fstat(proc: &GuestProcess, host: &dyn Host, fd_raw: u64, statbuf: u64) -> i64 {
    let fd = fd_raw as u32 as i32;
    let r = match proc.fds.get(fd) {
        None | Some(GuestFd::Reserved) => return -(abi::EBADF as i64),
        Some(GuestFd::Null) | Some(GuestFd::Zero) => Ok(HostStat::char_device()),
        Some(GuestFd::Host(f)) | Some(GuestFd::PipeRead(f)) | Some(GuestFd::PipeWrite(f)) => {
            host.stat_file(f) // 管道端 → S_IFIFO（file_ops::fifo_stat）
        }
        Some(GuestFd::HostDir(d)) => host.stat_path(&HostPath(d.host_path().to_path_buf())),
    };
    fill_stat(proc, r, statbuf)
}

pub(super) fn sys_newfstatat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let (dirfd, path_ptr, statbuf, flags) = (a[0] as u32 as i32, a[1], a[2], a[3]);
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    if path.is_empty() {
        // AT_EMPTY_PATH：对 dirfd 本身做 fstat（CLOEXEC 之外唯一常用形态）
        if flags & abi::AT_EMPTY_PATH == 0 {
            return -(abi::EINVAL as i64);
        }
        return sys_fstat(proc, host, dirfd as u64, statbuf);
    }
    if dirfd != abi::AT_FDCWD {
        return -(abi::EBADF as i64); // 目录 fd 相对路径 v0.2 仍不支持（规格 5.5）
    }
    // AT_SYMLINK_NOFOLLOW 与否等价（无 symlink 语义）
    let Some(host_path) = proc.fs.translate(&resolve_rel(proc, &path)) else {
        return -(abi::ENOENT as i64);
    };
    fill_stat(proc, host.stat_path(&HostPath(host_path)), statbuf)
}

/// HostStat → Linux `struct stat` 并写入客户缓冲区。
fn fill_stat(proc: &GuestProcess, r: Result<HostStat, HostError>, buf: u64) -> i64 {
    match r {
        Ok(hs) => {
            let st = host_stat_to_linux(&hs, proc.uid, proc.gid);
            // SAFETY: Stat 为 repr(C) 纯数值 POD，144 字节（vela-abi const 断言锁死）
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&st as *const abi::Stat) as *const u8,
                    std::mem::size_of::<abi::Stat>(),
                )
            };
            match write_guest(proc, buf, bytes) {
                Ok(()) => 0,
                Err(e) => -(e as i64),
            }
        }
        Err(e) => -(host_err_to_errno(&e) as i64),
    }
}

fn host_stat_to_linux(hs: &HostStat, uid: u32, gid: u32) -> abi::Stat {
    abi::Stat {
        st_dev: hs.dev,
        st_ino: hs.ino,
        st_nlink: hs.nlink,
        st_mode: hs.mode,
        st_uid: uid,
        st_gid: gid,
        __pad0: 0,
        st_rdev: 0,
        st_size: hs.size,
        st_blksize: 4096,
        st_blocks: (hs.size + 511) / 512,
        st_atime: hs.atime_ns / 1_000_000_000,
        st_atime_nsec: hs.atime_ns % 1_000_000_000,
        st_mtime: hs.mtime_ns / 1_000_000_000,
        st_mtime_nsec: hs.mtime_ns % 1_000_000_000,
        st_ctime: hs.ctime_ns / 1_000_000_000,
        st_ctime_nsec: hs.ctime_ns % 1_000_000_000,
        __unused: [0; 3],
    }
}

pub(super) fn sys_close(proc: &mut GuestProcess, host: &dyn Host, fd_raw: u64) -> i64 {
    let fd = fd_raw as u32 as i32;
    match proc.fds.remove(fd) {
        None => -(abi::EBADF as i64),
        Some(GuestFd::Host(f)) | Some(GuestFd::PipeRead(f)) | Some(GuestFd::PipeWrite(f)) => {
            match host.close(f) {
                Ok(()) => 0,
                Err(e) => -(host_err_to_errno(&e) as i64),
            }
        }
        Some(_) => 0,
    }
}

// ---------------------------------------------------------------- 管道 / 文件杂项

/// sysinfo(99)（PLAN-0.0.5 M4）：struct sysinfo（112 字节）。
/// uptime 用宿主运行时长；内存量诚实近似（vela 无宿主内存记账）。
pub(super) fn sys_sysinfo(proc: &mut GuestProcess, host: &dyn Host, buf: u64) -> i64 {
    const SI_LOAD_SHIFT: u64 = 16;
    let mut b = [0u8; 112];
    // uptime（秒）
    let uptime = host.monotonic_ns() / 1_000_000_000;
    b[0..8].copy_from_slice(&(uptime as i64).to_le_bytes());
    // loads[3]：0（无负载记账），按内核 SI_LOAD_SHIFT 定点编码
    for i in 0..3 {
        let o = 8 + i * 8;
        b[o..o + 8].copy_from_slice(&(1u64 << SI_LOAD_SHIFT).to_le_bytes());
    }
    // totalram/freeram：诚实近似（固定 8 GiB / 4 GiB）；mem_unit=1
    b[32..40].copy_from_slice(&8u64.wrapping_mul(1024 * 1024 * 1024).to_le_bytes());
    b[40..48].copy_from_slice(&4u64.wrapping_mul(1024 * 1024 * 1024).to_le_bytes());
    // procs = 1（单进程）
    b[80..82].copy_from_slice(&1u16.to_le_bytes());
    match write_guest(proc, buf, &b) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// fchmod(91)/chmod(90)（PLAN-0.0.5 M4）：Windows 只读位近似。
/// mode & 0222 == 0 → 只读；其余权限位忽略（记录于 SYSCALLS.md）。
pub(super) fn sys_fchmod(proc: &mut GuestProcess, host: &dyn Host, fd: u64, mode: u64) -> i64 {
    let fd = fd as u32 as i32;
    let readonly = mode & 0o222 == 0;
    match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => host
            .set_readonly_file(f, readonly)
            .map(|_| 0)
            .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
        Some(GuestFd::PipeRead(_)) | Some(GuestFd::PipeWrite(_)) => 0, // 无持久化语义
        _ => -(abi::EBADF as i64),
    }
}

/// readlinkat(267)/readlink(89)：vela 无 procfs、无 symlink——
/// 一律 -ENOENT（与 Linux 对不存在路径的语义一致）。
pub(super) fn sys_readlinkat(_dirfd: i32, _path: u64, _buf: u64, _size: u64) -> i64 {
    -(abi::ENOENT as i64)
}

/// ftruncate(77)（PLAN-0.0.5 M4）：截断/扩展已打开文件到 len。
pub(super) fn sys_ftruncate(proc: &mut GuestProcess, host: &dyn Host, fd: u64, len: u64) -> i64 {
    let fd = fd as u32 as i32;
    match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => host
            .set_len(f, len)
            .map(|_| 0)
            .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
        Some(GuestFd::PipeRead(_)) | Some(GuestFd::PipeWrite(_)) => -(abi::EINVAL as i64),
        _ => -(abi::EBADF as i64),
    }
}

/// fchown(93)/fchownat(260)：Windows 无 per-file 属主——校验 fd 后返回 0
/// （诚实 no-op，记录于 SYSCALLS.md）。
pub(super) fn sys_fchown(proc: &mut GuestProcess, fd: u64) -> i64 {
    let fd = fd as u32 as i32;
    match proc.fds.get(fd) {
        Some(GuestFd::Host(_) | GuestFd::PipeRead(_) | GuestFd::PipeWrite(_)) => 0,
        _ => -(abi::EBADF as i64),
    }
}

/// getrlimit(160)/setrlimit(161)：RLIM_INFINITY（与 prlimit64 一致）。
pub(super) fn sys_getrlimit(proc: &mut GuestProcess, buf: u64) -> i64 {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&abi::RLIM_INFINITY.to_le_bytes());
    b[8..16].copy_from_slice(&abi::RLIM_INFINITY.to_le_bytes());
    match write_guest(proc, buf, &b) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// pipe2(293)（0.0.6 M1 T1.1 下沉为宿主管道）：fd 对可跨 fork 继承，
/// 读写为真实阻塞语义（EOF = 写端全关，EPIPE = 读端全关）。
/// flags 仅接受 O_CLOEXEC（fd 记账）；O_NONBLOCK 无效果（Linux 子集）。
pub(super) fn sys_pipe2(proc: &mut GuestProcess, host: &dyn Host, pipefd: u64, flags: u64) -> i64 {
    if flags & !(abi::O_CLOEXEC | abi::O_NONBLOCK) != 0 {
        return -(abi::EINVAL as i64);
    }
    let (r, w) = match host.create_pipe() {
        Ok(x) => x,
        Err(e) => return -(host_err_to_errno(&e) as i64),
    };
    let rfd = proc.fds.alloc_fd(GuestFd::PipeRead(r));
    let wfd = proc.fds.alloc_fd(GuestFd::PipeWrite(w));
    if flags & abi::O_CLOEXEC != 0 {
        proc.fds.update_flags(rfd, |v| v | 1);
        proc.fds.update_flags(wfd, |v| v | 1);
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&(rfd as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(wfd as u32).to_le_bytes());
    match write_guest(proc, pipefd, &out) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

// ---------------------------------------------------------------- 目录遍历

/// getdents64(fd, dirp, count)：按 linux_dirent64 填充客户缓冲，填满即停。
/// 返回已填字节数；0 = 目录读完；count 不足以放一条 → EINVAL。
/// linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[] }
pub(super) fn sys_getdents64(
    proc: &mut GuestProcess,
    _host: &dyn Host,
    fd_raw: u64,
    buf: u64,
    count: u64,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    let dir = match proc.fds.get(fd) {
        None | Some(GuestFd::Reserved) => return -(abi::EBADF as i64),
        Some(GuestFd::HostDir(d)) => d,
        Some(_) => return -(abi::ENOTDIR as i64), // fd 存在但不是目录
    };
    let mut filled = 0usize;
    loop {
        let ent = match dir.peek() {
            Ok(Some(e)) => e,
            Ok(None) => break, // 目录读完
            Err(err) => return -(host_err_to_errno(&err) as i64),
        };
        let name = ent.name.as_bytes();
        if name.len() > 255 {
            dir.advance();
            continue; // 跳过超长名（Linux 文件名上限 255）
        }
        let reclen = (19 + name.len() + 1 + 7) & !7; // 头 19 字节 + NUL + 8 对齐
        if filled + reclen > count as usize {
            if filled == 0 {
                return -(abi::EINVAL as i64); // count 连一条都放不下
            }
            break; // 这条留给下次调用
        }
        // 栈缓冲复用（T1.4）：reclen 上限 19+255+1 对齐 = 280
        let mut rec = [0u8; 280];
        rec[0..8].copy_from_slice(&ent.ino.to_le_bytes());
        // d_off：目录 cookie。快照遍历下用递增序号（musl 只用其排序/停止判断）
        rec[8..16].copy_from_slice(&((filled as i64 + 1).to_le_bytes()));
        rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        rec[18] = if ent.is_dir { abi::DT_DIR } else { abi::DT_REG };
        rec[19..19 + name.len()].copy_from_slice(name);
        if let Err(e) = write_guest(proc, buf + filled as u64, &rec[..reclen]) {
            return -(e as i64);
        }
        dir.advance();
        filled += reclen;
    }
    filled as i64
}

// ---------------------------------------------------------------- fcntl / ioctl

/// fcntl 最小集：fd 标志（FD_CLOEXEC）与 status flags（O_APPEND/O_NONBLOCK 等）
/// 记账实现；O_NONBLOCK/O_APPEND 对当前同步 fd 语义无实际作用（记录即可）。
pub(super) fn sys_fcntl(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd_raw: u64,
    cmd: u64,
    arg: u64,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    if proc.fds.get(fd).is_none() {
        return -(abi::EBADF as i64);
    }
    match cmd {
        abi::F_GETFD => (proc.fds.get_flags(fd).unwrap_or(0) & 1) as i64,
        abi::F_SETFD => {
            proc.fds.update_flags(fd, |v| (v & !1) | (arg as u32 & 1));
            0
        }
        abi::F_GETFL => decode_status(proc.fds.get_flags(fd).unwrap_or(0)) as i64,
        abi::F_SETFL => {
            let mask = (abi::O_APPEND | abi::O_NONBLOCK | abi::O_RDWR | abi::O_WRONLY) as u32;
            let new_status = (arg as u32) & mask;
            proc.fds
                .update_flags(fd, |v| (v & !(0x1_FFFF << 8)) | (new_status << 8));
            0
        }
        abi::F_DUPFD | abi::F_DUPFD_CLOEXEC => {
            // 复制 fd；v0.3 从最小可用号分配（≥arg 语义极少依赖，注释见 SYSCALLS.md）
            dup_impl(proc, host, fd, None, cmd == abi::F_DUPFD_CLOEXEC)
        }
        _ => -(abi::EINVAL as i64),
    }
}

/// ioctl：仅 TIOCGWINSZ 提供固定 80x25 窗口尺寸（musl/busybox 探测用）；
/// 其余（含 TCGETS/TCSETS）返回 ENOTTY——诚实声明「不是终端」，musl isatty 据此走非 tty 路径。
pub(super) fn sys_ioctl(
    proc: &GuestProcess,
    _host: &dyn Host,
    fd_raw: u64,
    cmd: u64,
    arg: u64,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    if proc.fds.get(fd).is_none() {
        return -(abi::EBADF as i64);
    }
    if cmd == abi::TIOCGWINSZ {
        // struct winsize { ws_row, ws_col, ws_xpixel, ws_ypixel } = 4 × u16
        let ws: [u8; 8] = [25, 0, 80, 0, 0, 0, 0, 0]; // row=25, col=80, 像素位 0
        return match write_guest(proc, arg, &ws) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        };
    }
    -(abi::ENOTTY as i64)
}

// ---------------------------------------------------------------- 定位读写 / fsync

/// pread64/pwrite64：单线程模型下 seek→io→seek-back 等价于定位读写
/// （HostFile 单所有权，契约见 PLAN-0.0.3 T2.3）。
fn positioned(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd_raw: u64,
    buf: u64,
    len: u64,
    off: u64,
    is_write: bool,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    if !matches!(proc.fds.get(fd), Some(GuestFd::Host(_))) {
        return -(abi::ESPIPE as i64); // 非 Host fd（含目录/伪设备）不支持定位
    }
    // 段 1：保存当前游标
    let cur = match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => host.seek(f, 0, 1),
        _ => unreachable!(),
    };
    let cur = match cur {
        Ok(c) => c,
        Err(e) => return -(host_err_to_errno(&e) as i64),
    };
    // 段 2：定位
    if let Err(e) = match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => host.seek(f, off as i64, 0),
        _ => unreachable!(),
    } {
        return -(host_err_to_errno(&e) as i64);
    }
    // 段 3：IO
    let r = if is_write {
        match read_guest(proc, buf, len as usize) {
            Ok(data) => match proc.fds.get(fd) {
                Some(GuestFd::Host(f)) => host
                    .write(f, data)
                    .map(|n| n as i64)
                    .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
                _ => unreachable!(),
            },
            Err(e) => -(e as i64),
        }
    } else {
        match read_guest_mut(proc, buf, len as usize) {
            Ok(dst) => match proc.fds.get(fd) {
                Some(GuestFd::Host(f)) => host
                    .read(f, dst)
                    .map(|n| n as i64)
                    .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
                _ => unreachable!(),
            },
            Err(e) => -(e as i64),
        }
    };
    // 段 4：恢复游标（尽力而为）
    if let Some(GuestFd::Host(f)) = proc.fds.get(fd) {
        let _ = host.seek(f, cur as i64, 0);
    }
    r
}

pub(super) fn sys_pread64(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    buf: u64,
    len: u64,
    off: u64,
) -> i64 {
    positioned(proc, host, fd, buf, len, off, false)
}

pub(super) fn sys_pwrite64(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    buf: u64,
    len: u64,
    off: u64,
) -> i64 {
    positioned(proc, host, fd, buf, len, off, true)
}

pub(super) fn sys_fsync(proc: &GuestProcess, host: &dyn Host, fd_raw: u64, data_only: bool) -> i64 {
    let fd = fd_raw as u32 as i32;
    match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => host
            .sync_file(f, data_only)
            .map_or_else(|e| -(host_err_to_errno(&e) as i64), |_| 0),
        Some(GuestFd::HostDir(_)) | Some(GuestFd::Null) | Some(GuestFd::Zero) => 0, // 无持久化语义
        _ => -(abi::EBADF as i64),
    }
}

pub(super) fn sys_lseek(
    proc: &GuestProcess,
    host: &dyn Host,
    fd_raw: u64,
    off_raw: u64,
    whence_raw: u64,
) -> i64 {
    let fd = fd_raw as u32 as i32;
    match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => host
            .seek(f, off_raw as i64, whence_raw as u32 as i32)
            .map(|n| n as i64)
            .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
        _ => -(abi::ESPIPE as i64),
    }
}

// ---------------------------------------------------------------- 路径写操作

/// 路径解析（dirfd 支持，与 open_common 同一规则），返回宿主路径。
fn resolve_path(proc: &GuestProcess, dirfd: i32, path: &str) -> Result<std::path::PathBuf, i32> {
    if path.starts_with('/') {
        return proc.fs.translate(path).ok_or(abi::ENOENT);
    }
    if dirfd == abi::AT_FDCWD {
        return proc
            .fs
            .translate(&resolve_rel(proc, path))
            .ok_or(abi::ENOENT);
    }
    match proc.fds.get(dirfd) {
        Some(GuestFd::HostDir(d)) => {
            if path.split('/').any(|c| c == "..") {
                return Err(abi::EINVAL);
            }
            let mut p = d.host_path().to_path_buf();
            for c in path.split('/') {
                if !c.is_empty() && c != "." {
                    p.push(c);
                }
            }
            Ok(p)
        }
        _ => Err(abi::EBADF),
    }
}

pub(super) fn sys_mkdir(
    proc: &mut GuestProcess,
    host: &dyn Host,
    dirfd: i32,
    path_ptr: u64,
) -> i64 {
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    match resolve_path(proc, dirfd, &path) {
        Ok(hp) => host
            .mkdir(&HostPath(hp))
            .map_or_else(|e| -(host_err_to_errno(&e) as i64), |_| 0),
        Err(e) => -(e as i64),
    }
}

pub(super) fn sys_unlink_path(
    proc: &mut GuestProcess,
    host: &dyn Host,
    dirfd: i32,
    path_ptr: u64,
    dir: bool,
) -> i64 {
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    match resolve_path(proc, dirfd, &path) {
        Ok(hp) => host
            .remove(&HostPath(hp), dir)
            .map_or_else(|e| -(host_err_to_errno(&e) as i64), |_| 0),
        Err(e) => -(e as i64),
    }
}

pub(super) fn sys_rename(
    proc: &mut GuestProcess,
    host: &dyn Host,
    old_fd: i32,
    old_ptr: u64,
    new_fd: i32,
    new_ptr: u64,
) -> i64 {
    let old = match read_cstr(proc, old_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    let new = match read_cstr(proc, new_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    let r = (|| -> Result<HostPath, i32> {
        let _o = resolve_path(proc, old_fd, &old)?;
        let n = resolve_path(proc, new_fd, &new)?;
        Ok(HostPath(n))
    })()
    .and_then(|np| resolve_path(proc, old_fd, &old).map(|op| (op, np)));
    match r {
        Ok((op, HostPath(np))) => host
            .rename(&HostPath(op), &HostPath(np))
            .map_or_else(|e| -(host_err_to_errno(&e) as i64), |_| 0),
        Err(e) => -(e as i64),
    }
}

pub(super) fn sys_access(
    proc: &mut GuestProcess,
    host: &dyn Host,
    path_ptr: u64,
    mode: u64,
) -> i64 {
    access_common(proc, host, abi::AT_FDCWD, path_ptr, mode)
}

pub(super) fn sys_faccessat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    access_common(proc, host, a[0] as u32 as i32, a[1], a[2])
}

/// access 语义：存在性 + 按宿主只读位判 W_OK；X_OK 对目录成立、对文件按执行位推断
/// （Windows 权限位固定 0644/0755，故普通文件恒 X_OK——语义注释见 SYSCALLS.md）。
fn access_common(
    proc: &mut GuestProcess,
    host: &dyn Host,
    dirfd: i32,
    path_ptr: u64,
    mode: u64,
) -> i64 {
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    let hp = match resolve_path(proc, dirfd, &path) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    match host.stat_path(&HostPath(hp)) {
        Ok(st) => {
            if mode & abi::W_OK != 0 && st.is_readonly {
                return -(abi::EACCES as i64);
            }
            0
        }
        Err(e) => -(host_err_to_errno(&e) as i64),
    }
}

// ---------------------------------------------------------------- fd 复制

pub(super) fn sys_dup(proc: &mut GuestProcess, host: &dyn Host, oldfd_raw: u64) -> i64 {
    dup_impl(proc, host, oldfd_raw as u32 as i32, None, false)
}

/// dup2/dup3：目标 fd 已打开则先关闭；dup3 的 flags 仅接受 O_CLOEXEC。
pub(super) fn sys_dup2(
    proc: &mut GuestProcess,
    host: &dyn Host,
    oldfd_raw: u64,
    newfd_raw: u64,
    flags: u64,
    is_dup3: bool,
) -> i64 {
    let oldfd = oldfd_raw as u32 as i32;
    let newfd = newfd_raw as u32 as i32;
    if oldfd < 0 || newfd < 0 || proc.fds.get(oldfd).is_none() {
        return -(abi::EBADF as i64);
    }
    if is_dup3 && oldfd == newfd {
        return -(abi::EINVAL as i64);
    }
    if is_dup3 && flags & !abi::O_CLOEXEC != 0 {
        return -(abi::EINVAL as i64);
    }
    if oldfd == newfd {
        return newfd as i64; // dup2：等价 no-op
    }
    // 先移除目标（触发 host close）
    let _ = proc.fds.remove(newfd);
    dup_impl(
        proc,
        host,
        oldfd,
        Some(newfd),
        is_dup3 && flags & abi::O_CLOEXEC != 0,
    )
}

/// dup 核心：复制 Host 句柄或伪设备标记，分配（或落到指定）fd。
fn dup_impl(
    proc: &mut GuestProcess,
    host: &dyn Host,
    oldfd: i32,
    at: Option<i32>,
    cloexec: bool,
) -> i64 {
    let new_entry = match proc.fds.get(oldfd) {
        Some(GuestFd::Host(f)) | Some(GuestFd::PipeRead(f)) | Some(GuestFd::PipeWrite(f)) => {
            match host.dup_file(f) {
                Ok(nf) => match proc.fds.get(oldfd) {
                    // 管道端复制后保持端别（读端新句柄仍是读端）
                    Some(GuestFd::PipeRead(_)) => GuestFd::PipeRead(nf),
                    Some(GuestFd::PipeWrite(_)) => GuestFd::PipeWrite(nf),
                    _ => GuestFd::Host(nf),
                },
                Err(e) => return -(host_err_to_errno(&e) as i64),
            }
        }
        Some(GuestFd::Null) => GuestFd::Null,
        Some(GuestFd::Zero) => GuestFd::Zero,
        _ => return -(abi::EBADF as i64),
    };
    let fd = match at {
        Some(n) => {
            proc.fds.insert_at(n, new_entry);
            n
        }
        None => proc.fds.alloc_fd(new_entry),
    };
    if cloexec {
        proc.fds.update_flags(fd, |v| v | 1);
    }
    fd as i64
}

// ---------------------------------------------------------------- statx / 资源

/// statx(332)：写入完整 128 字节 struct statx（mask = STATX_BASIC_STATS）。
/// btime（创建时间）填 0——HostStat 无该字段时的诚实缺省。
pub(super) fn sys_statx(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let (dirfd, path_ptr, _buf, _flags, mask) = (a[0] as u32 as i32, a[1], a[2], a[3], a[4]);
    let _ = mask; // 全量填充，mask 请求子集由客户自行过滤
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    let r = if path.is_empty() {
        // AT_EMPTY_PATH：stat dirfd
        let fd = dirfd;
        return sys_fstat(proc, host, fd as u64, a[2]);
    } else {
        let hp = match resolve_path(proc, dirfd, &path) {
            Ok(p) => p,
            Err(e) => return -(e as i64),
        };
        host.stat_path(&HostPath(hp))
    };
    let hs = match r {
        Ok(hs) => hs,
        Err(e) => return -(host_err_to_errno(&e) as i64),
    };
    let mut b = [0u8; 128];
    b[0..4].copy_from_slice(&abi::STATX_BASIC_STATS.to_le_bytes());
    b[4..8].copy_from_slice(&4096u32.to_le_bytes());
    b[16..20].copy_from_slice(&(hs.nlink as u32).to_le_bytes());
    b[20..24].copy_from_slice(&proc.uid.to_le_bytes());
    b[24..28].copy_from_slice(&proc.gid.to_le_bytes());
    b[28..30].copy_from_slice(&(hs.mode as u16).to_le_bytes());
    b[32..40].copy_from_slice(&hs.ino.to_le_bytes());
    b[40..48].copy_from_slice(&(hs.size as u64).to_le_bytes());
    b[48..56].copy_from_slice(&(((hs.size + 511) / 512) as u64).to_le_bytes());
    b[56..64].copy_from_slice(&(abi::STATX_BASIC_STATS as u64).to_le_bytes());
    put_timespec16(&mut b[64..80], hs.atime_ns);
    put_timespec16(&mut b[80..96], hs.mtime_ns);
    put_timespec16(&mut b[96..112], hs.ctime_ns);
    match write_guest(proc, a[2], &b) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn put_timespec16(b: &mut [u8], ns: i64) {
    b[0..8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
    b[8..12].copy_from_slice(&((ns % 1_000_000_000) as u32).to_le_bytes());
}

/// getrusage：单线程记账缺失，诚实填零结构并返回 0（调用方校验 ru 字段的场景罕见）。
pub(super) fn sys_getrusage(proc: &mut GuestProcess, buf: u64) -> i64 {
    let who = 0u64;
    let _ = who;
    if buf == 0 {
        return -(abi::EINVAL as i64);
    }
    let zeros = [0u8; 144];
    match write_guest(proc, buf, &zeros) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// prlimit64：上报 RLIM_INFINITY（无资源限制语义），忽略 new 设置。
pub(super) fn sys_prlimit64(proc: &mut GuestProcess, old_buf: u64) -> i64 {
    if old_buf == 0 {
        return 0;
    }
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&abi::RLIM_INFINITY.to_le_bytes());
    b[8..16].copy_from_slice(&abi::RLIM_INFINITY.to_le_bytes());
    match write_guest(proc, old_buf, &b) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

// ---------------------------------------------------------------- utimensat

/// utimensat(280)（PLAN-0.1.0 T3.5）：设置 atime/mtime。
/// UTIME_NOW = (1<<30)-1，UTIME_OMIT = (1<<30)-2。flags ≠ 0（AT_SYMLINK
/// NOFOLLOW）与 pathname=NULL（dirfd 形态）诚实 ENOSYS；ctime 无 Windows
/// 对应，stat 回读值不变——均记录于 SYSCALLS 诚实边界。
pub(super) fn sys_utimensat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    const UTIME_NOW: i64 = (1 << 30) - 1;
    const UTIME_OMIT: i64 = (1 << 30) - 2;
    let (dirfd, path_ptr, times_ptr, flags) = (a[0] as u32 as i32, a[1], a[2], a[3]);
    if flags != 0 {
        return -(abi::ENOSYS as i64);
    }
    if dirfd != abi::AT_FDCWD {
        return -(abi::EBADF as i64); // 目录 fd 相对路径同 newfstatat 边界
    }
    let path = if path_ptr == 0 {
        return -(abi::ENOSYS as i64);
    } else {
        match read_cstr(proc, path_ptr) {
            Ok(p) => p,
            Err(e) => return -(e as i64),
        }
    };
    let Some(host_path) = proc.fs.translate(&resolve_rel(proc, &path)) else {
        return -(abi::ENOENT as i64);
    };
    // 解析 2×timespec（各 {i64 sec, i64 nsec}）
    let (now_s, now_n) = host.realtime();
    let now = (now_s, now_n as i64);
    let parse = |sec: i64, nsec: i64| -> Result<Option<(i64, i64)>, i32> {
        if !(0..1_000_000_000).contains(&nsec) {
            return Err(abi::EINVAL);
        }
        match sec {
            UTIME_NOW => Ok(Some(now)),
            UTIME_OMIT => Ok(None),
            _ => Ok(Some((sec, nsec))),
        }
    };
    let (atime, mtime) = if times_ptr == 0 {
        (Some(now), Some(now)) // times = NULL → 两者皆 UTIME_NOW
    } else {
        let buf = match read_guest(proc, times_ptr, 32) {
            Ok(b) => b,
            Err(e) => return -(e as i64),
        };
        let rd = |off: usize| i64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        match (parse(rd(0), rd(8)), parse(rd(16), rd(24))) {
            (Ok(a), Ok(m)) => (a, m),
            (Err(e), _) | (_, Err(e)) => return -(e as i64),
        }
    };
    match host.set_times(&HostPath(host_path), atime, mtime) {
        Ok(()) => 0,
        Err(e) => -(host_err_to_errno(&e) as i64),
    }
}

// HostFileKind 仅为 mock 测试保留引用，避免未使用告警的干净写法
#[allow(dead_code)]
fn _kind_is_disk(k: &HostFileKind) -> bool {
    matches!(k, HostFileKind::Disk { .. })
}
#[allow(dead_code)]
fn _file_is_host(f: &HostFile) -> bool {
    _kind_is_disk(&f.0)
}
