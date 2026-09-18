//! syscall dispatch：Linux 号 → 宿主语义（规格 5.4 白名单）。
//! 未实现的 syscall 一律返回 `-ENOSYS`（规格 0 成功标准 5）。

use vela_abi as abi;
use vela_sys::{Host, HostError, HostFile, HostFileKind, HostOpen, HostPath, HostProt, HostStat};

use crate::{
    host_err_to_errno, read_cstr, read_guest, read_guest_mut, write_guest, GuestFd, GuestProcess,
};

const PAGE: u64 = 4096;

pub fn dispatch(proc: &mut GuestProcess, host: &dyn Host, nr: u64, a: [u64; 6]) -> i64 {
    match nr {
        abi::SYS_READ => sys_read(proc, host, a[0], a[1], a[2]),
        abi::SYS_WRITE => sys_write(proc, host, a[0], a[1], a[2]),
        abi::SYS_WRITEV => sys_writev(proc, host, a[0], a[1], a[2]),
        abi::SYS_OPEN => sys_open(proc, host, a[0], a[1]),
        abi::SYS_OPENAT => sys_openat(proc, host, a),
        abi::SYS_CLOSE => sys_close(proc, host, a[0]),
        abi::SYS_LSEEK => sys_lseek(proc, host, a[0], a[1], a[2]),
        abi::SYS_STAT | abi::SYS_LSTAT => sys_stat(proc, host, a[0], a[1]),
        abi::SYS_FSTAT => sys_fstat(proc, host, a[0], a[1]),
        abi::SYS_NEWFSTATAT => sys_newfstatat(proc, host, a),
        abi::SYS_MMAP => sys_mmap(proc, host, a),
        abi::SYS_MPROTECT => sys_mprotect(proc, host, a[0], a[1], a[2]),
        abi::SYS_MUNMAP => sys_munmap(proc, host, a[0], a[1]),
        abi::SYS_MSYNC => sys_msync(proc, a[0], a[1]),
        abi::SYS_BRK => sys_brk(proc, a[0]),
        abi::SYS_PIPE2 => sys_pipe2(proc, a[0], a[1]),
        abi::SYS_WAIT4 => sys_wait4(a[0], a[1], a[2]),
        abi::SYS_GETPPID => sys_getppid(proc),
        abi::SYS_EXIT | abi::SYS_EXIT_GROUP => sys_exit(host, a[0]),
        abi::SYS_UNAME => sys_uname(proc, a[0]),
        abi::SYS_ARCH_PRCTL => sys_arch_prctl(proc, host, a[0], a[1]),
        abi::SYS_GETRANDOM => sys_getrandom(proc, host, a[0], a[1]),
        abi::SYS_GETPID => proc.pid as i64,
        abi::SYS_GETUID | abi::SYS_GETEUID => proc.uid as i64,
        abi::SYS_GETGID | abi::SYS_GETEGID => proc.gid as i64,
        abi::SYS_GETCWD => sys_getcwd(proc, a[0], a[1]),
        abi::SYS_CHDIR => sys_chdir(proc, host, a[0]),
        abi::SYS_SET_TID_ADDRESS => proc.pid as i64, // v0 单线程：返回假 pid 即可
        abi::SYS_SET_ROBUST_LIST => 0,               // musl 启动路径调用，忽略
        abi::SYS_CLOCK_GETTIME => sys_clock_gettime(proc, host, a[0], a[1]),
        abi::SYS_GETTIMEOFDAY => sys_gettimeofday(proc, host, a[0]),
        abi::SYS_GETDENTS64 => sys_getdents64(proc, host, a[0], a[1], a[2]),
        abi::SYS_FCNTL => sys_fcntl(proc, host, a[0], a[1], a[2]),
        abi::SYS_IOCTL => sys_ioctl(proc, host, a[0], a[1], a[2]),
        abi::SYS_PREAD64 => sys_pread64(proc, host, a[0], a[1], a[2], a[3]),
        abi::SYS_PWRITE64 => sys_pwrite64(proc, host, a[0], a[1], a[2], a[3]),
        abi::SYS_ACCESS => sys_access(proc, host, a[0], a[1]),
        abi::SYS_FACCESSAT => sys_faccessat(proc, host, a),
        abi::SYS_DUP => sys_dup(proc, host, a[0]),
        abi::SYS_DUP2 | abi::SYS_DUP3 => {
            sys_dup2(proc, host, a[0], a[1], a[2], nr == abi::SYS_DUP3)
        }
        abi::SYS_FSYNC | abi::SYS_FDATASYNC => {
            sys_fsync(proc, host, a[0], nr == abi::SYS_FDATASYNC)
        }
        abi::SYS_MKDIR => sys_mkdir(proc, host, abi::AT_FDCWD, a[0]),
        abi::SYS_MKDIRAT => sys_mkdir(proc, host, a[0] as u32 as i32, a[1]),
        abi::SYS_RMDIR => sys_unlink_path(proc, host, abi::AT_FDCWD, a[0], true),
        abi::SYS_UNLINK => sys_unlink_path(proc, host, abi::AT_FDCWD, a[0], false),
        abi::SYS_UNLINKAT => sys_unlink_path(
            proc,
            host,
            a[0] as u32 as i32,
            a[1],
            a[2] & abi::AT_REMOVEDIR != 0,
        ),
        abi::SYS_RENAME => sys_rename(proc, host, abi::AT_FDCWD, a[0], abi::AT_FDCWD, a[1]),
        abi::SYS_RENAMEAT => sys_rename(
            proc,
            host,
            a[0] as u32 as i32,
            a[1],
            a[2] as u32 as i32,
            a[3],
        ),
        abi::SYS_STATX => sys_statx(proc, host, a),
        abi::SYS_GETRUSAGE => sys_getrusage(proc, a[1]),
        // 诚实 stub：信号投递未实现（NONGOALS），但 musl/busybox 启动路径
        // 必须成功——记录后返回 0（与 set_robust_list 同模式）
        abi::SYS_RT_SIGACTION | abi::SYS_RT_SIGPROCMASK | abi::SYS_MADVISE => 0,
        abi::SYS_PRLIMIT64 => sys_prlimit64(proc, a[3]),
        abi::SYS_SOCKET => -(abi::ENOSYS as i64), // NONGOALS：socket 体系
        _ => -(abi::ENOSYS as i64),
    }
}

// ---------------------------------------------------------------- 读写

fn sys_write(proc: &GuestProcess, host: &dyn Host, fd_raw: u64, buf: u64, len: u64) -> i64 {
    let fd = fd_raw as u32 as i32;
    match proc.fds.get(fd) {
        None => -(abi::EBADF as i64),
        Some(GuestFd::Null) | Some(GuestFd::Zero) => len as i64,
        Some(GuestFd::Reserved) => -(abi::EBADF as i64),
        Some(GuestFd::HostDir(_)) => -(abi::EBADF as i64), // 不能 write 目录
        Some(GuestFd::PipeWrite(p)) => {
            // 管道写（T3.2）：读端全关 → EPIPE；满 → -EAGAIN（无阻塞调度）
            if !p.read_open.get() {
                return -(abi::EPIPE as i64);
            }
            let mut b = p.buf.borrow_mut();
            let room = p.capacity.saturating_sub(b.len());
            if room == 0 {
                return -(abi::EAGAIN as i64);
            }
            let data = match read_guest(proc, buf, (len as usize).min(room)) {
                Ok(d) => d,
                Err(e) => return -(e as i64),
            };
            let n = data.len();
            b.extend_from_slice(data);
            n as i64
        }
        Some(GuestFd::PipeRead(_)) => -(abi::EBADF as i64), // 读端不可写
        Some(GuestFd::Host(f)) => {
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

fn sys_read(proc: &mut GuestProcess, host: &dyn Host, fd_raw: u64, buf: u64, len: u64) -> i64 {
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
        Some(GuestFd::PipeRead(p)) => {
            // 管道读（T3.2）：空且写端开 → -EAGAIN（v0 无阻塞调度）；
            // 空且写端关 → 0（EOF）
            let mut b = p.buf.borrow_mut();
            if b.is_empty() {
                return if p.write_open.get() {
                    -(abi::EAGAIN as i64)
                } else {
                    0
                };
            }
            let n = (len as usize).min(b.len());
            let data: Vec<u8> = b.drain(..n).collect();
            match write_guest(proc, buf, data.as_slice()) {
                Ok(()) => n as i64,
                Err(e) => -(e as i64),
            }
        }
        Some(GuestFd::PipeWrite(_)) => -(abi::EBADF as i64), // 写端不可读
        Some(GuestFd::Host(f)) => match read_guest_mut(proc, buf, len as usize) {
            Ok(dst) => host
                .read(f, dst)
                .map(|n| n as i64)
                .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
            Err(e) => -(e as i64),
        },
    }
}

fn write_zeros(proc: &GuestProcess, addr: u64, len: usize) -> Result<(), i32> {
    write_guest(proc, addr, &vec![0u8; len])
}

fn sys_writev(proc: &GuestProcess, host: &dyn Host, fd_raw: u64, iov: u64, iovcnt_raw: u64) -> i64 {
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
        Some(GuestFd::PipeWrite(p)) => {
            // 管道 writev：逐 iov 追加，尊重容量（部分写）
            if !p.read_open.get() {
                return -(abi::EPIPE as i64);
            }
            let mut b = p.buf.borrow_mut();
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
                let room = p.capacity.saturating_sub(b.len());
                if room == 0 {
                    break;
                }
                let data = match read_guest(proc, base, (len as usize).min(room)) {
                    Ok(d) => d,
                    Err(e) => return -(e as i64),
                };
                b.extend_from_slice(data);
                total += data.len() as i64;
            }
            if total == 0 && b.len() == p.capacity {
                return -(abi::EAGAIN as i64);
            }
            total
        }
        Some(GuestFd::PipeRead(_)) => -(abi::EBADF as i64),
        Some(GuestFd::Host(f)) => {
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

fn sys_open(proc: &mut GuestProcess, host: &dyn Host, path_ptr: u64, flags: u64) -> i64 {
    open_common(proc, host, abi::AT_FDCWD, path_ptr, flags)
}

fn sys_openat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
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
fn sys_getcwd(proc: &GuestProcess, buf: u64, size: u64) -> i64 {
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
fn sys_chdir(proc: &mut GuestProcess, host: &dyn Host, path_ptr: u64) -> i64 {
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

fn sys_stat(proc: &mut GuestProcess, host: &dyn Host, path_ptr: u64, statbuf: u64) -> i64 {
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

fn sys_fstat(proc: &GuestProcess, host: &dyn Host, fd_raw: u64, statbuf: u64) -> i64 {
    let fd = fd_raw as u32 as i32;
    let r = match proc.fds.get(fd) {
        None | Some(GuestFd::Reserved) => return -(abi::EBADF as i64),
        Some(GuestFd::Null) | Some(GuestFd::Zero) => Ok(HostStat::char_device()),
        Some(GuestFd::Host(f)) => host.stat_file(f),
        Some(GuestFd::HostDir(d)) => host.stat_path(&HostPath(d.host_path().to_path_buf())),
        Some(GuestFd::PipeRead(_) | GuestFd::PipeWrite(_)) => {
            // FIFO 元数据（T3.2）：S_IFIFO | 0666，size 恒 0
            Ok(HostStat {
                size: 0,
                is_dir: false,
                is_readonly: false,
                mtime_ns: 0,
                mode: abi::S_IFIFO | 0o666,
                nlink: 1,
                ino: 2,
                dev: 1,
                atime_ns: 0,
                ctime_ns: 0,
            })
        }
    };
    fill_stat(proc, r, statbuf)
}

fn sys_newfstatat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
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

fn sys_close(proc: &mut GuestProcess, host: &dyn Host, fd_raw: u64) -> i64 {
    let fd = fd_raw as u32 as i32;
    match proc.fds.remove(fd) {
        None => -(abi::EBADF as i64),
        Some(GuestFd::Host(f)) => match host.close(f) {
            Ok(()) => 0,
            Err(e) => -(host_err_to_errno(&e) as i64),
        },
        Some(GuestFd::PipeRead(p)) => {
            p.read_open.set(false);
            0
        }
        Some(GuestFd::PipeWrite(p)) => {
            p.write_open.set(false);
            0
        }
        Some(_) => 0,
    }
}

// ---------------------------------------------------------------- 管道 / 进程族

/// pipe2(293)（PLAN-0.0.4 T3.2）：进程内环形缓冲 fd 对（容量 64 KiB）。
/// flags 仅接受 O_CLOEXEC（fd 记账）；非阻塞语义见 sys_read/sys_write。
fn sys_pipe2(proc: &mut GuestProcess, pipefd: u64, flags: u64) -> i64 {
    if flags & !(abi::O_CLOEXEC | abi::O_NONBLOCK) != 0 {
        return -(abi::EINVAL as i64);
    }
    let p = std::rc::Rc::new(crate::Pipe {
        capacity: crate::PIPE_CAPACITY,
        read_open: std::cell::Cell::new(true),
        write_open: std::cell::Cell::new(true),
        ..Default::default()
    });
    let rfd = proc.fds.alloc_fd(GuestFd::PipeRead(std::rc::Rc::clone(&p)));
    let wfd = proc.fds.alloc_fd(GuestFd::PipeWrite(p));
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

/// wait4(61)（T3.3）：vela 为单进程模型（无 fork），无子进程可等——
/// 诚实返回 -ECHILD（与 Linux 无子进程时 wait4 的语义一致）。
fn sys_wait4(_pid: u64, _status: u64, _opts: u64) -> i64 {
    -(abi::ECHILD as i64)
}

/// getppid(110)（T3.3）：返回宿主进程 id 与客户 pid 的组合哈希，保证
/// 同一 vela 进程内稳定且非 0（真实父进程不存在——诚实近似）。
fn sys_getppid(proc: &GuestProcess) -> i64 {
    (std::process::id() ^ proc.pid.wrapping_mul(0x9E37_79B9)) as i64
}

// ---------------------------------------------------------------- 目录遍历

/// getdents64(fd, dirp, count)：按 linux_dirent64 填充客户缓冲，填满即停。
/// 返回已填字节数；0 = 目录读完；count 不足以放一条 → EINVAL。
/// linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[] }
fn sys_getdents64(
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
fn sys_fcntl(proc: &mut GuestProcess, host: &dyn Host, fd_raw: u64, cmd: u64, arg: u64) -> i64 {
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
fn sys_ioctl(proc: &GuestProcess, _host: &dyn Host, fd_raw: u64, cmd: u64, arg: u64) -> i64 {
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

fn sys_pread64(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    buf: u64,
    len: u64,
    off: u64,
) -> i64 {
    positioned(proc, host, fd, buf, len, off, false)
}

fn sys_pwrite64(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    buf: u64,
    len: u64,
    off: u64,
) -> i64 {
    positioned(proc, host, fd, buf, len, off, true)
}

fn sys_fsync(proc: &GuestProcess, host: &dyn Host, fd_raw: u64, data_only: bool) -> i64 {
    let fd = fd_raw as u32 as i32;
    match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => host
            .sync_file(f, data_only)
            .map_or_else(|e| -(host_err_to_errno(&e) as i64), |_| 0),
        Some(GuestFd::HostDir(_)) | Some(GuestFd::Null) | Some(GuestFd::Zero) => 0, // 无持久化语义
        _ => -(abi::EBADF as i64),
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

fn sys_mkdir(proc: &mut GuestProcess, host: &dyn Host, dirfd: i32, path_ptr: u64) -> i64 {
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

fn sys_unlink_path(
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

fn sys_rename(
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

fn sys_access(proc: &mut GuestProcess, host: &dyn Host, path_ptr: u64, mode: u64) -> i64 {
    access_common(proc, host, abi::AT_FDCWD, path_ptr, mode)
}

fn sys_faccessat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
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

fn sys_dup(proc: &mut GuestProcess, host: &dyn Host, oldfd_raw: u64) -> i64 {
    dup_impl(proc, host, oldfd_raw as u32 as i32, None, false)
}

/// dup2/dup3：目标 fd 已打开则先关闭；dup3 的 flags 仅接受 O_CLOEXEC。
fn sys_dup2(
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
        Some(GuestFd::Host(f)) => match host.dup_file(f) {
            Ok(nf) => GuestFd::Host(nf),
            Err(e) => return -(host_err_to_errno(&e) as i64),
        },
        // 管道端复制共享同一缓冲（引用计数）
        Some(GuestFd::PipeRead(p)) => GuestFd::PipeRead(std::rc::Rc::clone(p)),
        Some(GuestFd::PipeWrite(p)) => GuestFd::PipeWrite(std::rc::Rc::clone(p)),
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
fn sys_statx(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
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
fn sys_getrusage(proc: &mut GuestProcess, buf: u64) -> i64 {
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
fn sys_prlimit64(proc: &mut GuestProcess, old_buf: u64) -> i64 {
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

fn sys_lseek(
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

// ---------------------------------------------------------------- 内存

fn sys_mmap(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let (addr, len, linux_prot, flags) = (a[0], a[1], a[2], a[3]);
    if len == 0 {
        return -(abi::EINVAL as i64);
    }
    let private = flags & abi::MAP_PRIVATE as u64 != 0;
    let shared = flags & abi::MAP_SHARED as u64 != 0;
    if !private && !shared {
        return -(abi::EINVAL as i64);
    }
    let anon = flags & abi::MAP_ANONYMOUS as u64 != 0;
    if shared {
        // MAP_SHARED（含共享匿名）延后：文件映射体系当前只做 MAP_PRIVATE
        //（PLAN-0.0.4 T1.2，记录于 SYSCALLS.md）
        return -(abi::ENOSYS as i64);
    }
    if !anon {
        return sys_mmap_file(proc, host, a);
    }
    let len_up = (len + PAGE - 1) & !(PAGE - 1);
    let fixed = flags & abi::MAP_FIXED as u64 != 0 && addr != 0;
    if fixed && proc.mem.overlaps(addr, len_up) {
        // Linux 语义：MAP_FIXED 替换既有映射。vela 无法部分释放 Windows 预留块；
        // 但 musl mallocng 依赖"把 brk 新增页用 MAP_FIXED 匿名映射转为可 munmap
        // 映射"（donate）。整个区间落在单个 Reserve 块内时就地接受并收敛保护位
        // （内容语义差异：Linux 替换为匿名零页，vela 保留原页——musl 只对未写入
        // 的 brk 尾页这样做，可接受并记录于 SYSCALLS.md）。
        if proc.mem.contains(addr, len_up)
            && proc.mem.containing(addr, len_up).map(|r| r.kind)
                == Some(crate::mem::MemKind::Reserve)
        {
            let prot = HostProt::from_bits(linux_prot as u32);
            let _ = unsafe { host.protect(addr as usize, len_up as usize, prot) };
            return addr as i64;
        }
        return -(abi::ENOMEM as i64);
    }
    let hint = if fixed { addr as usize } else { 0 };
    // 先 RW 提交（host.map 契约），再收敛到请求保护位
    let got = match unsafe {
        host.map(
            hint,
            len_up as usize,
            HostProt::READ | HostProt::WRITE,
            true,
        )
    } {
        Ok(p) => p as u64,
        Err(e) => return -(host_err_to_errno(&e) as i64),
    };
    if fixed && got != addr {
        let _ = unsafe { host.unmap(got as usize, len_up as usize) };
        return -(abi::ENOMEM as i64);
    }
    let prot = HostProt::from_bits(linux_prot as u32);
    if prot.bits() != (HostProt::READ | HostProt::WRITE).bits() {
        let _ = unsafe { host.protect(got as usize, len_up as usize, prot) };
    }
    proc.mem.add(crate::mem::MemRange::reserve(got, len_up));
    got as i64
}

/// 文件映射视图的对齐约束（Windows 分配粒度，见 windows::ALLOC_GRANULARITY）。
/// offset/hint 对齐时走真文件视图（demand paging + COW）；否则退化为
/// 匿名映射 + 读入内容（语义等价，仅无缺页加速）。
const MAP_VIEW_GRAN: u64 = 0x1_0000;

/// MAP_PRIVATE + fd 的文件映射（PLAN-0.0.4 T1.2）。
/// 优先真文件视图；MAP_FIXED 落在已登记预留区内时（ld-musl 先 PROT_NONE
/// 预留、再逐段 MAP_FIXED 覆盖的装载模式）直接把文件内容读入既有页——
/// Windows 预留块无法部分释放，读入副本与 Linux 的覆盖映射语义一致。
fn sys_mmap_file(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let (addr, len, linux_prot, flags, fd_raw, offset) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    let fd = fd_raw as u32 as i32;
    let f = match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => f,
        // Linux 对 /dev/null、目录、管道等不可映射对象返回 ENODEV
        Some(GuestFd::HostDir(_))
        | Some(GuestFd::Null)
        | Some(GuestFd::Zero)
        | Some(GuestFd::PipeRead(_))
        | Some(GuestFd::PipeWrite(_)) => return -(abi::ENODEV as i64),
        None | Some(GuestFd::Reserved) => return -(abi::EBADF as i64),
    };
    let len_up = (len + PAGE - 1) & !(PAGE - 1);
    let fixed = flags & abi::MAP_FIXED as u64 != 0 && addr != 0;
    let prot = HostProt::from_bits(linux_prot as u32);

    let carve = fixed && proc.mem.contains(addr, len_up);
    if carve
        && proc.mem.containing(addr, len_up).map(|r| r.kind) == Some(crate::mem::MemKind::FileView)
    {
        // 覆盖文件视图区间无法重建（视图不可部分重映射），诚实拒绝
        return -(abi::ENOMEM as i64);
    }
    if fixed && !carve && proc.mem.overlaps(addr, len_up) {
        return -(abi::ENOMEM as i64);
    }

    // 真文件视图：offset 与（固定时）hint 都必须对齐分配粒度
    if !carve {
        let can_view =
            offset.is_multiple_of(MAP_VIEW_GRAN) && (!fixed || addr.is_multiple_of(MAP_VIEW_GRAN));
        if can_view {
            let hint = if fixed { addr as usize } else { 0 };
            match unsafe { host.map_file(f, offset, len_up as usize, hint, prot) } {
                Ok(base) if !fixed || base == addr as usize => {
                    proc.mem
                        .add(crate::mem::MemRange::view(base as u64, len_up));
                    return base as i64;
                }
                Ok(base) => {
                    // 宿主自选了别的基址：违背 MAP_FIXED，回滚走读入回退
                    let _ = unsafe { host.unmap_view(base) };
                }
                Err(_) => {}
            }
        }
    }

    // 阶段 1：文件内容读入本地缓冲（此后不再持有 fd 借用）。EOF 之后保持
    // 零填充（mmap 对文件尾之外的页保证读到 0）。
    let mut data = vec![0u8; len_up as usize];
    if let Err(e) = read_file_at(host, f, offset, &mut data) {
        return -(host_err_to_errno(&e) as i64);
    }

    // 阶段 2：进程状态变更
    if carve {
        // 预留区可能处于 PROT_NONE：先放开为 RW，写入后收敛到请求保护位
        let _ = unsafe {
            host.protect(
                addr as usize,
                len_up as usize,
                HostProt::READ | HostProt::WRITE,
            )
        };
        if let Err(e) = write_guest(proc, addr, &data) {
            return -(e as i64);
        }
        if prot.bits() != (HostProt::READ | HostProt::WRITE).bits() {
            let _ = unsafe { host.protect(addr as usize, len_up as usize, prot) };
        }
        return addr as i64;
    }
    let hint = if fixed { addr as usize } else { 0 };
    let got = match unsafe {
        host.map(
            hint,
            len_up as usize,
            HostProt::READ | HostProt::WRITE,
            true,
        )
    } {
        Ok(p) => p as u64,
        Err(e) => return -(host_err_to_errno(&e) as i64),
    };
    if fixed && got != addr {
        let _ = unsafe { host.unmap(got as usize, len_up as usize) };
        return -(abi::ENOMEM as i64);
    }
    proc.mem.add(crate::mem::MemRange::reserve(got, len_up));
    if let Err(e) = write_guest(proc, got, &data) {
        return -(e as i64);
    }
    if prot.bits() != (HostProt::READ | HostProt::WRITE).bits() {
        let _ = unsafe { host.protect(got as usize, len_up as usize, prot) };
    }
    got as i64
}

/// 把 fd 在 offset 处的内容读满 buf；EOF 尾部保持 buf 既有值（零填充）。
/// 读取前后保存/恢复该 fd 的游标（v0 单线程客户，短暂移动安全）。
fn read_file_at(
    host: &dyn Host,
    f: &HostFile,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), HostError> {
    let cur = host.seek(f, 0, 1)?;
    let mut filled = 0usize;
    let result = host.seek(f, offset as i64, 0).and_then(|_| {
        while filled < buf.len() {
            match host.read(f, &mut buf[filled..]) {
                Ok(0) => break, // EOF
                Ok(n) => filled += n,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });
    let _ = host.seek(f, cur as i64, 0);
    result
}

fn sys_mprotect(
    proc: &mut GuestProcess,
    host: &dyn Host,
    addr: u64,
    len: u64,
    linux_prot: u64,
) -> i64 {
    if len == 0 {
        return 0;
    }
    // 文件视图上 VirtualProtect(RW) 会关闭 COW、把写入穿透到宿主文件——
    // MAP_PRIVATE 必须写私有，故对视图区间剥离 WRITE 位（W-only 变 no-op）。
    let view =
        proc.mem.containing(addr, len).map(|r| r.kind) == Some(crate::mem::MemKind::FileView);
    let prot = if view {
        HostProt::from_bits(linux_prot as u32 & !HostProt::WRITE.bits())
    } else {
        HostProt::from_bits(linux_prot as u32)
    };
    if !proc.mem.contains(addr, len) {
        return -(abi::ENOMEM as i64);
    }
    if view && prot.bits() == 0 {
        return 0;
    }
    match unsafe { host.protect(addr as usize, len as usize, prot) } {
        Ok(()) => 0,
        Err(e) => -(host_err_to_errno(&e) as i64),
    }
}

fn sys_munmap(proc: &mut GuestProcess, host: &dyn Host, addr_raw: u64, len_raw: u64) -> i64 {
    let addr = addr_raw & !(PAGE - 1);
    let len = (len_raw + PAGE - 1) & !(PAGE - 1);
    if len == 0 {
        return 0;
    }
    // v0：只移除完全被覆盖的登记项，释放 best-effort（规格 5.4）；
    // 登记项类型决定释放原语：文件视图走 UnmapViewOfFile（PLAN-0.0.4 T1.3）
    let removed = proc.mem.remove_fully_covered(addr, len);
    for r in &removed {
        let _ = match r.kind {
            crate::mem::MemKind::FileView => unsafe { host.unmap_view(r.start as usize) },
            crate::mem::MemKind::Reserve => unsafe { host.unmap(r.start as usize, r.len as usize) },
        };
    }
    0
}

/// msync(26)：vela 文件映射只有 MAP_PRIVATE（无回写语义），flush 恒为 no-op；
/// 仅做参数/区间校验，保持 Linux 错误语义。
fn sys_msync(proc: &GuestProcess, addr_raw: u64, len: u64) -> i64 {
    if !addr_raw.is_multiple_of(PAGE) || len == 0 {
        return -(abi::EINVAL as i64);
    }
    if !proc.mem.contains(addr_raw, len) {
        return -(abi::ENOMEM as i64);
    }
    0
}

fn sys_brk(proc: &mut GuestProcess, req: u64) -> i64 {
    // 堆为加载后预留的连续匿名块，brk 仅在块内移动断点（规格 5.4）
    let Some(heap) = proc.heap else {
        return -(abi::ENOMEM as i64);
    };
    if req == 0 || req < heap.start || req > heap.start + heap.len {
        // brk(0) 查询 / 越界：返回当前断点
        return proc.brk as i64;
    }
    proc.brk = req;
    proc.brk as i64
}

// ---------------------------------------------------------------- 进程/杂项

fn sys_exit(host: &dyn Host, code: u64) -> i64 {
    // 退出前冲刷 stdio，避免宿主侧缓冲丢失（规格 4：exit 直接结束进程）
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    host.process_exit((code & 0xff) as i32);
}

fn sys_uname(proc: &GuestProcess, buf: u64) -> i64 {
    // 规格 5.4：Linux / vela / 6.6.0-vela / x86_64
    let mut out = [0u8; 390];
    out[0..65].copy_from_slice(&fill65("Linux"));
    out[65..130].copy_from_slice(&fill65("vela"));
    out[130..195].copy_from_slice(&fill65("6.6.0-vela"));
    out[195..260].copy_from_slice(&fill65("#1 SMP vela"));
    out[260..325].copy_from_slice(&fill65("x86_64"));
    out[325..390].copy_from_slice(&fill65("(none)"));
    match write_guest(proc, buf, &out) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn fill65(s: &str) -> [u8; 65] {
    let mut b = [0u8; 65];
    let n = s.len().min(64);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

fn sys_arch_prctl(proc: &mut GuestProcess, host: &dyn Host, code: u64, addr: u64) -> i64 {
    match code {
        abi::ARCH_SET_FS => {
            // 记录新基址；宿主支持时标记待应用，由 CLI 在异常返回后的
            // 用户态 trampoline 实际切换（wrfsbase 在 VEH 处理器内会被
            // NtContinue 还原）。两种情况都返回 0（规格 5.1 允许）。
            proc.fs_base = addr;
            if host.set_fs_base(addr).is_ok() {
                proc.fs_apply_pending = Some(addr);
            }
            0
        }
        abi::ARCH_SET_GS => {
            proc.gs_base = addr;
            0
        }
        abi::ARCH_GET_FS => match write_guest_u64(proc, addr, proc.fs_base) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        },
        abi::ARCH_GET_GS => match write_guest_u64(proc, addr, proc.gs_base) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        },
        _ => -(abi::EINVAL as i64),
    }
}

fn write_guest_u64(proc: &GuestProcess, addr: u64, v: u64) -> Result<(), i32> {
    write_guest(proc, addr, &v.to_le_bytes())
}

fn sys_getrandom(proc: &mut GuestProcess, host: &dyn Host, buf: u64, len: u64) -> i64 {
    if len == 0 {
        return 0;
    }
    if len > (1 << 26) {
        return -(abi::EINVAL as i64); // v0 上限 64MiB 防呆
    }
    match read_guest_mut(proc, buf, len as usize) {
        Ok(dst) => host
            .random(dst)
            .map(|_| len as i64)
            .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
        Err(e) => -(e as i64),
    }
}

fn sys_clock_gettime(proc: &GuestProcess, host: &dyn Host, clk: u64, tp: u64) -> i64 {
    let (secs, nsecs) = match clk {
        abi::CLOCK_REALTIME => {
            let (s, ns) = host.realtime();
            (s as u64, ns as u64)
        }
        // MONOTONIC_RAW/BOOTTIME 语义子集：统一映射宿主单调时钟（PLAN T2.7）
        abi::CLOCK_MONOTONIC | abi::CLOCK_MONOTONIC_RAW | abi::CLOCK_BOOTTIME => {
            let n = host.monotonic_ns();
            (n / 1_000_000_000, n % 1_000_000_000)
        }
        _ => return -(abi::EINVAL as i64),
    };
    if tp == 0 {
        return 0;
    }
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&secs.to_le_bytes());
    out[8..16].copy_from_slice(&nsecs.to_le_bytes());
    match write_guest(proc, tp, &out) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn sys_gettimeofday(proc: &GuestProcess, host: &dyn Host, tv: u64) -> i64 {
    if tv == 0 {
        return 0;
    }
    let (s, ns) = host.realtime();
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&s.to_le_bytes());
    out[8..16].copy_from_slice(&((ns / 1000) as u64).to_le_bytes());
    match write_guest(proc, tv, &out) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
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
