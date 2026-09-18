//! syscall dispatch：Linux 号 → 宿主语义（规格 5.4 白名单）。
//! 未实现的 syscall 一律返回 `-ENOSYS`（规格 0 成功标准 5）。

use vela_abi as abi;
use vela_sys::{Host, HostDir, HostError, HostFile, HostFileKind, HostOpen, HostPath, HostProt, HostStat};

use crate::{read_cstr, read_guest, read_guest_mut, write_guest, GuestFd, GuestProcess, host_err_to_errno};

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
        abi::SYS_BRK => sys_brk(proc, a[0]),
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
        abi::SYS_FCNTL => sys_fcntl(proc, a[0], a[1], a[2]),
        abi::SYS_IOCTL => sys_ioctl(proc, host, a[0], a[1], a[2]),
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
        Some(GuestFd::Host(f)) => {
            if len == 0 {
                return 0;
            }
            match read_guest(proc, buf, len as usize) {
                Ok(data) => host.write(f, data).map(|n| n as i64).unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
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
        Some(GuestFd::Host(f)) => match read_guest_mut(proc, buf, len as usize) {
            Ok(dst) => host.read(f, dst).map(|n| n as i64).unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
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
    if iovcnt < 0 || iovcnt > 1024 {
        return -(abi::EINVAL as i64);
    }
    if iovcnt == 0 {
        return 0;
    }
    match proc.fds.get(fd) {
        None | Some(GuestFd::Reserved) => return -(abi::EBADF as i64),
        Some(GuestFd::HostDir(_)) => return -(abi::EBADF as i64),
        Some(GuestFd::Null) | Some(GuestFd::Zero) => {
            // /dev/null 语义：校验可读后返回总长
            let mut total = 0i64;
            for i in 0..iovcnt as u64 {
                match read_guest(proc, iov + i * 16, 16) {
                    Ok(ent) => total += rd_u64(ent, 8) as i64,
                    Err(e) => return -(e as i64),
                }
            }
            return total;
        }
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
fn open_common(proc: &mut GuestProcess, host: &dyn Host, dirfd: i32, path_ptr: u64, flags: u64) -> i64 {
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
        read: acc == abi::O_RDONLY as u64 || acc == abi::O_RDWR as u64,
        write: acc != abi::O_RDONLY as u64,
        create: flags & abi::O_CREAT as u64 != 0,
        excl: flags & abi::O_EXCL as u64 != 0,
        truncate: flags & abi::O_TRUNC as u64 != 0,
        append: flags & abi::O_APPEND as u64 != 0,
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
    let comps: Vec<&str> = joined.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    proc.cwd = if comps.is_empty() { "/".to_string() } else { format!("/{}", comps.join("/")) };
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
            let bytes =
                unsafe { std::slice::from_raw_parts((&st as *const abi::Stat) as *const u8, std::mem::size_of::<abi::Stat>()) };
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
        Some(_) => 0,
    }
}

// ---------------------------------------------------------------- 目录遍历

/// getdents64(fd, dirp, count)：按 linux_dirent64 填充客户缓冲，填满即停。
/// 返回已填字节数；0 = 目录读完；count 不足以放一条 → EINVAL。
/// linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[] }
fn sys_getdents64(proc: &mut GuestProcess, host: &dyn Host, fd_raw: u64, buf: u64, count: u64) -> i64 {
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
        let mut rec = vec![0u8; reclen];
        rec[0..8].copy_from_slice(&ent.ino.to_le_bytes());
        // d_off：目录 cookie。快照遍历下用递增序号（musl 只用其排序/停止判断）
        rec[8..16].copy_from_slice(&((filled as i64 + 1).to_le_bytes()));
        rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
        rec[18] = if ent.is_dir { abi::DT_DIR } else { abi::DT_REG };
        rec[19..19 + name.len()].copy_from_slice(name);
        if let Err(e) = write_guest(proc, buf + filled as u64, &rec) {
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
fn sys_fcntl(proc: &mut GuestProcess, fd_raw: u64, cmd: u64, arg: u64) -> i64 {
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
            proc.fds.update_flags(fd, |v| (v & !(0x1_FFFF << 8)) | (new_status << 8));
            0
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

fn sys_lseek(proc: &GuestProcess, host: &dyn Host, fd_raw: u64, off_raw: u64, whence_raw: u64) -> i64 {
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
    // v0 仅支持匿名私有映射，fd 忽略（规格 5.4）
    if flags & abi::MAP_ANONYMOUS as u64 == 0 || flags & abi::MAP_PRIVATE as u64 == 0 {
        return -(abi::ENOSYS as i64);
    }
    let len_up = (len + PAGE - 1) & !(PAGE - 1);
    let fixed = flags & abi::MAP_FIXED as u64 != 0 && addr != 0;
    if fixed && proc.mem.overlaps(addr, len_up) {
        return -(abi::ENOMEM as i64);
    }
    let hint = if fixed { addr as usize } else { 0 };
    // 先 RW 提交（host.map 契约），再收敛到请求保护位
    let got = match unsafe { host.map(hint, len_up as usize, HostProt::READ | HostProt::WRITE, true) } {
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
    proc.mem.add(crate::mem::MemRange { start: got, len: len_up });
    got as i64
}

fn sys_mprotect(proc: &mut GuestProcess, host: &dyn Host, addr: u64, len: u64, linux_prot: u64) -> i64 {
    if len == 0 {
        return 0;
    }
    if !proc.mem.contains(addr, len) {
        return -(abi::ENOMEM as i64);
    }
    match unsafe { host.protect(addr as usize, len as usize, HostProt::from_bits(linux_prot as u32)) } {
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
    // v0：只移除完全被覆盖的登记项，释放 best-effort（规格 5.4）
    let removed = proc.mem.remove_fully_covered(addr, len);
    for r in &removed {
        let _ = unsafe { host.unmap(r.start as usize, r.len as usize) };
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
        abi::CLOCK_MONOTONIC => {
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
