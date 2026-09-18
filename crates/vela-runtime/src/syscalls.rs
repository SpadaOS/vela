//! syscall dispatch：Linux 号 → 宿主语义（规格 5.4 白名单）。
//! 未实现的 syscall 一律返回 `-ENOSYS`（规格 0 成功标准 5）。

use vela_abi as abi;
use vela_sys::{Host, HostFile, HostFileKind, HostOpen, HostPath, HostProt};

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
        abi::SYS_MMAP => sys_mmap(proc, host, a),
        abi::SYS_MPROTECT => sys_mprotect(proc, host, a[0], a[1], a[2]),
        abi::SYS_MUNMAP => sys_munmap(proc, host, a[0], a[1]),
        abi::SYS_BRK => sys_brk(proc, a[0]),
        abi::SYS_EXIT | abi::SYS_EXIT_GROUP => sys_exit(host, a[0]),
        abi::SYS_UNAME => sys_uname(proc, a[0]),
        abi::SYS_ARCH_PRCTL => sys_arch_prctl(proc, host, a[0], a[1]),
        abi::SYS_GETRANDOM => sys_getrandom(proc, host, a[0], a[1]),
        abi::SYS_GETPID => proc.pid as i64,
        abi::SYS_SET_TID_ADDRESS => proc.pid as i64, // v0 单线程：返回假 pid 即可
        abi::SYS_SET_ROBUST_LIST => 0,               // musl 启动路径调用，忽略
        abi::SYS_CLOCK_GETTIME => sys_clock_gettime(proc, host, a[0], a[1]),
        abi::SYS_GETTIMEOFDAY => sys_gettimeofday(proc, host, a[0]),
        abi::SYS_IOCTL => -(abi::ENOTTY as i64), // 不是 tty
        abi::SYS_FCNTL => -(abi::ENOSYS as i64),
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
    open_common(proc, host, path_ptr, flags)
}

fn sys_openat(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let dirfd = a[0] as u32 as i32;
    if dirfd != abi::AT_FDCWD {
        return -(abi::EBADF as i64); // v0 仅支持 AT_FDCWD（规格 5.5）
    }
    open_common(proc, host, a[1], a[2])
}

fn open_common(proc: &mut GuestProcess, host: &dyn Host, path_ptr: u64, flags: u64) -> i64 {
    let path = match read_cstr(proc, path_ptr) {
        Ok(p) => p,
        Err(e) => return -(e as i64),
    };
    // 相对路径先拼 cwd，再走 vela-fs 翻译（路径在进入 Host 前已是宿主原生路径，规格 2.4）
    let linux_path = if path.starts_with('/') {
        path
    } else {
        format!("{}/{}", proc.cwd.trim_end_matches('/'), path)
    };
    let Some(host_path) = vela_fs::translate(&linux_path) else {
        return -(abi::ENOENT as i64);
    };
    let acc = flags & 0b11;
    let opt = HostOpen {
        read: acc == abi::O_RDONLY as u64 || acc == abi::O_RDWR as u64,
        write: acc != abi::O_RDONLY as u64,
        create: flags & abi::O_CREAT as u64 != 0,
        truncate: flags & abi::O_TRUNC as u64 != 0,
        append: flags & abi::O_APPEND as u64 != 0,
    };
    match host.open(&HostPath(host_path), opt) {
        Ok(f) => proc.fds.alloc_fd(GuestFd::Host(f)) as i64,
        Err(e) => -(host_err_to_errno(&e) as i64),
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
    matches!(k, HostFileKind::Disk(_))
}
#[allow(dead_code)]
fn _file_is_host(f: &HostFile) -> bool {
    _kind_is_disk(&f.0)
}
