//! syscall dispatch：Linux 号 → 宿主语义（规格 5.4 白名单）。
//! 未实现的 syscall 一律返回 `-ENOSYS`（规格 0 成功标准 5）。
//!
//! 子模块按子系统拆分（PLAN-0.1.0 T5.1）：`file` 文件/IO/资源、`mem` 内存、
//! `time` 时钟、`proc` 进程/杂项；本文件仅保留 dispatch 总分发。

use vela_abi as abi;
use vela_sys::Host;

use crate::GuestProcess;

mod file;
mod mem;
mod proc;
mod time;

pub fn dispatch(proc: &mut GuestProcess, host: &dyn Host, nr: u64, a: [u64; 6]) -> i64 {
    match nr {
        abi::SYS_READ => file::sys_read(proc, host, a[0], a[1], a[2]),
        abi::SYS_WRITE => file::sys_write(proc, host, a[0], a[1], a[2]),
        abi::SYS_WRITEV => file::sys_writev(proc, host, a[0], a[1], a[2]),
        abi::SYS_OPEN => file::sys_open(proc, host, a[0], a[1]),
        abi::SYS_OPENAT => file::sys_openat(proc, host, a),
        abi::SYS_CLOSE => file::sys_close(proc, host, a[0]),
        abi::SYS_LSEEK => file::sys_lseek(proc, host, a[0], a[1], a[2]),
        abi::SYS_STAT | abi::SYS_LSTAT => file::sys_stat(proc, host, a[0], a[1]),
        abi::SYS_FSTAT => file::sys_fstat(proc, host, a[0], a[1]),
        abi::SYS_NEWFSTATAT => file::sys_newfstatat(proc, host, a),
        abi::SYS_MMAP => mem::sys_mmap(proc, host, a),
        abi::SYS_MPROTECT => mem::sys_mprotect(proc, host, a[0], a[1], a[2]),
        abi::SYS_MUNMAP => mem::sys_munmap(proc, host, a[0], a[1]),
        abi::SYS_MSYNC => mem::sys_msync(proc, a[0], a[1]),
        abi::SYS_BRK => mem::sys_brk(proc, a[0]),
        abi::SYS_PIPE2 => file::sys_pipe2(proc, host, a[0], a[1]),
        abi::SYS_PIPE => file::sys_pipe2(proc, host, a[0], 0), // musl pipe() 降级
        abi::SYS_WAIT4 => proc::sys_wait4(a[0], a[1], a[2]),
        abi::SYS_KILL => -(abi::ENOSYS as i64), // CLI trap 层处理（SIGKILL/SIGTERM）
        abi::SYS_GETPPID => proc::sys_getppid(proc),
        // 进程组/会话（0.0.6 M5）：单进程无会话语义——pgid=sid=pid 的诚实近似
        abi::SYS_GETPGRP | abi::SYS_GETPGID => proc.pid as i64,
        abi::SYS_SETPGID | abi::SYS_SETSID | abi::SYS_GETSID => proc.pid as i64,
        abi::SYS_UTIMENSAT => file::sys_utimensat(proc, host, a),
        abi::SYS_SYSINFO => file::sys_sysinfo(proc, host, a[0]),
        abi::SYS_FCHMOD => file::sys_fchmod(proc, host, a[0], a[1]),
        abi::SYS_READLINK | abi::SYS_READLINKAT => file::sys_readlinkat(0, a[0], a[1], a[2]),
        abi::SYS_FTRUNCATE => file::sys_ftruncate(proc, host, a[0], a[1]),
        abi::SYS_FCHOWN => file::sys_fchown(proc, a[0]),
        abi::SYS_FCHOWNAT => file::sys_fchown(proc, a[1]),
        abi::SYS_GETRLIMIT => file::sys_getrlimit(proc, a[1]),
        abi::SYS_SETRLIMIT => 0,
        abi::SYS_EXIT | abi::SYS_EXIT_GROUP => proc::sys_exit(host, a[0]),
        abi::SYS_UNAME => proc::sys_uname(proc, a[0]),
        abi::SYS_ARCH_PRCTL => proc::sys_arch_prctl(proc, host, a[0], a[1]),
        abi::SYS_GETRANDOM => proc::sys_getrandom(proc, host, a[0], a[1]),
        abi::SYS_GETPID => proc.pid as i64,
        abi::SYS_GETUID | abi::SYS_GETEUID => proc.uid as i64,
        abi::SYS_GETGID | abi::SYS_GETEGID => proc.gid as i64,
        abi::SYS_GETCWD => file::sys_getcwd(proc, a[0], a[1]),
        abi::SYS_CHDIR => file::sys_chdir(proc, host, a[0]),
        abi::SYS_SET_TID_ADDRESS => proc.pid as i64, // v0 单线程：返回假 pid 即可
        abi::SYS_SET_ROBUST_LIST => 0,               // musl 启动路径调用，忽略
        abi::SYS_CLOCK_GETTIME => time::sys_clock_gettime(proc, host, a[0], a[1]),
        abi::SYS_GETTIMEOFDAY => time::sys_gettimeofday(proc, host, a[0]),
        abi::SYS_GETDENTS64 => file::sys_getdents64(proc, host, a[0], a[1], a[2]),
        abi::SYS_FCNTL => file::sys_fcntl(proc, host, a[0], a[1], a[2]),
        abi::SYS_IOCTL => file::sys_ioctl(proc, host, a[0], a[1], a[2]),
        abi::SYS_PREAD64 => file::sys_pread64(proc, host, a[0], a[1], a[2], a[3]),
        abi::SYS_PWRITE64 => file::sys_pwrite64(proc, host, a[0], a[1], a[2], a[3]),
        abi::SYS_ACCESS => file::sys_access(proc, host, a[0], a[1]),
        abi::SYS_FACCESSAT => file::sys_faccessat(proc, host, a),
        abi::SYS_DUP => file::sys_dup(proc, host, a[0]),
        abi::SYS_DUP2 | abi::SYS_DUP3 => {
            file::sys_dup2(proc, host, a[0], a[1], a[2], nr == abi::SYS_DUP3)
        }
        abi::SYS_FSYNC | abi::SYS_FDATASYNC => {
            file::sys_fsync(proc, host, a[0], nr == abi::SYS_FDATASYNC)
        }
        abi::SYS_MKDIR => file::sys_mkdir(proc, host, abi::AT_FDCWD, a[0]),
        abi::SYS_MKDIRAT => file::sys_mkdir(proc, host, a[0] as u32 as i32, a[1]),
        abi::SYS_RMDIR => file::sys_unlink_path(proc, host, abi::AT_FDCWD, a[0], true),
        abi::SYS_UNLINK => file::sys_unlink_path(proc, host, abi::AT_FDCWD, a[0], false),
        abi::SYS_UNLINKAT => file::sys_unlink_path(
            proc,
            host,
            a[0] as u32 as i32,
            a[1],
            a[2] & abi::AT_REMOVEDIR != 0,
        ),
        abi::SYS_RENAME => file::sys_rename(proc, host, abi::AT_FDCWD, a[0], abi::AT_FDCWD, a[1]),
        abi::SYS_RENAMEAT => file::sys_rename(
            proc,
            host,
            a[0] as u32 as i32,
            a[1],
            a[2] as u32 as i32,
            a[3],
        ),
        abi::SYS_STATX => file::sys_statx(proc, host, a),
        abi::SYS_GETRUSAGE => file::sys_getrusage(proc, a[1]),
        // 诚实 stub：信号投递未实现（NONGOALS），但 musl/busybox 启动路径
        // 必须成功——记录后返回 0（与 set_robust_list 同模式）
        abi::SYS_RT_SIGACTION | abi::SYS_RT_SIGPROCMASK | abi::SYS_MADVISE => 0,
        abi::SYS_PRLIMIT64 => file::sys_prlimit64(proc, a[3]),
        abi::SYS_SOCKET => -(abi::ENOSYS as i64), // NONGOALS：socket 体系
        _ => -(abi::ENOSYS as i64),
    }
}
