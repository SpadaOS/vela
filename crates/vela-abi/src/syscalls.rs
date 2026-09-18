//! syscall 号（Linux x86_64）。

pub const SYS_READ: u64 = 0;
pub const SYS_WRITE: u64 = 1;
pub const SYS_OPEN: u64 = 2;
pub const SYS_CLOSE: u64 = 3;
pub const SYS_STAT: u64 = 4;
pub const SYS_FSTAT: u64 = 5;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_MMAP: u64 = 9;
pub const SYS_MPROTECT: u64 = 10;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_MSYNC: u64 = 26;
pub const SYS_BRK: u64 = 12;
pub const SYS_EXECVE: u64 = 59;
pub const SYS_WAIT4: u64 = 61;
pub const SYS_GETPPID: u64 = 110;
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_PREAD64: u64 = 17;
pub const SYS_PWRITE64: u64 = 18;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_ACCESS: u64 = 21;
pub const SYS_PIPE: u64 = 22;
pub const SYS_DUP: u64 = 32;
pub const SYS_DUP2: u64 = 33;
pub const SYS_GETPID: u64 = 39;
pub const SYS_MADVISE: u64 = 28;
pub const SYS_SOCKET: u64 = 41;
pub const SYS_EXIT: u64 = 60;
pub const SYS_UNAME: u64 = 63;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_FSYNC: u64 = 74;
pub const SYS_FDATASYNC: u64 = 75;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_RENAME: u64 = 82;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_RMDIR: u64 = 84;
pub const SYS_UNLINK: u64 = 87;
pub const SYS_TRUNCATE: u64 = 76;
pub const SYS_FTRUNCATE: u64 = 77;
pub const SYS_CHMOD: u64 = 90;
pub const SYS_FCHMOD: u64 = 91;
pub const SYS_FCHMODAT: u64 = 92;
pub const SYS_FCHOWN: u64 = 93;
pub const SYS_FCHOWNAT: u64 = 260;
pub const SYS_READLINK: u64 = 89;
pub const SYS_READLINKAT: u64 = 267;
pub const SYS_SYSINFO: u64 = 99;
pub const SYS_GETRLIMIT: u64 = 160;
pub const SYS_SETRLIMIT: u64 = 161;
pub const SYS_GETRUSAGE: u64 = 98;
pub const SYS_GETUID: u64 = 102;
pub const SYS_GETGID: u64 = 104;
pub const SYS_GETEUID: u64 = 107;
pub const SYS_GETEGID: u64 = 108;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_MKDIRAT: u64 = 258;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_UNLINKAT: u64 = 263;
pub const SYS_RENAMEAT: u64 = 264;
pub const SYS_FACCESSAT: u64 = 269;
pub const SYS_GETDENTS64: u64 = 217;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_DUP3: u64 = 292;
pub const SYS_PIPE2: u64 = 293;
pub const SYS_PRLIMIT64: u64 = 302;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_GETRANDOM: u64 = 318;
pub const SYS_STATX: u64 = 332;

/// syscall 号的可读名字，仅供日志使用。
pub fn syscall_name(nr: u64) -> &'static str {
    match nr {
        SYS_READ => "read",
        SYS_WRITE => "write",
        SYS_OPEN => "open",
        SYS_CLOSE => "close",
        SYS_STAT => "stat",
        SYS_FSTAT => "fstat",
        SYS_LSTAT => "lstat",
        SYS_LSEEK => "lseek",
        SYS_MMAP => "mmap",
        SYS_MPROTECT => "mprotect",
        SYS_MUNMAP => "munmap",
        SYS_MSYNC => "msync",
        SYS_EXECVE => "execve",
        SYS_WAIT4 => "wait4",
        SYS_GETPPID => "getppid",
        SYS_PIPE2 => "pipe2",
        SYS_BRK => "brk",
        SYS_IOCTL => "ioctl",
        SYS_WRITEV => "writev",
        SYS_EXIT => "exit",
        SYS_UNAME => "uname",
        SYS_FCNTL => "fcntl",
        SYS_GETCWD => "getcwd",
        SYS_CHDIR => "chdir",
        SYS_GETPID => "getpid",
        SYS_GETUID => "getuid",
        SYS_GETGID => "getgid",
        SYS_GETEUID => "geteuid",
        SYS_GETEGID => "getegid",
        SYS_GETTIMEOFDAY => "gettimeofday",
        SYS_ARCH_PRCTL => "arch_prctl",
        SYS_EXIT_GROUP => "exit_group",
        SYS_OPENAT => "openat",
        SYS_NEWFSTATAT => "newfstatat",
        SYS_GETDENTS64 => "getdents64",
        SYS_SET_TID_ADDRESS => "set_tid_address",
        SYS_SET_ROBUST_LIST => "set_robust_list",
        SYS_CLOCK_GETTIME => "clock_gettime",
        SYS_GETRANDOM => "getrandom",
        SYS_RT_SIGACTION => "rt_sigaction",
        SYS_RT_SIGPROCMASK => "rt_sigprocmask",
        SYS_PREAD64 => "pread64",
        SYS_PWRITE64 => "pwrite64",
        SYS_ACCESS => "access",
        SYS_DUP => "dup",
        SYS_DUP2 => "dup2",
        SYS_DUP3 => "dup3",
        SYS_MADVISE => "madvise",
        SYS_FSYNC => "fsync",
        SYS_FDATASYNC => "fdatasync",
        SYS_RENAME => "rename",
        SYS_MKDIR => "mkdir",
        SYS_RMDIR => "rmdir",
        SYS_UNLINK => "unlink",
        SYS_GETRUSAGE => "getrusage",
        SYS_MKDIRAT => "mkdirat",
        SYS_UNLINKAT => "unlinkat",
        SYS_RENAMEAT => "renameat",
        SYS_FACCESSAT => "faccessat",
        SYS_PRLIMIT64 => "prlimit64",
        SYS_STATX => "statx",
        SYS_SOCKET => "socket",
        SYS_PIPE => "pipe",
        SYS_TRUNCATE => "truncate",
        SYS_FTRUNCATE => "ftruncate",
        SYS_CHMOD => "chmod",
        SYS_FCHMOD => "fchmod",
        SYS_FCHMODAT => "fchmodat",
        SYS_FCHOWN => "fchown",
        SYS_FCHOWNAT => "fchownat",
        SYS_READLINK => "readlink",
        SYS_READLINKAT => "readlinkat",
        SYS_SYSINFO => "sysinfo",
        SYS_GETRLIMIT => "getrlimit",
        SYS_SETRLIMIT => "setrlimit",
        _ => "unknown",
    }
}

/// T1.3（PLAN-0.0.5）：dispatch 已处理的全部号必须有可读名字——
/// 防止 strace 日志再现 "unknown(nr=...)" 排障盲区。新加 dispatch
/// 分支时把号加进本表。
#[cfg(test)]
mod name_coverage_tests {
    use super::*;

    const DISPATCHED: [u64; 60] = [
        SYS_READ,
        SYS_WRITE,
        SYS_WRITEV,
        SYS_OPEN,
        SYS_CLOSE,
        SYS_STAT,
        SYS_LSTAT,
        SYS_FSTAT,
        SYS_NEWFSTATAT,
        SYS_LSEEK,
        SYS_MMAP,
        SYS_MPROTECT,
        SYS_MUNMAP,
        SYS_MSYNC,
        SYS_BRK,
        SYS_EXIT,
        SYS_EXIT_GROUP,
        SYS_UNAME,
        SYS_ARCH_PRCTL,
        SYS_GETRANDOM,
        SYS_GETPID,
        SYS_GETUID,
        SYS_GETEUID,
        SYS_GETGID,
        SYS_GETEGID,
        SYS_SET_TID_ADDRESS,
        SYS_SET_ROBUST_LIST,
        SYS_CLOCK_GETTIME,
        SYS_GETTIMEOFDAY,
        SYS_GETDENTS64,
        SYS_FCNTL,
        SYS_IOCTL,
        SYS_PREAD64,
        SYS_PWRITE64,
        SYS_ACCESS,
        SYS_FACCESSAT,
        SYS_DUP,
        SYS_DUP2,
        SYS_DUP3,
        SYS_FSYNC,
        SYS_FDATASYNC,
        SYS_MKDIR,
        SYS_MKDIRAT,
        SYS_RMDIR,
        SYS_UNLINK,
        SYS_UNLINKAT,
        SYS_RENAME,
        SYS_RENAMEAT,
        SYS_STATX,
        SYS_GETRUSAGE,
        SYS_RT_SIGACTION,
        SYS_RT_SIGPROCMASK,
        SYS_MADVISE,
        SYS_PRLIMIT64,
        SYS_PIPE2,
        SYS_WAIT4,
        SYS_GETPPID,
        SYS_EXECVE,
        SYS_SOCKET,
        SYS_PIPE,
    ];

    #[test]
    fn every_dispatched_syscall_has_a_name() {
        for nr in DISPATCHED {
            assert_ne!(
                syscall_name(nr),
                "unknown",
                "syscall {nr} lacks a readable name"
            );
        }
    }
}
