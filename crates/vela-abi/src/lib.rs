//! vela-abi：只描述 Linux x86_64 用户态 ABI（syscall 号、errno、结构体布局）。
//! 禁止依赖 `std::os` 与任何宿主类型（规格 2.4 / 5.1）。

// ---------------------------------------------------------------- syscalls

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
pub const SYS_BRK: u64 = 12;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_WRITEV: u64 = 20;
pub const SYS_EXIT: u64 = 60;
pub const SYS_UNAME: u64 = 63;
pub const SYS_FCNTL: u64 = 72;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_CHDIR: u64 = 80;
pub const SYS_GETPID: u64 = 39;
pub const SYS_GETTIMEOFDAY: u64 = 96;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_EXIT_GROUP: u64 = 231;
pub const SYS_OPENAT: u64 = 257;
pub const SYS_NEWFSTATAT: u64 = 262;
pub const SYS_SET_TID_ADDRESS: u64 = 218;
pub const SYS_SET_ROBUST_LIST: u64 = 273;
pub const SYS_CLOCK_GETTIME: u64 = 228;
pub const SYS_GETRANDOM: u64 = 318;

// ---------------------------------------------------------------- errno

pub const ENOENT: i32 = 2;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const EEXIST: i32 = 17;
pub const ENOTDIR: i32 = 20;
pub const EINVAL: i32 = 22;
pub const ENOTTY: i32 = 25;
pub const ESPIPE: i32 = 29;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;

pub fn errno_result(e: i32) -> i64 {
    -(e as i64)
}

// ---------------------------------------------------------------- mmap

pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_FAILED: i64 = -1;

// ---------------------------------------------------------------- open flags

pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0x40;
pub const O_EXCL: u64 = 0x80;
pub const O_TRUNC: u64 = 0x200;
pub const O_APPEND: u64 = 0x400;
pub const O_CLOEXEC: u64 = 0x80000;

pub const AT_FDCWD: i32 = -100;
pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

// ---------------------------------------------------------------- file type (st_mode)

pub const S_IFMT: u32 = 0o170000;
pub const S_IFCHR: u32 = 0o0020000;
pub const S_IFDIR: u32 = 0o0040000;
pub const S_IFREG: u32 = 0o0100000;
pub const S_IFLNK: u32 = 0o0120000;

// ---------------------------------------------------------------- auxv

pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_EXECFN: u64 = 31;

// ---------------------------------------------------------------- clock

pub const CLOCK_REALTIME: u64 = 0;
pub const CLOCK_MONOTONIC: u64 = 1;

// ---------------------------------------------------------------- arch_prctl

pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

// ---------------------------------------------------------------- structs

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UtsName {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoVec {
    pub iov_base: u64,
    pub iov_len: u64,
}

/// Linux x86_64 `struct stat` 原始布局（144 字节），不是 Windows 也不是 stat64。
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

// 布局锁死（规格 5.1：实现后用 const assert 锁死）
const _: () = assert!(std::mem::size_of::<Stat>() == 144);
const _: () = assert!(std::mem::size_of::<UtsName>() == 390);
const _: () = assert!(std::mem::size_of::<IoVec>() == 16);

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
        SYS_BRK => "brk",
        SYS_IOCTL => "ioctl",
        SYS_WRITEV => "writev",
        SYS_EXIT => "exit",
        SYS_UNAME => "uname",
        SYS_FCNTL => "fcntl",
        SYS_GETCWD => "getcwd",
        SYS_CHDIR => "chdir",
        SYS_GETPID => "getpid",
        SYS_GETTIMEOFDAY => "gettimeofday",
        SYS_ARCH_PRCTL => "arch_prctl",
        SYS_EXIT_GROUP => "exit_group",
        SYS_OPENAT => "openat",
        SYS_NEWFSTATAT => "newfstatat",
        SYS_SET_TID_ADDRESS => "set_tid_address",
        SYS_SET_ROBUST_LIST => "set_robust_list",
        SYS_CLOCK_GETTIME => "clock_gettime",
        SYS_GETRANDOM => "getrandom",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn stat_layout_is_linux_x86_64() {
        assert_eq!(size_of::<Stat>(), 144);
    }

    #[test]
    fn utsname_layout() {
        assert_eq!(size_of::<UtsName>(), 390);
    }

    #[test]
    fn errno_negation() {
        assert_eq!(errno_result(ENOSYS), -38);
        assert_eq!(errno_result(EINVAL), -22);
    }
}
