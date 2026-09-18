//! 与 Linux ABI 布局锁死的 C 结构体。

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

/// uname(2) 返回结构（390 字节，6 × 65）。
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

/// readv/writev 的 iovec。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoVec {
    pub iov_base: u64,
    pub iov_len: u64,
}

// 布局锁死（规格 5.1：实现后用 const assert 锁死）
const _: () = assert!(std::mem::size_of::<Stat>() == 144);
const _: () = assert!(std::mem::size_of::<UtsName>() == 390);
const _: () = assert!(std::mem::size_of::<IoVec>() == 16);
