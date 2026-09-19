//! errno（Linux x86_64 值）。

pub const ENOENT: i32 = 2;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const ENODEV: i32 = 19;
pub const EFAULT: i32 = 14;
pub const EEXIST: i32 = 17;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENOTTY: i32 = 25;
pub const ESPIPE: i32 = 29;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const ECHILD: i32 = 10;
pub const EPIPE: i32 = 32;
pub const EAGAIN: i32 = 11;
pub const ENOEXEC: i32 = 8;
pub const ERANGE: i32 = 34;
pub const EIO: i32 = 5;
pub const ESRCH: i32 = 3;

pub fn errno_result(e: i32) -> i64 {
    -(e as i64)
}
