//! open(2) 标志（Linux x86_64 值）。

pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0x40;
pub const O_EXCL: u64 = 0x80;
pub const O_TRUNC: u64 = 0x200;
pub const O_APPEND: u64 = 0x400;
pub const O_NONBLOCK: u64 = 0x800;
pub const O_DIRECTORY: u64 = 0x10000;
pub const O_CLOEXEC: u64 = 0x80000;
