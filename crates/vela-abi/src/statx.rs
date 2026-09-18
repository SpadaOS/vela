//! statx(2) mask。

pub const STATX_TYPE: u32 = 0x1;
pub const STATX_MODE: u32 = 0x2;
pub const STATX_NLINK: u32 = 0x4;
pub const STATX_SIZE: u32 = 0x8;
pub const STATX_BASIC_STATS: u32 = 0x7ff;
pub const STATX_ALL: u32 = 0xfff;
