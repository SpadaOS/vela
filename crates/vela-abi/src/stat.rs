//! st_mode 文件类型位（Linux 值）。

pub const S_IFMT: u32 = 0o170000;
pub const S_IFCHR: u32 = 0o0020000;
pub const S_IFDIR: u32 = 0o0040000;
pub const S_IFIFO: u32 = 0o0010000;
pub const S_IFREG: u32 = 0o0100000;
pub const S_IFLNK: u32 = 0o0120000;
