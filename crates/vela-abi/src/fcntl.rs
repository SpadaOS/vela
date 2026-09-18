//! fcntl / ioctl / AT_* / access / dirent d_type。

/// fcntl cmd（x86_64 F_* 值）。
pub const F_GETFD: u64 = 1;
pub const F_SETFD: u64 = 2;
pub const F_GETFL: u64 = 3;
pub const F_SETFL: u64 = 4;
pub const FD_CLOEXEC: u64 = 1;

/// fcntl 扩展 cmd。
pub const F_DUPFD: u64 = 0;
pub const F_DUPFD_CLOEXEC: u64 = 1030;

/// ioctl 请求（x86_64 tty 相关）。
pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TIOCGWINSZ: u64 = 0x5413;

/// linux_dirent64 d_type。
pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;

pub const AT_FDCWD: i32 = -100;
pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const AT_REMOVEDIR: u64 = 0x200;

/// access(2)/faccessat(2) mode。
pub const F_OK: u64 = 0;
pub const X_OK: u64 = 1;
pub const W_OK: u64 = 2;
pub const R_OK: u64 = 4;
