//! vela-abi：只描述 Linux x86_64 用户态 ABI（syscall 号、errno、结构体布局）。
//! 禁止依赖 `std::os` 与任何宿主类型（规格 2.4 / 5.1）。
//!
//! 0.0.5 T1.2：按语义拆分为子模块；此处全量重导出，`abi::SYS_MMAP` 等
//! 既有路径保持不变。

pub mod auxv;
pub mod clock;
pub mod errno;
pub mod fcntl;
pub mod mmap;
pub mod open;
pub mod stat;
pub mod statx;
pub mod structs;
pub mod syscalls;

pub use auxv::*;
pub use clock::*;
pub use errno::*;
pub use fcntl::*;
pub use mmap::*;
pub use open::*;
pub use stat::*;
pub use statx::*;
pub use structs::*;
pub use syscalls::*;

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
