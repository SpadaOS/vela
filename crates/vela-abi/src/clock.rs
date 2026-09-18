//! clock 与杂项系统常量。

/// clock_gettime 基准。
pub const CLOCK_REALTIME: u64 = 0;
pub const CLOCK_MONOTONIC: u64 = 1;

/// clock_gettime 扩展（映射 monotonic）。
pub const CLOCK_MONOTONIC_RAW: u64 = 4;
pub const CLOCK_BOOTTIME: u64 = 7;

/// prlimit64 的 RLIM_INFINITY。
pub const RLIM_INFINITY: u64 = u64::MAX;

/// arch_prctl 操作码（x86_64）。
pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;
