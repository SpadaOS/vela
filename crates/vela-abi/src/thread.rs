//! Linux x86_64 thread and futex ABI constants.

/// `clone(2)` flags accepted by Vela's pthread baseline.
pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// glibc/musl may set this legacy flag. Linux treats it as obsolete; Vela
/// accepts it as a compatibility no-op while retaining thread semantics.
pub const CLONE_DETACHED: u64 = 0x0040_0000;

/// `clone` flags that identify the supported pthread shape.
pub const CLONE_THREAD_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_DETACHED;

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_flags_are_linux_values() {
        assert_eq!(CLONE_VM, 0x100);
        assert_eq!(CLONE_THREAD, 0x10_000);
        assert_eq!(FUTEX_PRIVATE_FLAG, 128);
        assert_eq!(FUTEX_CMD_MASK & FUTEX_PRIVATE_FLAG, 0);
    }
}
