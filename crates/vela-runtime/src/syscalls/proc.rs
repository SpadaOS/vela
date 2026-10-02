//! 进程/杂项子系统（PLAN-0.1.0 T5.1）：exit / uname / arch_prctl /
//! getrandom / getppid / wait4。

use std::time::Duration;
use vela_abi as abi;

use vela_sys::{Host, HostError};

use crate::{host_err_to_errno, read_guest_mut, write_guest, GuestProcess};

pub(super) fn sys_exit(proc: &mut GuestProcess, host: &dyn Host, code: u64, group: bool) -> i64 {
    // 退出前冲刷 stdio，避免宿主侧缓冲丢失（规格 4：exit 直接结束进程）
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    if group {
        host.process_exit((code & 0xff) as i32);
    } else {
        if let Some(addr) = host.take_clear_tid().or_else(|| proc.clear_tid.take()) {
            let _ = crate::write_guest(proc, addr, &0u32.to_le_bytes());
            let _ = host.futex_wake(addr as *const u32, 1);
        }
        host.thread_exit((code & 0xff) as i32);
    }
}

/// `set_tid_address(2)` returns the current thread id.  The clear-tid store
/// is owned by the thread launcher; this baseline records the address in the
/// future `GuestThread` state and validates it when a process mapping exists.
pub(super) fn sys_set_tid_address(proc: &mut GuestProcess, host: &dyn Host, addr: u64) -> i64 {
    if addr != 0 && !proc.mem.contains(addr, 4) {
        return -(abi::EFAULT as i64);
    }
    proc.clear_tid = if addr == 0 { None } else { Some(addr) };
    host.set_clear_tid(addr);
    host.current_tid() as i64
}

/// `futex(2)` baseline: private WAIT/WAKE.  The host wait is called only
/// after all guest pointer and timespec validation has completed, so a host
/// implementation may block without holding a guest process lock.
pub(super) fn sys_futex(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let addr = a[0];
    let op = a[1] as u32;
    let command = op & abi::FUTEX_CMD_MASK;
    if addr == 0 || !addr.is_multiple_of(std::mem::align_of::<u32>() as u64) {
        return -(abi::EINVAL as i64);
    }
    if !proc.mem.contains(addr, 4) {
        return -(abi::EFAULT as i64);
    }
    let ptr = addr as *const u32;
    match command {
        abi::FUTEX_WAIT => {
            let current = unsafe { std::ptr::read_volatile(ptr) };
            if current != a[2] as u32 {
                return -(abi::EAGAIN as i64);
            }
            let timeout = match parse_futex_timeout(proc, a[3]) {
                Ok(v) => v,
                Err(e) => return -(e as i64),
            };
            match host.futex_wait(ptr, a[2] as u32, timeout) {
                Ok(()) => 0,
                Err(HostError::TimedOut) => -(abi::ETIMEDOUT as i64),
                Err(HostError::Other(e)) if e == abi::EAGAIN => -(abi::EAGAIN as i64),
                Err(e) => -(crate::host_err_to_errno(&e) as i64),
            }
        }
        abi::FUTEX_WAKE => match host.futex_wake(ptr, a[2] as u32) {
            Ok(n) => n as i64,
            Err(e) => -(crate::host_err_to_errno(&e) as i64),
        },
        _ => -(abi::ENOSYS as i64),
    }
}

fn parse_futex_timeout(proc: &GuestProcess, addr: u64) -> Result<Option<Duration>, i32> {
    if addr == 0 {
        return Ok(None);
    }
    let raw = crate::read_guest(proc, addr, 16)?;
    let sec = i64::from_le_bytes(raw[0..8].try_into().expect("timespec seconds"));
    let nsec = i64::from_le_bytes(raw[8..16].try_into().expect("timespec nanoseconds"));
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(abi::EINVAL);
    }
    let secs = u64::try_from(sec).map_err(|_| abi::EINVAL)?;
    Ok(Some(Duration::new(secs, nsec as u32)))
}

pub(super) fn sys_uname(proc: &GuestProcess, buf: u64) -> i64 {
    // 规格 5.4：Linux / vela / 6.6.0-vela / x86_64
    let mut out = [0u8; 390];
    out[0..65].copy_from_slice(&fill65("Linux"));
    out[65..130].copy_from_slice(&fill65("vela"));
    out[130..195].copy_from_slice(&fill65("6.6.0-vela"));
    out[195..260].copy_from_slice(&fill65("#1 SMP vela"));
    out[260..325].copy_from_slice(&fill65("x86_64"));
    out[325..390].copy_from_slice(&fill65("(none)"));
    match write_guest(proc, buf, &out) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn fill65(s: &str) -> [u8; 65] {
    let mut b = [0u8; 65];
    let n = s.len().min(64);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

pub(super) fn sys_arch_prctl(
    proc: &mut GuestProcess,
    host: &dyn Host,
    code: u64,
    addr: u64,
) -> i64 {
    match code {
        abi::ARCH_SET_FS => {
            // 记录新基址；宿主支持时标记待应用，由 CLI 在异常返回后的
            // 用户态 trampoline 实际切换（wrfsbase 在异常处理器内会被
            // 内核还原）。两种情况都返回 0（规格 5.1 允许）。
            proc.fs_base = addr;
            host.set_soft_tls_base(addr);
            if host.set_fs_base(addr).is_ok() {
                proc.fs_apply_pending = Some(addr);
            }
            0
        }
        abi::ARCH_SET_GS => {
            proc.gs_base = addr;
            0
        }
        abi::ARCH_GET_FS => {
            match write_guest_u64(proc, addr, host.get_fs_base().unwrap_or(proc.fs_base)) {
                Ok(()) => 0,
                Err(e) => -(e as i64),
            }
        }
        abi::ARCH_GET_GS => match write_guest_u64(proc, addr, proc.gs_base) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        },
        _ => -(abi::EINVAL as i64),
    }
}

fn write_guest_u64(proc: &GuestProcess, addr: u64, v: u64) -> Result<(), i32> {
    write_guest(proc, addr, &v.to_le_bytes())
}

pub(super) fn sys_getrandom(proc: &mut GuestProcess, host: &dyn Host, buf: u64, len: u64) -> i64 {
    if len == 0 {
        return 0;
    }
    if len > (1 << 26) {
        return -(abi::EINVAL as i64); // v0 上限 64MiB 防呆
    }
    match read_guest_mut(proc, buf, len as usize) {
        Ok(dst) => host
            .random(dst)
            .map(|_| len as i64)
            .unwrap_or_else(|e| -(host_err_to_errno(&e) as i64)),
        Err(e) => -(e as i64),
    }
}

/// getppid(110)（0.0.6 M1 T1.5）：fork 子进程返回真实父 pid；普通启动
/// 为宿主派生的稳定值（真实父进程不存在——诚实近似）。
pub(super) fn sys_getppid(proc: &GuestProcess) -> i64 {
    if proc.ppid != 0 {
        return proc.ppid as i64;
    }
    (std::process::id() ^ proc.pid.wrapping_mul(0x9E37_79B9)) as i64
}

/// wait4(61)（T3.3）：vela 为单进程模型（无 fork），无子进程可等——
/// 诚实返回 -ECHILD（与 Linux 无子进程时 wait4 的语义一致）。
pub(super) fn sys_wait4(_pid: u64, _status: u64, _opts: u64) -> i64 {
    -(abi::ECHILD as i64)
}
