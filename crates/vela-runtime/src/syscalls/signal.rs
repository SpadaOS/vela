//! Signal disposition and pending-mask syscalls. Delivery is kept at the
//! trap safe-point by the CLI; this module owns Linux ABI validation/state.

use crate::{read_guest, write_guest, GuestProcess};
use vela_abi as abi;

fn unsupported_signal(sig: u64) -> bool {
    (32..65).contains(&sig) || matches!(sig, 18..=22)
}

fn valid_signal(sig: u64) -> bool {
    (1..abi::NSIG as u64).contains(&sig)
}

pub(super) fn sys_rt_sigaction(
    proc: &mut GuestProcess,
    sig: u64,
    act: u64,
    old: u64,
    size: u64,
) -> i64 {
    if sig == 0 && act == 0 && old == 0 && size == 0 {
        return 0;
    }
    if size != 8 || !valid_signal(sig) || sig == abi::SIGKILL as u64 || sig == abi::SIGSTOP as u64 {
        return -(abi::EINVAL as i64);
    }
    if unsupported_signal(sig) {
        return -(abi::ENOSYS as i64);
    }
    let idx = sig as usize - 1;
    if old != 0 {
        let d = proc.signals.dispositions[idx];
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&d.handler.to_le_bytes());
        b[8..16].copy_from_slice(&d.flags.to_le_bytes());
        b[16..24].copy_from_slice(&d.restorer.to_le_bytes());
        b[24..32].copy_from_slice(&d.mask.to_le_bytes());
        if let Err(e) = write_guest(proc, old, &b) {
            return -(e as i64);
        }
    }
    if act != 0 {
        let b = match read_guest(proc, act, 32) {
            Ok(b) => b,
            Err(e) => return -(e as i64),
        };
        let disposition = crate::SignalDisposition {
            handler: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            flags: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            restorer: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            mask: u64::from_le_bytes(b[24..32].try_into().unwrap()),
        };
        let supported = abi::SA_RESTORER
            | abi::SA_ONSTACK
            | abi::SA_RESTART
            | abi::SA_NODEFER
            | abi::SA_RESETHAND;
        if disposition.flags & !supported != 0 {
            return -(abi::EINVAL as i64);
        }
        proc.signals.dispositions[idx] = disposition;
    }
    0
}

pub(super) fn sys_rt_sigprocmask(
    proc: &mut GuestProcess,
    how: u64,
    set: u64,
    old: u64,
    size: u64,
) -> i64 {
    if how == 0 && set == 0 && old == 0 && size == 0 {
        return 0;
    }
    if size != 8 {
        return -(abi::EINVAL as i64);
    }
    if old != 0 && write_guest(proc, old, &proc.signals.blocked.to_le_bytes()).is_err() {
        return -(abi::EFAULT as i64);
    }
    if set != 0 {
        let bits = match read_guest(proc, set, 8) {
            Ok(b) => u64::from_le_bytes(b.try_into().unwrap()),
            Err(e) => return -(e as i64),
        };
        match how {
            x if x == abi::SIG_BLOCK as u64 => proc.signals.blocked |= bits,
            x if x == abi::SIG_UNBLOCK as u64 => proc.signals.blocked &= !bits,
            x if x == abi::SIG_SETMASK as u64 => proc.signals.blocked = bits,
            _ => return -(abi::EINVAL as i64),
        }
        proc.signals.blocked &= !((1u64 << (abi::SIGKILL - 1)) | (1u64 << (abi::SIGSTOP - 1)));
    }
    0
}

pub(super) fn sys_sigreturn(proc: &mut GuestProcess) -> i64 {
    match proc.signal_frames.pop() {
        Some(frame) => {
            proc.signals.blocked = frame.blocked;
            proc.alt_stack = frame.alt_stack;
            proc.signal_restore = Some(frame);
            0
        }
        None => -(abi::EINVAL as i64),
    }
}

pub(super) fn sys_sigaltstack(proc: &mut GuestProcess, new_ptr: u64, old_ptr: u64) -> i64 {
    const SS_DISABLE: i32 = 2;
    if old_ptr != 0 {
        let (sp, size, flags) = proc.alt_stack.unwrap_or((0, 0, SS_DISABLE));
        let mut raw = [0u8; 24];
        raw[0..8].copy_from_slice(&sp.to_le_bytes());
        raw[8..12].copy_from_slice(&flags.to_le_bytes());
        raw[16..24].copy_from_slice(&size.to_le_bytes());
        if let Err(e) = write_guest(proc, old_ptr, &raw) {
            return -(e as i64);
        }
    }
    if new_ptr != 0 {
        if proc.alt_stack.is_some_and(|(_, _, flags)| flags & 1 != 0) {
            return -(abi::EPERM as i64);
        }
        let raw = match read_guest(proc, new_ptr, 24) {
            Ok(raw) => raw,
            Err(e) => return -(e as i64),
        };
        let sp = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let flags = i32::from_le_bytes(raw[8..12].try_into().unwrap());
        let size = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        if flags & !SS_DISABLE != 0 || (flags & SS_DISABLE == 0 && (sp == 0 || size < 2048)) {
            return -(abi::EINVAL as i64);
        }
        proc.alt_stack = if flags & SS_DISABLE != 0 {
            None
        } else {
            Some((sp, size, 0))
        };
    }
    0
}

pub(super) fn sys_kill(proc: &mut GuestProcess, pid: u64, sig: u64) -> i64 {
    if pid as u32 != proc.pid && pid as u32 != 0 {
        return -(abi::ESRCH as i64);
    }
    if sig >= abi::NSIG as u64 {
        return -(abi::EINVAL as i64);
    }
    if unsupported_signal(sig) {
        return -(abi::ENOSYS as i64);
    }
    if sig != 0 {
        proc.signals.pending |= 1u64 << (sig - 1);
    }
    0
}

pub(super) fn sys_tgkill(proc: &mut GuestProcess, tgid: u64, tid: u64, sig: u64) -> i64 {
    if tgid as u32 != proc.pid || !proc.threads.contains_key(&(tid as u32)) {
        return -(abi::ESRCH as i64);
    }
    if sig >= abi::NSIG as u64 {
        return -(abi::EINVAL as i64);
    }
    if unsupported_signal(sig) {
        return -(abi::ENOSYS as i64);
    }
    if sig != 0 {
        *proc.thread_pending.entry(tid as u32).or_default() |= 1u64 << (sig - 1);
    }
    0
}
