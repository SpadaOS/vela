//! Bounded syscall attempts under one state guard, interruptible waiting
//! outside it. Guest memory references never survive a guard release.

#[cfg(windows)]
use super::*;
#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
static FUTEX_WAITERS: std::sync::Mutex<
    BTreeMap<u64, Vec<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
> = std::sync::Mutex::new(BTreeMap::new());

#[cfg(windows)]
struct FutexWaiter {
    addr: u64,
    woken: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(windows)]
impl FutexWaiter {
    fn new(addr: u64) -> Self {
        let woken = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        FUTEX_WAITERS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(addr)
            .or_default()
            .push(woken.clone());
        Self { addr, woken }
    }
}
#[cfg(windows)]
impl Drop for FutexWaiter {
    fn drop(&mut self) {
        let mut map = FUTEX_WAITERS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(waiters) = map.get_mut(&self.addr) {
            waiters.retain(|flag| !std::sync::Arc::ptr_eq(flag, &self.woken));
            if waiters.is_empty() {
                map.remove(&self.addr);
            }
        }
    }
}
#[cfg(windows)]
fn wake_futex(addr: u64, count: u32) -> i64 {
    let map = FUTEX_WAITERS.lock().unwrap_or_else(|p| p.into_inner());
    map.get(&addr).map_or(0, |waiters| {
        waiters
            .iter()
            .filter(|flag| !flag.load(Ordering::Acquire))
            .take(count as usize)
            .map(|flag| {
                flag.store(true, Ordering::Release);
                1
            })
            .sum()
    })
}

#[cfg(windows)]
fn timespec(proc: &GuestProcess, ptr: u64, unit: u64) -> Result<Option<Duration>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let raw = vela_runtime::read_guest(proc, ptr, 16).map_err(|e| -(e as i64))?;
    let sec = i64::from_le_bytes(raw[..8].try_into().unwrap());
    let fraction = i64::from_le_bytes(raw[8..].try_into().unwrap());
    if sec < 0 || fraction < 0 || fraction as u64 >= unit {
        return Err(-(vela_abi::EINVAL as i64));
    }
    Ok(Some(Duration::new(
        sec as u64,
        (fraction as u64 * (1_000_000_000 / unit)) as u32,
    )))
}

#[cfg(windows)]
struct Wait {
    active: bool,
    timeout: Option<Duration>,
    idle_result: i64,
    select_inputs: Vec<(u64, Vec<u8>)>,
    temporary_mask: Option<u64>,
    socket: Option<vela_sys::HostSocket>,
    resource: Option<(i32, u64)>,
}

#[cfg(windows)]
impl Wait {
    fn new(proc: &GuestProcess, nr: u64, a: &[u64; 6]) -> Result<Self, i64> {
        use vela_abi as abi;
        let mut wait = Self {
            active: false,
            timeout: None,
            idle_result: -(abi::EAGAIN as i64),
            select_inputs: Vec::new(),
            temporary_mask: None,
            socket: None,
            resource: None,
        };
        match nr {
            abi::SYS_POLL => {
                wait.active = true;
                wait.timeout =
                    ((a[2] as i32) >= 0).then(|| Duration::from_millis(a[2] as u32 as u64));
                wait.idle_result = 0;
            }
            abi::SYS_PPOLL => {
                wait.active = true;
                wait.timeout = timespec(proc, a[2], 1_000_000_000)?;
                wait.idle_result = 0;
            }
            abi::SYS_SELECT | abi::SYS_PSELECT6 => {
                if a[0] > 1024 {
                    return Err(-(abi::EINVAL as i64));
                }
                wait.active = true;
                wait.idle_result = 0;
                wait.timeout = timespec(
                    proc,
                    a[4],
                    if nr == abi::SYS_SELECT {
                        1_000_000
                    } else {
                        1_000_000_000
                    },
                )?;
                for ptr in [a[1], a[2], a[3]] {
                    if ptr != 0 {
                        wait.select_inputs.push((
                            ptr,
                            vela_runtime::read_guest(proc, ptr, (a[0] as usize).div_ceil(64) * 8)
                                .map_err(|e| -(e as i64))?
                                .to_vec(),
                        ));
                    }
                }
            }
            abi::SYS_EPOLL_WAIT | abi::SYS_EPOLL_PWAIT => {
                wait.active = true;
                wait.timeout =
                    ((a[3] as i32) >= 0).then(|| Duration::from_millis(a[3] as u32 as u64));
                wait.idle_result = 0;
            }
            abi::SYS_WAIT4 => {
                wait.active = a[2] & 1 == 0;
                wait.idle_result = 0;
            }
            abi::SYS_FUTEX if a[1] as u32 & abi::FUTEX_CMD_MASK == abi::FUTEX_WAIT => {
                wait.active = true;
                wait.timeout = timespec(proc, a[3], 1_000_000_000)?;
                wait.idle_result = -(abi::ETIMEDOUT as i64);
            }
            abi::SYS_READ
            | abi::SYS_READV
            | abi::SYS_WRITE
            | abi::SYS_WRITEV
            | abi::SYS_ACCEPT
            | abi::SYS_ACCEPT4
            | abi::SYS_CONNECT
            | abi::SYS_SENDTO
            | abi::SYS_RECVFROM
            | abi::SYS_SENDMSG
            | abi::SYS_RECVMSG => match proc.fds.get(a[0] as i32) {
                Some(vela_runtime::GuestFd::Host(vela_sys::HostFile(
                    vela_sys::HostFileKind::Socket(socket),
                ))) => {
                    let flags = match nr {
                        abi::SYS_SENDTO | abi::SYS_RECVFROM => a[3],
                        abi::SYS_SENDMSG | abi::SYS_RECVMSG => a[2],
                        _ => 0,
                    };
                    wait.active = !socket.nonblocking() && flags & abi::MSG_DONTWAIT as u64 == 0;
                    let receive = matches!(
                        nr,
                        abi::SYS_READ
                            | abi::SYS_READV
                            | abi::SYS_RECVFROM
                            | abi::SYS_RECVMSG
                            | abi::SYS_ACCEPT
                            | abi::SYS_ACCEPT4
                    );
                    let timeout = socket.timeout_us(receive);
                    wait.timeout = (timeout != 0).then(|| Duration::from_micros(timeout));
                    wait.socket = Some(socket.clone());
                    if nr == abi::SYS_CONNECT {
                        wait.idle_result = -(abi::EINPROGRESS as i64);
                    }
                }
                Some(vela_runtime::GuestFd::PipeRead(_))
                | Some(vela_runtime::GuestFd::PipeWrite(_)) => {
                    wait.active = proc.fds.get_flags(a[0] as i32).unwrap_or(0)
                        & ((abi::O_NONBLOCK as u32) << 8)
                        == 0;
                }
                _ => {}
            },
            _ => {}
        }
        if wait.active
            && !matches!(
                nr,
                abi::SYS_POLL
                    | abi::SYS_PPOLL
                    | abi::SYS_SELECT
                    | abi::SYS_PSELECT6
                    | abi::SYS_FUTEX
                    | abi::SYS_WAIT4
            )
        {
            wait.resource = proc.fds.identity(a[0] as i32).map(|id| (a[0] as i32, id));
        }
        let (mask, size) = match nr {
            abi::SYS_PPOLL => (a[3], a[4]),
            abi::SYS_EPOLL_PWAIT => (a[4], a[5]),
            abi::SYS_PSELECT6 if a[5] != 0 => {
                let raw = vela_runtime::read_guest(proc, a[5], 16).map_err(|e| -(e as i64))?;
                (
                    u64::from_le_bytes(raw[..8].try_into().unwrap()),
                    u64::from_le_bytes(raw[8..].try_into().unwrap()),
                )
            }
            _ => (0, 0),
        };
        if mask != 0 {
            if size != 8 {
                return Err(-(abi::EINVAL as i64));
            }
            let raw = vela_runtime::read_guest(proc, mask, 8).map_err(|e| -(e as i64))?;
            wait.temporary_mask = Some(
                u64::from_le_bytes(raw.try_into().unwrap())
                    & !((1 << (abi::SIGKILL - 1)) | (1 << (abi::SIGSTOP - 1))),
            );
        }
        Ok(wait)
    }
}

#[cfg(windows)]
pub(super) unsafe fn run(
    state: &vela_runtime::ProcessShared<GuestState>,
    nr: u64,
    args: &[u64; 6],
    frame: &mut TrapFrame,
) -> i64 {
    use vela_abi as abi;
    let original = *frame.regs;
    let flags = frame.e_flags;
    let start = Instant::now();
    let mut guard = state.lock().unwrap_or_else(|p| p.into_inner());
    let tid = guard.host.current_tid();
    vela_runtime::GuestContext::enter(&mut guard.proc, tid);
    let wait = Wait::new(&guard.proc, nr, args);
    let mut wait = match wait {
        Ok(wait) => wait,
        Err(error) => {
            return unsafe { super::trap_locked(&mut guard, nr, args, frame, Some(error), true) }
        }
    };
    if wait.active && nr == abi::SYS_FUTEX {
        if args[0] == 0 || !args[0].is_multiple_of(4) || !guard.proc.can_access(args[0], 4, 1) {
            return unsafe {
                super::trap_locked(
                    &mut guard,
                    nr,
                    args,
                    frame,
                    Some(-(abi::EFAULT as i64)),
                    true,
                )
            };
        }
        if unsafe { std::ptr::read_volatile(args[0] as *const u32) } != args[2] as u32 {
            wait.active = false;
        }
    }
    let old_mask = guard.proc.signals.blocked;
    let futex_waiter = (wait.active && nr == abi::SYS_FUTEX).then(|| FutexWaiter::new(args[0]));
    let mut first = true;
    loop {
        let st = &mut *guard;
        if CONSOLE_STOP.swap(false, Ordering::AcqRel) {
            fork::terminate_all_children(st);
        }
        vela_runtime::GuestContext::enter(&mut st.proc, tid);
        fork::poll_children(st);
        st.host.reap_guest_threads();
        if let Some(mask) = wait.temporary_mask {
            st.proc.signals.blocked = mask;
        }
        st.proc.nonblocking_step = true;
        if nr == abi::SYS_SCHED_YIELD {
            let result = unsafe { super::trap_locked(st, nr, args, frame, Some(0), true) };
            drop(guard);
            std::thread::yield_now();
            return result;
        }
        if nr == abi::SYS_EXIT || nr == abi::SYS_EXIT_GROUP {
            if logx::enabled() {
                eprintln!("[vela] {}({:#x})", abi::syscall_name(nr), args[0]);
            }
            let host = st.host.clone();
            if let Some(addr) = host.take_clear_tid().or(st.proc.clear_tid.take()) {
                let _ = write_guest(&st.proc, addr, &0u32.to_le_bytes());
                wake_futex(addr, 1);
            }
            st.proc.threads.remove(&tid);
            st.proc.thread_pending.remove(&tid);
            drop(guard);
            if nr == abi::SYS_EXIT_GROUP {
                host.process_exit(args[0] as i32);
            } else {
                host.thread_exit(args[0] as i32);
            }
        }
        for (ptr, data) in &wait.select_inputs {
            if let Err(error) = write_guest(&st.proc, *ptr, data) {
                return unsafe {
                    super::trap_locked(st, nr, args, frame, Some(-(error as i64)), true)
                };
            }
        }
        *frame.regs = original;
        frame.e_flags = flags;
        let mut attempt_args = *args;
        if wait.active && nr == abi::SYS_WAIT4 {
            attempt_args[2] |= 1;
        }
        st.proc.discard_ignored_signals();
        let directed = st.proc.thread_pending.get(&tid).copied().unwrap_or(0);
        let pending = (st.proc.signals.pending | directed) & !st.proc.signals.blocked;
        let caught = pending != 0
            && (0..64).any(|i| {
                pending & (1 << i) != 0
                    && st.proc.signals.dispositions[i].handler != abi::SIG_IGN
                    && (st.proc.signals.dispositions[i].handler != abi::SIG_DFL
                        || i + 1 != abi::SIGCHLD as usize)
            });
        let mut override_result = (wait.active && caught).then_some(-(abi::EINTR as i64));
        if wait
            .resource
            .is_some_and(|(fd, identity)| st.proc.fds.identity(fd) != Some(identity))
        {
            override_result = Some(-(abi::EBADF as i64));
        }
        if let Some(socket) = &wait.socket {
            let same = matches!(st.proc.fds.get(args[0] as i32), Some(vela_runtime::GuestFd::Host(vela_sys::HostFile(vela_sys::HostFileKind::Socket(current)))) if current.identity() == socket.identity());
            if !same {
                override_result = Some(-(abi::EBADF as i64));
            }
        }
        if wait.active && nr == abi::SYS_CONNECT && !first && override_result.is_none() {
            let socket = wait.socket.as_ref().unwrap();
            let ready = socket.poll_ready(abi::POLLOUT);
            override_result = Some(if ready != 0 {
                match socket.get_option(abi::SOL_SOCKET, abi::SO_ERROR) {
                    Ok(0) => 0,
                    Ok(error) => -(error as i64),
                    Err(_) => -(abi::EIO as i64),
                }
            } else {
                -(abi::EINPROGRESS as i64)
            });
        }

        if wait.active && nr == abi::SYS_FUTEX && !first {
            if !st.proc.can_access(args[0], 4, 1) {
                override_result = Some(-(abi::EFAULT as i64));
            } else if futex_waiter
                .as_ref()
                .is_some_and(|waiter| waiter.woken.load(Ordering::Acquire))
            {
                override_result = Some(0);
            }
        }
        if nr == abi::SYS_FUTEX
            && args[1] as u32 & abi::FUTEX_CMD_MASK == abi::FUTEX_WAKE
            && st.proc.can_access(args[0], 4, 1)
            && args[0].is_multiple_of(4)
        {
            override_result = Some(wake_futex(args[0], args[2] as u32));
        }
        let result = unsafe {
            super::trap_locked(st, nr, &attempt_args, frame, override_result, !wait.active)
        };
        let retry = wait.active
            && if matches!(
                nr,
                abi::SYS_POLL
                    | abi::SYS_PPOLL
                    | abi::SYS_SELECT
                    | abi::SYS_PSELECT6
                    | abi::SYS_EPOLL_WAIT
                    | abi::SYS_EPOLL_PWAIT
                    | abi::SYS_WAIT4
            ) {
                result == 0
            } else if nr == abi::SYS_CONNECT {
                result == -(abi::EINPROGRESS as i64)
            } else {
                override_result.is_none() && result == -(abi::EAGAIN as i64)
            };
        let expired = wait
            .timeout
            .is_some_and(|timeout| start.elapsed() >= timeout);
        if !retry || expired {
            if wait.active {
                let result = if retry && expired {
                    wait.idle_result
                } else {
                    result
                };
                *frame.regs = original;
                frame.e_flags = flags;
                let depth = st.proc.signal_frames.len();
                let outcome =
                    unsafe { super::trap_locked(st, nr, args, frame, Some(result), true) };
                if wait.temporary_mask.is_some() {
                    // Select the handler using the atomic wait mask, but
                    // sigreturn must restore the caller's pre-wait mask.
                    if st.proc.signal_frames.len() > depth {
                        st.proc.signal_frames[depth].blocked = old_mask;
                    } else {
                        st.proc.signals.blocked = old_mask;
                    }
                }
                return outcome;
            }
            return result;
        }
        first = false;
        drop(guard);
        // A bounded wait also observes close/epoll changes and child exits
        // without borrowing the guest address space or native descriptors.
        std::thread::sleep(Duration::from_millis(1));
        guard = state.lock().unwrap_or_else(|p| p.into_inner());
    }
}
