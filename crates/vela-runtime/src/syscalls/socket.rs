//! Socket and epoll syscall translation. All host networking stays behind
//! `vela_sys::HostFileOps`.

use crate::{
    host_err_to_errno, read_guest, read_guest_mut, write_guest, EpollState, EpollWatch, GuestFd,
    GuestProcess,
};
use std::sync::{Arc, Mutex};
use vela_abi as abi;
use vela_sys::{Host, HostError, HostFile, HostFileKind, HostSocket};

fn sock(proc: &GuestProcess, fd: i32) -> Result<&HostSocket, i64> {
    match proc.fds.get(fd) {
        Some(GuestFd::Host(HostFile(HostFileKind::Socket(s)))) => Ok(s),
        Some(GuestFd::Host(_)) => Err(-(abi::ENOTSOCK as i64)),
        _ => Err(-(abi::EBADF as i64)),
    }
}

fn host_err(e: HostError) -> i64 {
    -(host_err_to_errno(&e) as i64)
}

fn socket_err(proc: &mut GuestProcess, e: HostError) -> i64 {
    let errno = host_err_to_errno(&e);
    if errno == abi::EPIPE {
        proc.signals.pending |= 1u64 << (abi::SIGPIPE - 1);
    }
    -(errno as i64)
}

pub(super) fn sys_socket(
    proc: &mut GuestProcess,
    host: &dyn Host,
    domain: u64,
    kind: u64,
    protocol: u64,
) -> i64 {
    let kind32 = kind as u32;
    if kind32 & !(abi::SOCK_TYPE_MASK | abi::SOCK_NONBLOCK | abi::SOCK_CLOEXEC) != 0
        || kind32 & abi::SOCK_TYPE_MASK == 0
    {
        return -(abi::EINVAL as i64);
    }
    let s = match host.socket(domain as u16, kind32, protocol as u32) {
        Ok(s) => s,
        Err(e) => return host_err(e),
    };
    let fd = proc
        .fds
        .alloc_fd(GuestFd::Host(HostFile(HostFileKind::Socket(s))));
    if kind32 & abi::SOCK_CLOEXEC != 0 {
        proc.fds.update_flags(fd, |v| v | 1);
    }
    if kind32 & abi::SOCK_NONBLOCK != 0 {
        proc.fds
            .update_flags(fd, |v| v | ((abi::O_NONBLOCK as u32) << 8));
    }
    fd as i64
}

pub(super) fn sys_socketpair(
    proc: &mut GuestProcess,
    host: &dyn Host,
    domain: u64,
    kind: u64,
    protocol: u64,
    out: u64,
) -> i64 {
    let kind32 = kind as u32;
    if kind32 & !(abi::SOCK_TYPE_MASK | abi::SOCK_NONBLOCK | abi::SOCK_CLOEXEC) != 0
        || kind32 & abi::SOCK_TYPE_MASK != abi::SOCK_STREAM
    {
        return -(abi::EINVAL as i64);
    }
    let (a, b) = match host.socketpair(domain as u16, kind as u32, protocol as u32) {
        Ok(v) => v,
        Err(e) => return host_err(e),
    };
    let fda = proc
        .fds
        .alloc_fd(GuestFd::Host(HostFile(HostFileKind::Socket(a))));
    let fdb = proc
        .fds
        .alloc_fd(GuestFd::Host(HostFile(HostFileKind::Socket(b))));
    if kind & abi::SOCK_CLOEXEC as u64 != 0 {
        proc.fds.update_flags(fda, |v| v | 1);
        proc.fds.update_flags(fdb, |v| v | 1);
    }
    if kind & abi::SOCK_NONBLOCK as u64 != 0 {
        proc.fds
            .update_flags(fda, |v| v | ((abi::O_NONBLOCK as u32) << 8));
        proc.fds
            .update_flags(fdb, |v| v | ((abi::O_NONBLOCK as u32) << 8));
        for fd in [fda, fdb] {
            if let Some(GuestFd::Host(HostFile(HostFileKind::Socket(s)))) = proc.fds.get(fd) {
                if let Err(e) = host.socket_set_nonblocking(s, true) {
                    return host_err(e);
                }
            }
        }
    }
    if let Err(e) = write_guest(
        proc,
        out,
        &fda.to_le_bytes()
            .into_iter()
            .chain(fdb.to_le_bytes())
            .collect::<Vec<_>>(),
    ) {
        return -(e as i64);
    }
    0
}

fn sockaddr(proc: &GuestProcess, ptr: u64, len: u64) -> Result<Vec<u8>, i64> {
    if ptr == 0 || !(2..=128).contains(&len) {
        return Err(-(abi::EINVAL as i64));
    }
    read_guest(proc, ptr, len as usize)
        .map(|b| b.to_vec())
        .map_err(|e| -(e as i64))
}

pub(super) fn sys_bind(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    addr: u64,
    len: u64,
) -> i64 {
    let s = match sock(proc, fd as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let a = match sockaddr(proc, addr, len) {
        Ok(a) => a,
        Err(e) => return e,
    };
    host.socket_bind(s, &a).map(|_| 0).unwrap_or_else(host_err)
}
pub(super) fn sys_connect(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    addr: u64,
    len: u64,
) -> i64 {
    let s = match sock(proc, fd as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let a = match sockaddr(proc, addr, len) {
        Ok(a) => a,
        Err(e) => return e,
    };
    host.socket_connect(s, &a)
        .map(|_| 0)
        .unwrap_or_else(host_err)
}
pub(super) fn sys_listen(proc: &GuestProcess, host: &dyn Host, fd: u64, backlog: u64) -> i64 {
    let s = match sock(proc, fd as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    host.socket_listen(s, backlog as i32)
        .map(|_| 0)
        .unwrap_or_else(host_err)
}
pub(super) fn sys_accept(proc: &mut GuestProcess, host: &dyn Host, fd: u64, flags: u64) -> i64 {
    if flags & !(abi::SOCK_NONBLOCK as u64 | abi::SOCK_CLOEXEC as u64) != 0 {
        return -(abi::EINVAL as i64);
    }
    let s = match sock(proc, fd as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let accepted = match host.socket_accept(s) {
        Ok(s) => s,
        Err(e) => return host_err(e),
    };
    let n = proc
        .fds
        .alloc_fd(GuestFd::Host(HostFile(HostFileKind::Socket(accepted))));
    if flags & abi::SOCK_CLOEXEC as u64 != 0 {
        proc.fds.update_flags(n, |v| v | 1);
    }
    if flags & abi::SOCK_NONBLOCK as u64 != 0 {
        proc.fds
            .update_flags(n, |v| v | ((abi::O_NONBLOCK as u32) << 8));
        if let Some(GuestFd::Host(HostFile(HostFileKind::Socket(s)))) = proc.fds.get(n) {
            let _ = host.socket_set_nonblocking(s, true);
        }
    }
    n as i64
}

pub(super) fn sys_shutdown(proc: &GuestProcess, host: &dyn Host, fd: u64, how: u64) -> i64 {
    let s = match sock(proc, fd as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    host.socket_shutdown(s, how as u32)
        .map(|_| 0)
        .unwrap_or_else(host_err)
}
pub(super) fn sys_sendto(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let s = match sock(proc, a[0] as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match read_guest(proc, a[1], a[2] as usize) {
        Ok(d) => d,
        Err(e) => return -(e as i64),
    };
    if a[4] == 0 {
        match host.socket_send(s, data, a[3] as u32) {
            Ok(n) => n as i64,
            Err(e) => socket_err(proc, e),
        }
    } else {
        let addr = match sockaddr(proc, a[4], a[5]) {
            Ok(a) => a,
            Err(e) => return e,
        };
        match host.socket_sendto(s, data, &addr, a[3] as u32) {
            Ok(n) => n as i64,
            Err(e) => socket_err(proc, e),
        }
    }
}
pub(super) fn sys_recvfrom(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let s = match sock(proc, a[0] as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let dst = match read_guest_mut(proc, a[1], a[2] as usize) {
        Ok(d) => d,
        Err(e) => return -(e as i64),
    };
    let (n, addr) = match host.socket_recvfrom(s, dst, a[3] as u32) {
        Ok(v) => v,
        Err(e) => return host_err(e),
    };
    if a[4] != 0 {
        let cap = match read_guest(proc, a[5], 4) {
            Ok(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
            Err(e) => return -(e as i64),
        };
        let copy = cap.min(addr.len());
        let _ = write_guest(proc, a[4], &addr[..copy]);
        let _ = write_guest(proc, a[5], &(addr.len() as u32).to_le_bytes());
    }
    n as i64
}

pub(super) fn sys_sendmsg(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    msg: u64,
    flags: u64,
) -> i64 {
    let hdr = match read_guest(proc, msg, 56) {
        Ok(b) => b,
        Err(e) => return -(e as i64),
    };
    let iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let count = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    if count > 1024 {
        return -(abi::EINVAL as i64);
    }
    let mut payload = Vec::new();
    for i in 0..count {
        let ent_addr = match iov.checked_add(i.saturating_mul(16)) {
            Some(v) => v,
            None => return -(abi::EFAULT as i64),
        };
        let ent = match read_guest(proc, ent_addr, 16) {
            Ok(b) => b,
            Err(e) => return -(e as i64),
        };
        let base = u64::from_le_bytes(ent[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(ent[8..16].try_into().unwrap());
        if len > usize::MAX as u64 {
            return -(abi::E2BIG as i64);
        }
        let data = match read_guest(proc, base, len as usize) {
            Ok(d) => d,
            Err(e) => return -(e as i64),
        };
        payload.extend_from_slice(data);
    }
    let socket = match sock(proc, fd as i32) {
        Ok(socket) => socket,
        Err(e) => return e,
    };
    match host.socket_send(socket, &payload, flags as u32) {
        Ok(n) => n as i64,
        Err(e) => socket_err(proc, e),
    }
}
pub(super) fn sys_recvmsg(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    msg: u64,
    flags: u64,
) -> i64 {
    let hdr = match read_guest(proc, msg, 56) {
        Ok(b) => b,
        Err(e) => return -(e as i64),
    };
    let iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let count = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    if count > 1024 {
        return -(abi::EINVAL as i64);
    }
    let mut buffers = Vec::new();
    let mut total_len = 0usize;
    for i in 0..count {
        let ent_addr = match iov.checked_add(i.saturating_mul(16)) {
            Some(v) => v,
            None => return -(abi::EFAULT as i64),
        };
        let ent = match read_guest(proc, ent_addr, 16) {
            Ok(b) => b,
            Err(e) => return -(e as i64),
        };
        let base = u64::from_le_bytes(ent[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(ent[8..16].try_into().unwrap());
        if len > usize::MAX as u64 {
            return -(abi::E2BIG as i64);
        }
        buffers.push((base, len as usize));
        total_len = match total_len.checked_add(len as usize) {
            Some(total) => total,
            None => return -(abi::E2BIG as i64),
        };
    }
    let socket = match sock(proc, fd as i32) {
        Ok(socket) => socket,
        Err(e) => return e,
    };
    let mut payload = vec![0u8; total_len];
    let received = match host.socket_recv(socket, &mut payload, flags as u32) {
        Ok(n) => n,
        Err(e) => return host_err(e),
    };
    let mut copied = 0usize;
    for (base, len) in buffers {
        if copied >= received {
            break;
        }
        let n = len.min(received - copied);
        if let Err(e) = write_guest(proc, base, &payload[copied..copied + n]) {
            return -(e as i64);
        }
        copied += n;
    }
    received as i64
}

pub(super) fn sys_sockname(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    out: u64,
    lenp: u64,
    peer: bool,
) -> i64 {
    let s = match sock(proc, fd as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let addr = match host.socket_name(s, peer) {
        Ok(a) => a,
        Err(e) => return host_err(e),
    };
    let cap = match read_guest(proc, lenp, 4) {
        Ok(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
        Err(e) => return -(e as i64),
    };
    let n = cap.min(addr.len());
    if let Err(e) = write_guest(proc, out, &addr[..n]) {
        return -(e as i64);
    }
    if let Err(e) = write_guest(proc, lenp, &(addr.len() as u32).to_le_bytes()) {
        return -(e as i64);
    }
    0
}
pub(super) fn sys_setsockopt(proc: &GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let s = match sock(proc, a[0] as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let raw = match read_guest(proc, a[4], a[5] as usize) {
        Ok(b) => b,
        Err(e) => return -(e as i64),
    };
    if raw.len() < 4 {
        return -(abi::EINVAL as i64);
    }
    host.socket_set_option(
        s,
        a[1] as u32,
        a[2] as u32,
        i32::from_ne_bytes(raw[0..4].try_into().unwrap()),
    )
    .map(|_| 0)
    .unwrap_or_else(host_err)
}
pub(super) fn sys_getsockopt(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let s = match sock(proc, a[0] as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let value = match host.socket_get_option(s, a[1] as u32, a[2] as u32) {
        Ok(v) => v,
        Err(e) => return host_err(e),
    };
    let cap = match read_guest(proc, a[4], 4) {
        Ok(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
        Err(e) => return -(e as i64),
    };
    let bytes = value.to_ne_bytes();
    let n = cap.min(bytes.len());
    if let Err(e) = write_guest(proc, a[3], &bytes[..n]) {
        return -(e as i64);
    }
    if let Err(e) = write_guest(proc, a[4], &(n as u32).to_ne_bytes()) {
        return -(e as i64);
    }
    0
}

pub(super) fn sys_epoll_create1(proc: &mut GuestProcess, flags: u64) -> i64 {
    if flags & !abi::O_CLOEXEC != 0 {
        return -(abi::EINVAL as i64);
    }
    let fd = proc
        .fds
        .alloc_fd(GuestFd::Epoll(Arc::new(Mutex::new(EpollState::default()))));
    if flags & abi::O_CLOEXEC != 0 {
        proc.fds.set_flags(fd, 1);
    }
    fd as i64
}
pub(super) fn sys_epoll_ctl(
    proc: &mut GuestProcess,
    op: u64,
    epfd: u64,
    fd: u64,
    event: u64,
) -> i64 {
    let state = match proc.fds.get(epfd as i32) {
        Some(GuestFd::Epoll(s)) => s.clone(),
        _ => return -(abi::EBADF as i64),
    };
    if fd as i32 == epfd as i32 {
        return -(abi::EINVAL as i64);
    }
    if proc.fds.get(fd as i32).is_none() {
        return -(abi::EBADF as i64);
    }
    let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
    match op {
        x if x == abi::EPOLL_CTL_ADD as u64 => {
            if state.watches.contains_key(&(fd as i32)) {
                return -(abi::EEXIST as i64);
            }
            if state.watches.len() >= 1024 {
                return -(abi::ENOSPC as i64);
            }
            let b = match read_guest(proc, event, 12) {
                Ok(b) => b,
                Err(e) => return -(e as i64),
            };
            let events = u32::from_le_bytes(b[0..4].try_into().unwrap());
            if events & (abi::EPOLLET | abi::EPOLLONESHOT) != 0 {
                return -(abi::EINVAL as i64);
            }
            state.watches.insert(
                fd as i32,
                EpollWatch {
                    events,
                    data: u64::from_le_bytes(b[4..12].try_into().unwrap()),
                },
            );
            0
        }
        x if x == abi::EPOLL_CTL_MOD as u64 => {
            let b = match read_guest(proc, event, 12) {
                Ok(b) => b,
                Err(e) => return -(e as i64),
            };
            let events = u32::from_le_bytes(b[0..4].try_into().unwrap());
            if events & (abi::EPOLLET | abi::EPOLLONESHOT) != 0 {
                return -(abi::EINVAL as i64);
            }
            let Some(w) = state.watches.get_mut(&(fd as i32)) else {
                return -(abi::ENOENT as i64);
            };
            *w = EpollWatch {
                events,
                data: u64::from_le_bytes(b[4..12].try_into().unwrap()),
            };
            0
        }
        x if x == abi::EPOLL_CTL_DEL as u64 => {
            if state.watches.remove(&(fd as i32)).is_some() {
                0
            } else {
                -(abi::ENOENT as i64)
            }
        }
        _ => -(abi::EINVAL as i64),
    }
}
pub(super) fn sys_epoll_wait(
    proc: &mut GuestProcess,
    host: &dyn Host,
    epfd: u64,
    events: u64,
    maxevents: u64,
    timeout: u64,
) -> i64 {
    if maxevents == 0 || maxevents > 1024 {
        return -(abi::EINVAL as i64);
    }
    let state = match proc.fds.get(epfd as i32) {
        Some(GuestFd::Epoll(s)) => s.clone(),
        _ => return -(abi::EBADF as i64),
    };
    let watches = state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .watches
        .clone();
    let mut files = Vec::new();
    let mut ids = Vec::new();
    for (&fd, watch) in &watches {
        let Some(gfd) = proc.fds.get(fd) else {
            continue;
        };
        let source = match gfd {
            GuestFd::Host(f) | GuestFd::PipeRead(f) | GuestFd::PipeWrite(f) => f,
            _ => continue,
        };
        let Ok(copy) = host.dup_file(source) else {
            continue;
        };
        files.push(copy);
        ids.push((fd, *watch));
    }
    let mut pfds = files
        .iter()
        .zip(ids.iter())
        .map(|(file, (_, watch))| vela_sys::HostPollFd {
            file,
            events: (watch.events & 0xffff) as u16,
            revents: 0,
        })
        .collect::<Vec<_>>();
    let timeout_i = if timeout == u64::MAX {
        -1
    } else {
        match i64::try_from(timeout) {
            Ok(v) if (0..=i32::MAX as i64).contains(&v) => v as i32,
            _ => return -(abi::EINVAL as i64),
        }
    };
    if let Err(e) = host.poll(&mut pfds, timeout_i) {
        return host_err(e);
    }
    let mut out = 0;
    for (i, pfd) in pfds.iter().enumerate() {
        if pfd.revents == 0 || out >= maxevents as usize {
            continue;
        }
        let (_fd, watch) = ids[i];
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&(pfd.revents as u32).to_le_bytes());
        b[4..12].copy_from_slice(&watch.data.to_le_bytes());
        let offset = match (out as u64).checked_mul(12) {
            Some(v) => v,
            None => return -(abi::EFAULT as i64),
        };
        let dst = match events.checked_add(offset) {
            Some(v) => v,
            None => return -(abi::EFAULT as i64),
        };
        if let Err(e) = write_guest(proc, dst, &b) {
            return -(e as i64);
        }
        out += 1;
    }
    out as i64
}

pub(super) fn sys_epoll_pwait(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let mask_ptr = a[4];
    let mask_len = a[5];
    let old = proc.signals.blocked;
    if mask_ptr != 0 {
        if mask_len != 8 {
            return -(abi::EINVAL as i64);
        }
        let raw = match read_guest(proc, mask_ptr, 8) {
            Ok(v) => v,
            Err(e) => return -(e as i64),
        };
        proc.signals.blocked = u64::from_le_bytes(raw.try_into().unwrap());
    }
    let result = sys_epoll_wait(proc, host, a[0], a[1], a[2], a[3]);
    proc.signals.blocked = old;
    result
}
