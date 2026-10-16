//! Socket and epoll syscall translation. All host networking stays behind
//! `vela_sys::HostFileOps`.

use crate::{
    host_err_to_errno, read_guest, validate_guest_write, write_guest, EpollState, EpollWatch,
    GuestFd, GuestProcess,
};
use std::sync::{Arc, Mutex};
use vela_abi as abi;
use vela_sys::{Host, HostError, HostFile, HostFileKind, HostSocket};

fn validate_address(proc: &GuestProcess, out: u64, lenp: u64) -> Result<usize, i64> {
    if out == 0 {
        return Ok(0);
    }
    validate_guest_write(proc, lenp, 4).map_err(|e| -(e as i64))?;
    let raw = read_guest(proc, lenp, 4).map_err(|e| -(e as i64))?;
    let capacity = u32::from_le_bytes(raw.try_into().unwrap()) as usize;
    validate_guest_write(proc, out, capacity.min(128)).map_err(|e| -(e as i64))?;
    Ok(capacity)
}

fn put_address(
    proc: &GuestProcess,
    out: u64,
    lenp: u64,
    capacity: usize,
    address: &[u8],
) -> Result<(), i64> {
    write_guest(proc, out, &address[..capacity.min(address.len())]).map_err(|e| -(e as i64))?;
    write_guest(proc, lenp, &(address.len() as u32).to_le_bytes()).map_err(|e| -(e as i64))
}

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

fn socket_err(proc: &mut GuestProcess, e: HostError, flags: u32) -> i64 {
    let errno = host_err_to_errno(&e);
    if errno == abi::EPIPE && flags & abi::MSG_NOSIGNAL == 0 {
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
    if domain as u32 != abi::AF_INET as u32 && domain as u32 != abi::AF_INET6 as u32 {
        return -(abi::EAFNOSUPPORT as i64);
    }
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
    proc.fds
        .update_flags(fd, |v| v | ((abi::O_RDWR as u32) << 8));
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
    if domain as u32 != abi::AF_UNIX as u32 {
        return -(abi::EAFNOSUPPORT as i64);
    }
    if validate_guest_write(proc, out, 8).is_err() {
        return -(abi::EFAULT as i64);
    }
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
    for fd in [fda, fdb] {
        proc.fds
            .update_flags(fd, |v| v | ((abi::O_RDWR as u32) << 8));
    }
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
pub(super) fn sys_accept(
    proc: &mut GuestProcess,
    host: &dyn Host,
    fd: u64,
    out: u64,
    lenp: u64,
    flags: u64,
) -> i64 {
    if flags & !(abi::SOCK_NONBLOCK as u64 | abi::SOCK_CLOEXEC as u64) != 0 {
        return -(abi::EINVAL as i64);
    }
    let capacity = match validate_address(proc, out, lenp) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    let s = match sock(proc, fd as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let accepted = match host.socket_accept(s) {
        Ok(s) => s,
        Err(e) => return host_err(e),
    };
    if out != 0 {
        let address = match host.socket_name(&accepted, true) {
            Ok(addr) => addr,
            Err(error) => return host_err(error),
        };
        if let Err(error) = put_address(proc, out, lenp, capacity, &address) {
            return error;
        }
    }
    if let Err(error) =
        host.socket_set_nonblocking(&accepted, flags & abi::SOCK_NONBLOCK as u64 != 0)
    {
        return host_err(error);
    }
    let n = proc
        .fds
        .alloc_fd(GuestFd::Host(HostFile(HostFileKind::Socket(accepted))));
    proc.fds
        .update_flags(n, |v| v | ((abi::O_RDWR as u32) << 8));
    if flags & abi::SOCK_CLOEXEC as u64 != 0 {
        proc.fds.update_flags(n, |v| v | 1);
    }
    if flags & abi::SOCK_NONBLOCK as u64 != 0 {
        proc.fds
            .update_flags(n, |v| v | ((abi::O_NONBLOCK as u32) << 8));
        if let Some(GuestFd::Host(HostFile(HostFileKind::Socket(s)))) = proc.fds.get(n) {
            if let Err(error) = host.socket_set_nonblocking(s, true) {
                return host_err(error);
            }
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
    if a[2] > 16 * 1024 * 1024 {
        return -(abi::EMSGSIZE as i64);
    }
    let s = match sock(proc, a[0] as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let data = match read_guest(proc, a[1], a[2] as usize) {
        Ok(d) => d.to_vec(),
        Err(e) => return -(e as i64),
    };
    if a[4] == 0 {
        match host.socket_send(s, &data, a[3] as u32) {
            Ok(n) => n as i64,
            Err(e) => socket_err(proc, e, a[3] as u32),
        }
    } else {
        let addr = match sockaddr(proc, a[4], a[5]) {
            Ok(a) => a,
            Err(e) => return e,
        };
        match host.socket_sendto(s, &data, &addr, a[3] as u32) {
            Ok(n) => n as i64,
            Err(e) => socket_err(proc, e, a[3] as u32),
        }
    }
}
pub(super) fn sys_recvfrom(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    if a[2] > 16 * 1024 * 1024 {
        return -(abi::EMSGSIZE as i64);
    }
    let capacity = match validate_address(proc, a[4], a[5]) {
        Ok(cap) => cap,
        Err(e) => return e,
    };
    if validate_guest_write(proc, a[1], a[2] as usize).is_err() {
        return -(abi::EFAULT as i64);
    }
    let s = match sock(proc, a[0] as i32) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut dst = vec![0; a[2] as usize];
    let (n, addr) = match host.socket_recvfrom(s, &mut dst, a[3] as u32) {
        Ok(v) => v,
        Err(e) => return host_err(e),
    };
    if let Err(error) = write_guest(proc, a[1], &dst[..n.min(dst.len())]) {
        return -(error as i64);
    }
    if a[4] != 0 {
        if let Err(error) = put_address(proc, a[4], a[5], capacity, &addr) {
            return error;
        }
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
    let name = u64::from_le_bytes(hdr[..8].try_into().unwrap());
    let name_len = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as u64;
    if u64::from_le_bytes(hdr[40..48].try_into().unwrap()) != 0 {
        return -(abi::EOPNOTSUPP as i64);
    }
    let address = if name != 0 {
        match sockaddr(proc, name, name_len) {
            Ok(addr) => Some(addr),
            Err(error) => return error,
        }
    } else {
        None
    };
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
        if len > 16 * 1024 * 1024 || payload.len() as u64 + len > 16 * 1024 * 1024 {
            return -(abi::E2BIG as i64);
        }
        let data = match read_guest(proc, base, len as usize) {
            Ok(d) => d,
            Err(e) => return -(e as i64),
        };
        payload.extend_from_slice(&data);
    }
    let socket = match sock(proc, fd as i32) {
        Ok(socket) => socket,
        Err(e) => return e,
    };
    let result = if let Some(address) = address {
        host.socket_sendto(socket, &payload, &address, flags as u32)
    } else {
        host.socket_send(socket, &payload, flags as u32)
    };
    match result {
        Ok(n) => n as i64,
        Err(e) => socket_err(proc, e, flags as u32),
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
        Ok(b) => b.to_vec(),
        Err(e) => return -(e as i64),
    };
    let iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let count = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let name = u64::from_le_bytes(hdr[..8].try_into().unwrap());
    let name_capacity = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as usize;
    if u64::from_le_bytes(hdr[40..48].try_into().unwrap()) != 0 {
        return -(abi::EOPNOTSUPP as i64);
    }
    if validate_guest_write(proc, msg, 56).is_err()
        || (name != 0 && validate_guest_write(proc, name, name_capacity.min(128)).is_err())
    {
        return -(abi::EFAULT as i64);
    }
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
        if len > 16 * 1024 * 1024 || total_len as u64 + len > 16 * 1024 * 1024 {
            return -(abi::E2BIG as i64);
        }
        buffers.push((base, len as usize));
        if validate_guest_write(proc, base, len as usize).is_err() {
            return -(abi::EFAULT as i64);
        }
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
    let (received, address) =
        match host.socket_recvfrom(socket, &mut payload, flags as u32 | abi::MSG_TRUNC) {
            Ok(n) => n,
            Err(e) => return host_err(e),
        };
    let mut copied = 0usize;
    for (base, len) in buffers {
        if copied >= received {
            break;
        }
        let n = len.min(received.min(payload.len()) - copied);
        if let Err(e) = write_guest(proc, base, &payload[copied..copied + n]) {
            return -(e as i64);
        }
        copied += n;
        if copied == payload.len() {
            break;
        }
    }
    if name != 0 {
        if let Err(error) = write_guest(proc, name, &address[..name_capacity.min(address.len())]) {
            return -(error as i64);
        }
    }
    let output_flags = if received > payload.len() {
        abi::MSG_TRUNC
    } else {
        0
    };
    for (offset, bytes) in [
        (8, (address.len() as u32).to_le_bytes().to_vec()),
        (40, 0u64.to_le_bytes().to_vec()),
        (48, output_flags.to_le_bytes().to_vec()),
    ] {
        if let Err(error) = write_guest(proc, msg + offset, &bytes) {
            return -(error as i64);
        }
    }
    if flags & abi::MSG_TRUNC as u64 != 0 {
        received as i64
    } else {
        copied as i64
    }
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
    let timeout = a[1] == abi::SOL_SOCKET as u64
        && (a[2] == abi::SO_RCVTIMEO as u64 || a[2] == abi::SO_SNDTIMEO as u64);
    let required = if timeout { 16 } else { 4 };
    if a[4] < required {
        return -(abi::EINVAL as i64);
    }
    let raw = match read_guest(proc, a[3], required as usize) {
        Ok(b) => b,
        Err(e) => return -(e as i64),
    };
    if timeout {
        let seconds = i64::from_le_bytes(raw[..8].try_into().unwrap());
        let micros = i64::from_le_bytes(raw[8..16].try_into().unwrap());
        if seconds < 0 || !(0..1_000_000).contains(&micros) {
            return -(abi::EINVAL as i64);
        }
        let Some(total) = (seconds as u64)
            .checked_mul(1_000_000)
            .and_then(|value| value.checked_add(micros as u64))
        else {
            return -(abi::EINVAL as i64);
        };
        s.set_timeout_us(a[2] == abi::SO_RCVTIMEO as u64, total);
        return 0;
    }
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
    if validate_guest_write(proc, a[4], 4).is_err() {
        return -(abi::EFAULT as i64);
    }
    let cap = match read_guest(proc, a[4], 4) {
        Ok(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
        Err(e) => return -(e as i64),
    };
    let timeout = a[1] == abi::SOL_SOCKET as u64
        && (a[2] == abi::SO_RCVTIMEO as u64 || a[2] == abi::SO_SNDTIMEO as u64);
    let needed = if timeout { 16 } else { 4 };
    if validate_guest_write(proc, a[3], cap.min(needed)).is_err() {
        return -(abi::EFAULT as i64);
    }
    let bytes = if timeout {
        let micros = s.timeout_us(a[2] == abi::SO_RCVTIMEO as u64);
        [
            (micros / 1_000_000).to_le_bytes(),
            (micros % 1_000_000).to_le_bytes(),
        ]
        .concat()
    } else {
        match host.socket_get_option(s, a[1] as u32, a[2] as u32) {
            Ok(value) => value.to_le_bytes().to_vec(),
            Err(error) => return host_err(error),
        }
    };
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
    match proc.fds.get(fd as i32) {
        Some(GuestFd::Epoll(_)) => return -(abi::EINVAL as i64),
        Some(GuestFd::Host(HostFile(HostFileKind::Socket(_))))
        | Some(GuestFd::PipeRead(_))
        | Some(GuestFd::PipeWrite(_)) => {}
        _ => return -(abi::EPERM as i64),
    }
    let key = (fd as i32, proc.fds.identity(fd as i32).unwrap());
    let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
    match op {
        x if x == abi::EPOLL_CTL_ADD as u64 => {
            if state.watches.contains_key(&key) {
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
            if events
                & !(abi::EPOLLIN | abi::EPOLLOUT | abi::EPOLLERR | abi::EPOLLHUP | abi::EPOLLRDHUP)
                != 0
            {
                return -(abi::EINVAL as i64);
            }
            state.watches.insert(
                key,
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
            if events
                & !(abi::EPOLLIN | abi::EPOLLOUT | abi::EPOLLERR | abi::EPOLLHUP | abi::EPOLLRDHUP)
                != 0
            {
                return -(abi::EINVAL as i64);
            }
            let Some(w) = state.watches.get_mut(&key) else {
                return -(abi::ENOENT as i64);
            };
            *w = EpollWatch {
                events,
                data: u64::from_le_bytes(b[4..12].try_into().unwrap()),
            };
            0
        }
        x if x == abi::EPOLL_CTL_DEL as u64 => {
            if state.watches.remove(&key).is_some() {
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
    let cursor = state.lock().unwrap_or_else(|p| p.into_inner()).cursor;
    let ordered = watches.iter().collect::<Vec<_>>();
    for index in 0..ordered.len() {
        let (&(fd, identity), watch) = ordered[(index + cursor) % ordered.len()];
        let Some(gfd) = proc.fds.source_for_identity(identity) else {
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
            events: (watch.events & (abi::EPOLLIN | abi::EPOLLOUT | abi::EPOLLRDHUP)) as u16,
            revents: 0,
        })
        .collect::<Vec<_>>();
    let timeout_i = if proc.nonblocking_step {
        0
    } else if timeout == u64::MAX {
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
    let mut last = 0;
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
        last = i + 1;
    }
    if !ordered.is_empty() && last != 0 {
        state.lock().unwrap_or_else(|p| p.into_inner()).cursor = (cursor + last) % ordered.len();
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
