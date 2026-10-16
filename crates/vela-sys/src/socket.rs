//! Nonblocking socket operations. The runtime owns interruptible waits;
//! no OS call below waits while holding shared metadata.

use crate::HostError;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::sync::{Arc, Mutex};

const PAIR_CAPACITY: usize = 64 * 1024;

#[derive(Debug, Default)]
struct PairState {
    queues: [VecDeque<u8>; 2],
    read_closed: [bool; 2],
    write_closed: [bool; 2],
}

#[derive(Debug)]
enum Backend {
    Native(Socket),
    Pair {
        bus: Arc<Mutex<PairState>>,
        side: usize,
    },
}

#[derive(Debug, Default)]
struct Metadata {
    nonblock: bool,
    connecting: bool,
    connected: bool,
    connect_failed: bool,
    error: i32,
    receive_timeout_us: u64,
    send_timeout_us: u64,
}

#[derive(Debug)]
struct SocketInner {
    backend: Backend,
    domain: u16,
    kind: u32,
    meta: Mutex<Metadata>,
}

impl Drop for SocketInner {
    fn drop(&mut self) {
        if let Backend::Pair { bus, side } = &self.backend {
            let mut state = bus.lock().unwrap_or_else(|p| p.into_inner());
            state.read_closed[*side] = true;
            state.write_closed[*side] = true;
        }
    }
}

#[derive(Clone, Debug)]
pub struct HostSocket(Arc<SocketInner>);

impl HostSocket {
    pub fn new(domain: u16, kind: u32, nonblock: bool) -> Result<Self, HostError> {
        let domain_value = match domain {
            crate::AF_INET => Domain::IPV4,
            crate::AF_INET6 => Domain::IPV6,
            _ => return Err(HostError::Other(crate::EAFNOSUPPORT)),
        };
        let (socket_type, protocol) = match kind & crate::SOCK_TYPE_MASK {
            crate::SOCK_STREAM => (Type::STREAM, Protocol::TCP),
            crate::SOCK_DGRAM => (Type::DGRAM, Protocol::UDP),
            _ => return Err(HostError::Invalid),
        };
        let socket = Socket::new(domain_value, socket_type, Some(protocol)).map_err(map_io)?;
        socket.set_nonblocking(true).map_err(map_io)?;
        Ok(Self(Arc::new(SocketInner {
            backend: Backend::Native(socket),
            domain,
            kind: kind & crate::SOCK_TYPE_MASK,
            meta: Mutex::new(Metadata {
                nonblock,
                ..Metadata::default()
            }),
        })))
    }

    pub fn pair() -> (Self, Self) {
        let bus = Arc::new(Mutex::new(PairState::default()));
        let endpoint = |side| {
            Self(Arc::new(SocketInner {
                backend: Backend::Pair {
                    bus: bus.clone(),
                    side,
                },
                domain: crate::AF_UNIX,
                kind: crate::SOCK_STREAM,
                meta: Mutex::new(Metadata::default()),
            }))
        };
        (endpoint(0), endpoint(1))
    }

    fn native(&self) -> Result<&Socket, HostError> {
        match &self.0.backend {
            Backend::Native(socket) => Ok(socket),
            _ => Err(HostError::Other(crate::EOPNOTSUPP)),
        }
    }

    pub fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
    pub fn nonblocking(&self) -> bool {
        self.0
            .meta
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .nonblock
    }
    pub fn timeout_us(&self, receive: bool) -> u64 {
        let meta = self.0.meta.lock().unwrap_or_else(|p| p.into_inner());
        if receive {
            meta.receive_timeout_us
        } else {
            meta.send_timeout_us
        }
    }
    pub fn set_timeout_us(&self, receive: bool, value: u64) {
        let mut meta = self.0.meta.lock().unwrap_or_else(|p| p.into_inner());
        if receive {
            meta.receive_timeout_us = value;
        } else {
            meta.send_timeout_us = value;
        }
    }

    pub fn bind(&self, addr: &[u8]) -> Result<(), HostError> {
        self.native()?
            .bind(&parse_sockaddr(addr, self.0.domain)?.into())
            .map_err(map_io)
    }
    pub fn listen(&self, backlog: i32) -> Result<(), HostError> {
        self.native()?.listen(backlog.max(0)).map_err(map_io)
    }
    pub fn connect(&self, addr: &[u8]) -> Result<(), HostError> {
        let target = parse_sockaddr(addr, self.0.domain)?;
        let mut meta = self.0.meta.lock().unwrap_or_else(|p| p.into_inner());
        if meta.connecting {
            return Err(HostError::Other(crate::EALREADY));
        }
        if meta.connected && self.0.kind == crate::SOCK_STREAM {
            return Err(HostError::Other(crate::EISCONN));
        }
        meta.connect_failed = false;
        meta.error = 0;
        match self.native()?.connect(&target.into()) {
            Ok(()) => {
                meta.connected = true;
                Ok(())
            }
            Err(error) => {
                let mapped = map_io(error);
                if mapped == HostError::Other(crate::EAGAIN)
                    || mapped == HostError::Other(crate::EINPROGRESS)
                {
                    meta.connecting = true;
                    Err(HostError::Other(crate::EINPROGRESS))
                } else {
                    Err(mapped)
                }
            }
        }
    }
    pub fn accept(&self) -> Result<Self, HostError> {
        let (socket, _) = self.native()?.accept().map_err(map_io)?;
        socket.set_nonblocking(true).map_err(map_io)?;
        Ok(Self(Arc::new(SocketInner {
            backend: Backend::Native(socket),
            domain: self.0.domain,
            kind: self.0.kind,
            meta: Mutex::new(Metadata {
                connected: true,
                ..Metadata::default()
            }),
        })))
    }
    pub fn send(&self, data: &[u8], flags: u32) -> Result<usize, HostError> {
        self.check_flags(flags, false)?;
        match &self.0.backend {
            Backend::Native(socket) => socket.send(data).map_err(map_io),
            Backend::Pair { bus, side } => {
                if data.is_empty() {
                    return Ok(0);
                }
                let mut state = bus.lock().unwrap_or_else(|p| p.into_inner());
                if state.write_closed[*side] || state.read_closed[1 - side] {
                    return Err(HostError::Other(crate::EPIPE));
                }
                let queue = &mut state.queues[1 - side];
                let count = data.len().min(PAIR_CAPACITY - queue.len());
                if count == 0 {
                    return Err(HostError::Other(crate::EAGAIN));
                }
                queue.extend(&data[..count]);
                Ok(count)
            }
        }
    }
    pub fn send_to(&self, data: &[u8], addr: &[u8], flags: u32) -> Result<usize, HostError> {
        self.check_flags(flags, false)?;
        self.native()?
            .send_to(data, &parse_sockaddr(addr, self.0.domain)?.into())
            .map_err(map_io)
    }
    pub fn recv(&self, data: &mut [u8], flags: u32) -> Result<usize, HostError> {
        self.recv_from(data, flags).map(|(n, _)| n)
    }
    pub fn recv_from(&self, data: &mut [u8], flags: u32) -> Result<(usize, Vec<u8>), HostError> {
        self.check_flags(flags, true)?;
        match &self.0.backend {
            Backend::Pair { bus, side } => {
                if data.is_empty() {
                    return Ok((0, Vec::new()));
                }
                let mut state = bus.lock().unwrap_or_else(|p| p.into_inner());
                if state.read_closed[*side] {
                    return Ok((0, Vec::new()));
                }
                let eof = state.write_closed[1 - side];
                let queue = &mut state.queues[*side];
                if queue.is_empty() && !eof {
                    return Err(HostError::Other(crate::EAGAIN));
                }
                let count = data.len().min(queue.len());
                for (out, byte) in data[..count].iter_mut().zip(queue.iter()) {
                    *out = *byte;
                }
                if flags & crate::MSG_PEEK == 0 {
                    queue.drain(..count);
                }
                Ok((count, Vec::new()))
            }
            Backend::Native(socket) => {
                // Receive into an owned datagram buffer so Windows truncation
                // cannot discard bytes before MSG_TRUNC reports the full size.
                let mut payload = vec![
                    std::mem::MaybeUninit::uninit();
                    if self.0.kind == crate::SOCK_DGRAM {
                        65536
                    } else {
                        data.len()
                    }
                ];
                let host_flags = if flags & crate::MSG_PEEK != 0 { 2 } else { 0 };
                let (received, addr) = socket
                    .recv_from_with_flags(&mut payload, host_flags)
                    .map_err(map_io)?;
                let copied = data.len().min(received);
                // SAFETY: recv initialized exactly the first `received` bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        payload.as_ptr().cast::<u8>(),
                        data.as_mut_ptr(),
                        copied,
                    );
                }
                let count = if flags & crate::MSG_TRUNC != 0 && self.0.kind == crate::SOCK_DGRAM {
                    received
                } else {
                    copied
                };
                Ok((
                    count,
                    addr.as_socket().map(sockaddr_bytes).unwrap_or_default(),
                ))
            }
        }
    }
    fn check_flags(&self, flags: u32, receive: bool) -> Result<(), HostError> {
        let supported = crate::MSG_DONTWAIT
            | if receive {
                crate::MSG_PEEK | crate::MSG_TRUNC
            } else {
                crate::MSG_NOSIGNAL
            };
        if flags & !supported != 0 {
            Err(HostError::Other(crate::EOPNOTSUPP))
        } else {
            Ok(())
        }
    }
    pub fn shutdown(&self, how: u32) -> Result<(), HostError> {
        let direction = match how {
            0 => Shutdown::Read,
            1 => Shutdown::Write,
            2 => Shutdown::Both,
            _ => return Err(HostError::Invalid),
        };
        match &self.0.backend {
            Backend::Native(socket) => socket.shutdown(direction).map_err(map_io),
            Backend::Pair { bus, side } => {
                let mut state = bus.lock().unwrap_or_else(|p| p.into_inner());
                if how != 1 {
                    state.read_closed[*side] = true;
                    state.queues[*side].clear();
                }
                if how != 0 {
                    state.write_closed[*side] = true;
                }
                Ok(())
            }
        }
    }
    pub fn set_nonblocking(&self, enabled: bool) -> Result<(), HostError> {
        self.0
            .meta
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .nonblock = enabled;
        Ok(())
    }
    pub fn poll_ready(&self, events: u16) -> u16 {
        match &self.0.backend {
            Backend::Pair { bus, side } => {
                let state = bus.lock().unwrap_or_else(|p| p.into_inner());
                let mut ready = 0;
                if !state.queues[*side].is_empty()
                    || state.write_closed[1 - side]
                    || state.read_closed[*side]
                {
                    ready |= events & crate::POLLIN;
                }
                if !state.write_closed[*side]
                    && !state.read_closed[1 - side]
                    && state.queues[1 - side].len() < PAIR_CAPACITY
                {
                    ready |= events & crate::POLLOUT;
                }
                if state.write_closed[1 - side] {
                    ready |= crate::POLLRDHUP & events;
                }
                if state.read_closed[1 - side] && state.write_closed[1 - side] {
                    ready |= crate::POLLHUP;
                }
                ready
            }
            Backend::Native(socket) => {
                #[cfg(windows)]
                let mut ready = crate::windows::poll_socket(socket, events);
                #[cfg(not(windows))]
                let mut ready = {
                    let _ = socket;
                    crate::POLLERR
                };
                let mut meta = self.0.meta.lock().unwrap_or_else(|p| p.into_inner());
                if meta.connected
                    && self.0.kind == crate::SOCK_STREAM
                    && events & crate::POLLRDHUP != 0
                    && ready & (crate::POLLIN | crate::POLLHUP) != 0
                {
                    let mut byte = [std::mem::MaybeUninit::uninit(); 1];
                    if matches!(socket.peek(&mut byte), Ok(0)) {
                        ready |= crate::POLLRDHUP;
                    }
                }
                if meta.connecting {
                    match socket.take_error() {
                        Ok(Some(error)) => {
                            meta.error = errno_io(error);
                            meta.connect_failed = true;
                            ready |= crate::POLLERR | (events & crate::POLLOUT);
                        }
                        Ok(None)
                            if ready & crate::POLLOUT != 0
                                && ready & (crate::POLLERR | crate::POLLHUP) == 0 =>
                        {
                            meta.connected = true;
                        }
                        _ => {}
                    }
                    if meta.error != 0 || meta.connected {
                        meta.connecting = false;
                    }
                }
                if meta.error != 0 {
                    ready |= crate::POLLERR;
                }
                if meta.connect_failed {
                    ready |= crate::POLLHUP | (events & crate::POLLOUT);
                }
                ready
            }
        }
    }
    pub fn name(&self, peer: bool) -> Result<Vec<u8>, HostError> {
        match &self.0.backend {
            Backend::Pair { .. } => Ok(crate::AF_UNIX.to_le_bytes().to_vec()),
            Backend::Native(socket) => {
                let addr = if peer {
                    socket.peer_addr()
                } else {
                    socket.local_addr()
                }
                .map_err(map_io)?;
                addr.as_socket()
                    .map(sockaddr_bytes)
                    .ok_or(HostError::Invalid)
            }
        }
    }
    pub fn set_option(&self, level: u32, opt: u32, value: i32) -> Result<(), HostError> {
        match (level, opt) {
            (crate::SOL_SOCKET, crate::SO_REUSEADDR) => {
                self.native()?.set_reuse_address(value != 0).map_err(map_io)
            }
            (crate::IPPROTO_TCP, crate::TCP_NODELAY) => {
                self.native()?.set_nodelay(value != 0).map_err(map_io)
            }
            _ => Err(HostError::Other(crate::ENOPROTOOPT)),
        }
    }
    pub fn get_option(&self, level: u32, opt: u32) -> Result<i32, HostError> {
        match (level, opt) {
            (crate::SOL_SOCKET, crate::SO_ERROR) => {
                self.poll_ready(crate::POLLOUT);
                let mut meta = self.0.meta.lock().unwrap_or_else(|p| p.into_inner());
                if meta.connect_failed {
                    return Ok(std::mem::take(&mut meta.error));
                }
                if meta.error != 0 {
                    return Ok(std::mem::take(&mut meta.error));
                }
                match &self.0.backend {
                    Backend::Native(socket) => socket
                        .take_error()
                        .map(|e| e.map(errno_io).unwrap_or(0))
                        .map_err(map_io),
                    _ => Ok(0),
                }
            }
            (crate::SOL_SOCKET, crate::SO_REUSEADDR) => self
                .native()?
                .reuse_address()
                .map(i32::from)
                .map_err(map_io),
            (crate::IPPROTO_TCP, crate::TCP_NODELAY) => {
                self.native()?.nodelay().map(i32::from).map_err(map_io)
            }
            _ => Err(HostError::Other(crate::ENOPROTOOPT)),
        }
    }
    /// The descriptor owns an Arc; dropping the last reference releases it.
    pub fn close(&self) {}
}

fn parse_sockaddr(bytes: &[u8], domain: u16) -> Result<SocketAddr, HostError> {
    if bytes.len() < 2 {
        return Err(HostError::Invalid);
    }
    let family = u16::from_le_bytes(bytes[..2].try_into().unwrap());
    if family != domain {
        return Err(HostError::Other(crate::EAFNOSUPPORT));
    }
    match family {
        crate::AF_INET if bytes.len() >= 16 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
        )),
        crate::AF_INET6 if bytes.len() >= 28 => Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap()),
            u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
        ))),
        _ => Err(HostError::Invalid),
    }
}
fn sockaddr_bytes(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(addr) => {
            let mut b = vec![0; 16];
            b[..2].copy_from_slice(&crate::AF_INET.to_le_bytes());
            b[2..4].copy_from_slice(&addr.port().to_be_bytes());
            b[4..8].copy_from_slice(&addr.ip().octets());
            b
        }
        SocketAddr::V6(addr) => {
            let mut b = vec![0; 28];
            b[..2].copy_from_slice(&crate::AF_INET6.to_le_bytes());
            b[2..4].copy_from_slice(&addr.port().to_be_bytes());
            b[4..8].copy_from_slice(&addr.flowinfo().to_be_bytes());
            b[8..24].copy_from_slice(&addr.ip().octets());
            b[24..28].copy_from_slice(&addr.scope_id().to_le_bytes());
            b
        }
    }
}
fn errno_io(error: std::io::Error) -> i32 {
    use std::io::ErrorKind as K;
    match error.kind() {
        K::WouldBlock => crate::EAGAIN,
        K::Interrupted => crate::EINTR,
        K::ConnectionRefused => crate::ECONNREFUSED,
        K::ConnectionReset => crate::ECONNRESET,
        K::AddrInUse => crate::EADDRINUSE,
        K::NotConnected => crate::ENOTCONN,
        K::BrokenPipe => crate::EPIPE,
        K::TimedOut => crate::ETIMEDOUT,
        K::InvalidInput => crate::EINVAL,
        K::PermissionDenied => crate::EACCES,
        _ => match error.raw_os_error() {
            Some(10035) => crate::EAGAIN,
            Some(10036) => crate::EINPROGRESS,
            Some(10037) => crate::EALREADY,
            Some(10056) => crate::EISCONN,
            Some(10040) => crate::EMSGSIZE,
            Some(10047) => crate::EAFNOSUPPORT,
            Some(10049) => crate::EADDRNOTAVAIL,
            Some(10051) => crate::ENETUNREACH,
            Some(10053) => crate::ECONNABORTED,
            Some(10058) => crate::EPIPE,
            _ => crate::EIO,
        },
    }
}
fn map_io(error: std::io::Error) -> HostError {
    HostError::Other(errno_io(error))
}
