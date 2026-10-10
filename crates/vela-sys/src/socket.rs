//! Platform-neutral socket state. Windows uses the standard Winsock-backed
//! `std::net` objects; the runtime only sees this small safe contract.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::{Arc, Condvar, Mutex};

use crate::HostError;

#[derive(Debug)]
pub(crate) struct PairBus {
    a_to_b: Mutex<VecDeque<u8>>,
    b_to_a: Mutex<VecDeque<u8>>,
    open_a: Mutex<bool>,
    open_b: Mutex<bool>,
    wake: Condvar,
}

#[derive(Debug)]
pub(crate) enum SocketState {
    Unbound {
        domain: u16,
        kind: u32,
        nonblock: bool,
        reuseaddr: bool,
        nodelay: bool,
    },
    Listener {
        listener: TcpListener,
        nonblock: bool,
        pending: VecDeque<TcpStream>,
    },
    Stream {
        stream: TcpStream,
        nonblock: bool,
    },
    Datagram {
        socket: UdpSocket,
        nonblock: bool,
    },
    Pair {
        bus: Arc<PairBus>,
        side_a: bool,
        nonblock: bool,
    },
    Closed,
}

#[derive(Clone, Debug)]
pub struct HostSocket(pub(crate) Arc<Mutex<SocketState>>);

impl HostSocket {
    pub fn new(domain: u16, kind: u32, nonblock: bool) -> Self {
        Self(Arc::new(Mutex::new(SocketState::Unbound {
            domain,
            kind: kind & crate::SOCK_TYPE_MASK,
            nonblock,
            reuseaddr: false,
            nodelay: false,
        })))
    }

    pub fn pair() -> (Self, Self) {
        let bus = Arc::new(PairBus {
            a_to_b: Mutex::new(VecDeque::new()),
            b_to_a: Mutex::new(VecDeque::new()),
            open_a: Mutex::new(true),
            open_b: Mutex::new(true),
            wake: Condvar::new(),
        });
        (
            Self(Arc::new(Mutex::new(SocketState::Pair {
                bus: bus.clone(),
                side_a: true,
                nonblock: false,
            }))),
            Self(Arc::new(Mutex::new(SocketState::Pair {
                bus,
                side_a: false,
                nonblock: false,
            }))),
        )
    }

    pub fn bind(&self, addr: &[u8]) -> Result<(), HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        let (domain, kind, nonblock) = match &*state {
            SocketState::Unbound {
                domain,
                kind,
                nonblock,
                ..
            } => (*domain, *kind, *nonblock),
            _ => return Err(HostError::Invalid),
        };
        let socket_addr = parse_sockaddr(addr, domain)?;
        match kind {
            crate::SOCK_STREAM => {
                let listener = TcpListener::bind(socket_addr).map_err(map_io)?;
                listener.set_nonblocking(nonblock).map_err(map_io)?;
                *state = SocketState::Listener {
                    listener,
                    nonblock,
                    pending: VecDeque::new(),
                };
            }
            crate::SOCK_DGRAM => {
                let socket = UdpSocket::bind(socket_addr).map_err(map_io)?;
                socket.set_nonblocking(nonblock).map_err(map_io)?;
                *state = SocketState::Datagram { socket, nonblock };
            }
            _ => return Err(HostError::Invalid),
        }
        Ok(())
    }

    pub fn listen(&self, _backlog: i32) -> Result<(), HostError> {
        let state = self.0.lock().map_err(|_| HostError::Invalid)?;
        matches!(*state, SocketState::Listener { .. })
            .then_some(())
            .ok_or(HostError::Invalid)
    }

    pub fn connect(&self, addr: &[u8]) -> Result<(), HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        let (domain, kind, nonblock, nodelay) = match &*state {
            SocketState::Unbound {
                domain,
                kind,
                nonblock,
                nodelay,
                ..
            } => (*domain, *kind, *nonblock, *nodelay),
            _ => return Err(HostError::Invalid),
        };
        let socket_addr = parse_sockaddr(addr, domain)?;
        match kind {
            crate::SOCK_STREAM => {
                let stream = TcpStream::connect(socket_addr).map_err(map_io)?;
                stream.set_nonblocking(nonblock).map_err(map_io)?;
                stream.set_nodelay(nodelay).ok();
                *state = SocketState::Stream { stream, nonblock };
            }
            crate::SOCK_DGRAM => {
                let bind_addr: SocketAddr = if socket_addr.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                let socket = UdpSocket::bind(bind_addr).map_err(map_io)?;
                socket.connect(socket_addr).map_err(map_io)?;
                socket.set_nonblocking(nonblock).map_err(map_io)?;
                *state = SocketState::Datagram { socket, nonblock };
            }
            _ => return Err(HostError::Invalid),
        }
        Ok(())
    }

    pub fn accept(&self) -> Result<Self, HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        let SocketState::Listener {
            listener,
            nonblock,
            pending,
        } = &mut *state
        else {
            return Err(HostError::Invalid);
        };
        let stream = if let Some(stream) = pending.pop_front() {
            stream
        } else {
            let (stream, _) = listener.accept().map_err(map_io)?;
            stream
        };
        stream.set_nonblocking(*nonblock).map_err(map_io)?;
        Ok(Self(Arc::new(Mutex::new(SocketState::Stream {
            stream,
            nonblock: *nonblock,
        }))))
    }

    pub fn send(&self, data: &[u8], flags: u32) -> Result<usize, HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        match &mut *state {
            SocketState::Stream { stream, nonblock } => {
                write_stream(stream, *nonblock || flags & crate::MSG_DONTWAIT != 0, data)
            }
            SocketState::Datagram { socket, nonblock } => {
                send_datagram(socket, *nonblock || flags & crate::MSG_DONTWAIT != 0, data)
            }
            SocketState::Pair {
                bus,
                side_a,
                nonblock,
            } => pair_send(
                bus,
                *side_a,
                *nonblock || flags & crate::MSG_DONTWAIT != 0,
                data,
            ),
            _ => Err(HostError::Other(crate::ENOTCONN)),
        }
    }

    pub fn send_to(&self, data: &[u8], addr: &[u8], flags: u32) -> Result<usize, HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        match &mut *state {
            SocketState::Datagram { socket, .. } => socket
                .send_to(
                    data,
                    parse_sockaddr(addr, crate::AF_INET).map_err(|_| HostError::Invalid)?,
                )
                .map_err(map_io),
            SocketState::Unbound {
                domain,
                kind: crate::SOCK_DGRAM,
                nonblock,
                ..
            } => {
                let destination = parse_sockaddr(addr, *domain)?;
                let bind_addr: SocketAddr = if destination.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                let is_nonblock = *nonblock;
                let socket = UdpSocket::bind(bind_addr).map_err(map_io)?;
                socket.set_nonblocking(is_nonblock).map_err(map_io)?;
                let sent = if is_nonblock || flags & crate::MSG_DONTWAIT != 0 {
                    let probe = socket.try_clone().map_err(map_io)?;
                    probe.set_nonblocking(true).map_err(map_io)?;
                    probe.send_to(data, destination).map_err(map_io)?
                } else {
                    socket.send_to(data, destination).map_err(map_io)?
                };
                *state = SocketState::Datagram {
                    socket,
                    nonblock: is_nonblock,
                };
                Ok(sent)
            }
            SocketState::Pair {
                bus,
                side_a,
                nonblock,
            } => pair_send(
                bus,
                *side_a,
                *nonblock || flags & crate::MSG_DONTWAIT != 0,
                data,
            ),
            _ => Err(HostError::Other(crate::ENOTCONN)),
        }
    }

    pub fn recv(&self, buf: &mut [u8], flags: u32) -> Result<usize, HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        match &mut *state {
            SocketState::Stream { stream, nonblock } => {
                read_stream(stream, *nonblock || flags & crate::MSG_DONTWAIT != 0, buf)
            }
            SocketState::Datagram { socket, nonblock } => {
                recv_datagram(socket, *nonblock || flags & crate::MSG_DONTWAIT != 0, buf)
            }
            SocketState::Pair {
                bus,
                side_a,
                nonblock,
            } => pair_recv(
                bus,
                *side_a,
                *nonblock || flags & crate::MSG_DONTWAIT != 0,
                buf,
            ),
            _ => Err(HostError::Other(crate::ENOTCONN)),
        }
    }

    pub fn recv_from(&self, buf: &mut [u8], flags: u32) -> Result<(usize, Vec<u8>), HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        match &mut *state {
            SocketState::Stream { stream, nonblock } => {
                read_stream(stream, *nonblock || flags & crate::MSG_DONTWAIT != 0, buf)
                    .map(|n| (n, Vec::new()))
            }
            SocketState::Datagram { socket, nonblock } => {
                let (n, addr) =
                    recv_datagram_from(socket, *nonblock || flags & crate::MSG_DONTWAIT != 0, buf)?;
                Ok((n, sockaddr_bytes(addr)))
            }
            SocketState::Pair {
                bus,
                side_a,
                nonblock,
            } => pair_recv(
                bus,
                *side_a,
                *nonblock || flags & crate::MSG_DONTWAIT != 0,
                buf,
            )
            .map(|n| (n, Vec::new())),
            _ => Err(HostError::Other(crate::ENOTCONN)),
        }
    }

    pub fn shutdown(&self, how: u32) -> Result<(), HostError> {
        let state = self.0.lock().map_err(|_| HostError::Invalid)?;
        if let SocketState::Stream { stream, .. } = &*state {
            stream
                .shutdown(match how {
                    0 => Shutdown::Read,
                    1 => Shutdown::Write,
                    2 => Shutdown::Both,
                    _ => return Err(HostError::Invalid),
                })
                .map_err(map_io)
        } else {
            Ok(())
        }
    }

    pub fn set_nonblocking(&self, enabled: bool) -> Result<(), HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        match &mut *state {
            SocketState::Unbound { nonblock, .. }
            | SocketState::Listener { nonblock, .. }
            | SocketState::Stream { nonblock, .. }
            | SocketState::Datagram { nonblock, .. }
            | SocketState::Pair { nonblock, .. } => *nonblock = enabled,
            SocketState::Closed => return Err(HostError::Invalid),
        }
        match &mut *state {
            SocketState::Listener { listener, .. } => {
                listener.set_nonblocking(enabled).map_err(map_io)
            }
            SocketState::Stream { stream, .. } => stream.set_nonblocking(enabled).map_err(map_io),
            SocketState::Datagram { socket, .. } => socket.set_nonblocking(enabled).map_err(map_io),
            _ => Ok(()),
        }
    }

    pub fn poll_ready(&self, events: u16) -> u16 {
        let mut state = match self.0.lock() {
            Ok(s) => s,
            Err(_) => return crate::POLLERR,
        };
        let mut out = 0;
        match &mut *state {
            SocketState::Listener {
                listener,
                nonblock,
                pending,
            } => {
                if events & crate::POLLIN != 0 {
                    if !pending.is_empty() {
                        out |= crate::POLLIN;
                    } else if let Ok(probe) = listener.try_clone() {
                        let _ = probe.set_nonblocking(true);
                        match probe.accept() {
                            Ok((stream, _)) => {
                                let _ = stream.set_nonblocking(*nonblock);
                                pending.push_back(stream);
                                out |= crate::POLLIN;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => out |= crate::POLLERR,
                        }
                        let _ = listener.set_nonblocking(*nonblock);
                    }
                }
            }
            SocketState::Stream { stream, .. } => {
                if events & crate::POLLIN != 0 {
                    match peek_stream(stream) {
                        Ok(_) => out |= crate::POLLIN,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => out |= crate::POLLHUP,
                    }
                }
                if events & crate::POLLOUT != 0 {
                    out |= crate::POLLOUT;
                }
            }
            SocketState::Datagram { socket, .. } => {
                if events & crate::POLLIN != 0 {
                    match peek_datagram(socket) {
                        Ok(_) => out |= crate::POLLIN,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => out |= crate::POLLERR,
                    }
                }
                if events & crate::POLLOUT != 0 {
                    out |= crate::POLLOUT;
                }
            }
            SocketState::Pair { bus, side_a, .. } => {
                let q = if *side_a { &bus.b_to_a } else { &bus.a_to_b };
                if events & crate::POLLIN != 0 && !q.lock().map(|q| q.is_empty()).unwrap_or(true) {
                    out |= crate::POLLIN;
                }
                if events & crate::POLLOUT != 0 {
                    out |= crate::POLLOUT;
                }
                if !bus_open(bus, !*side_a) {
                    out |= crate::POLLHUP;
                }
            }
            _ => out |= crate::POLLERR,
        }
        out
    }

    pub fn name(&self, peer: bool) -> Result<Vec<u8>, HostError> {
        let state = self.0.lock().map_err(|_| HostError::Invalid)?;
        let addr = match &*state {
            SocketState::Listener { listener, .. } => listener.local_addr().map_err(map_io)?,
            SocketState::Stream { stream, .. } => {
                if peer {
                    stream.peer_addr().map_err(map_io)?
                } else {
                    stream.local_addr().map_err(map_io)?
                }
            }
            SocketState::Datagram { socket, .. } => {
                if peer {
                    socket.peer_addr().map_err(map_io)?
                } else {
                    socket.local_addr().map_err(map_io)?
                }
            }
            _ => return Err(HostError::Invalid),
        };
        Ok(sockaddr_bytes(addr))
    }

    pub fn set_option(&self, level: u32, opt: u32, value: i32) -> Result<(), HostError> {
        let mut state = self.0.lock().map_err(|_| HostError::Invalid)?;
        match (&mut *state, level, opt) {
            (SocketState::Unbound { reuseaddr, .. }, crate::SOL_SOCKET, crate::SO_REUSEADDR) => {
                *reuseaddr = value != 0;
                Ok(())
            }
            (SocketState::Unbound { nodelay, .. }, crate::IPPROTO_TCP, crate::TCP_NODELAY) => {
                *nodelay = value != 0;
                Ok(())
            }
            (SocketState::Stream { stream, .. }, crate::IPPROTO_TCP, crate::TCP_NODELAY) => {
                stream.set_nodelay(value != 0).map_err(map_io)
            }
            (SocketState::Unbound { .. }, crate::SOL_SOCKET, crate::SO_RCVTIMEO)
            | (SocketState::Unbound { .. }, crate::SOL_SOCKET, crate::SO_SNDTIMEO)
            | (SocketState::Stream { .. }, crate::SOL_SOCKET, crate::SO_RCVTIMEO)
            | (SocketState::Stream { .. }, crate::SOL_SOCKET, crate::SO_SNDTIMEO)
            | (SocketState::Datagram { .. }, crate::SOL_SOCKET, crate::SO_RCVTIMEO)
            | (SocketState::Datagram { .. }, crate::SOL_SOCKET, crate::SO_SNDTIMEO)
            | (SocketState::Unbound { .. }, crate::SOL_SOCKET, crate::SO_ERROR)
            | (SocketState::Stream { .. }, crate::SOL_SOCKET, crate::SO_ERROR)
            | (SocketState::Datagram { .. }, crate::SOL_SOCKET, crate::SO_ERROR) => Ok(()),
            _ => Err(HostError::Other(crate::ENOPROTOOPT)),
        }
    }

    pub fn get_option(&self, level: u32, opt: u32) -> Result<i32, HostError> {
        let state = self.0.lock().map_err(|_| HostError::Invalid)?;
        match (level, opt) {
            (crate::SOL_SOCKET, crate::SO_ERROR)
            | (crate::SOL_SOCKET, crate::SO_RCVTIMEO)
            | (crate::SOL_SOCKET, crate::SO_SNDTIMEO) => Ok(0),
            (crate::SOL_SOCKET, crate::SO_REUSEADDR) => Ok(match &*state {
                SocketState::Unbound { reuseaddr, .. } => i32::from(*reuseaddr),
                _ => 0,
            }),
            (crate::IPPROTO_TCP, crate::TCP_NODELAY) => Ok(match &*state {
                SocketState::Unbound { nodelay, .. } => i32::from(*nodelay),
                _ => 0,
            }),
            _ => Err(HostError::Other(crate::ENOPROTOOPT)),
        }
    }

    pub fn close(&self) {
        if Arc::strong_count(&self.0) > 1 {
            return;
        }
        if let Ok(mut state) = self.0.lock() {
            if let SocketState::Pair { bus, side_a, .. } = &*state {
                let slot = if *side_a { &bus.open_a } else { &bus.open_b };
                if let Ok(mut open) = slot.lock() {
                    *open = false;
                }
                bus.wake.notify_all();
            }
            *state = SocketState::Closed;
        }
    }
}

fn bus_open(bus: &PairBus, side_a: bool) -> bool {
    let slot = if side_a { &bus.open_a } else { &bus.open_b };
    slot.lock().map(|open| *open).unwrap_or(false)
}

fn write_stream(stream: &mut TcpStream, nonblock: bool, data: &[u8]) -> Result<usize, HostError> {
    if nonblock {
        let probe = stream.try_clone().map_err(map_io)?;
        probe.set_nonblocking(true).map_err(map_io)?;
        (&probe).write(data).map_err(map_io)
    } else {
        stream.write(data).map_err(map_io)
    }
}

fn read_stream(
    stream: &mut TcpStream,
    nonblock: bool,
    data: &mut [u8],
) -> Result<usize, HostError> {
    if nonblock {
        let probe = stream.try_clone().map_err(map_io)?;
        probe.set_nonblocking(true).map_err(map_io)?;
        (&probe).read(data).map_err(map_io)
    } else {
        stream.read(data).map_err(map_io)
    }
}

fn send_datagram(socket: &mut UdpSocket, nonblock: bool, data: &[u8]) -> Result<usize, HostError> {
    if nonblock {
        let probe = socket.try_clone().map_err(map_io)?;
        probe.set_nonblocking(true).map_err(map_io)?;
        probe.send(data).map_err(map_io)
    } else {
        socket.send(data).map_err(map_io)
    }
}

fn recv_datagram(
    socket: &mut UdpSocket,
    nonblock: bool,
    data: &mut [u8],
) -> Result<usize, HostError> {
    if nonblock {
        let probe = socket.try_clone().map_err(map_io)?;
        probe.set_nonblocking(true).map_err(map_io)?;
        probe.recv(data).map_err(map_io)
    } else {
        socket.recv(data).map_err(map_io)
    }
}

fn recv_datagram_from(
    socket: &mut UdpSocket,
    nonblock: bool,
    data: &mut [u8],
) -> Result<(usize, SocketAddr), HostError> {
    if nonblock {
        let probe = socket.try_clone().map_err(map_io)?;
        probe.set_nonblocking(true).map_err(map_io)?;
        probe.recv_from(data).map_err(map_io)
    } else {
        socket.recv_from(data).map_err(map_io)
    }
}

fn peek_stream(stream: &TcpStream) -> std::io::Result<usize> {
    let probe = stream.try_clone()?;
    probe.set_nonblocking(true)?;
    let mut b = [0u8; 1];
    probe.peek(&mut b)
}

fn peek_datagram(socket: &UdpSocket) -> std::io::Result<(usize, SocketAddr)> {
    let probe = socket.try_clone()?;
    probe.set_nonblocking(true)?;
    let mut b = [0u8; 1];
    probe.peek_from(&mut b)
}

fn pair_send(bus: &PairBus, side_a: bool, nonblock: bool, data: &[u8]) -> Result<usize, HostError> {
    let open = if side_a { &bus.open_b } else { &bus.open_a };
    if !*open.lock().map_err(|_| HostError::Invalid)? {
        return Err(HostError::Other(crate::EPIPE));
    }
    let q = if side_a { &bus.a_to_b } else { &bus.b_to_a };
    let _ = nonblock;
    q.lock()
        .map_err(|_| HostError::Invalid)?
        .extend(data.iter().copied());
    bus.wake.notify_all();
    Ok(data.len())
}

fn pair_recv(
    bus: &PairBus,
    side_a: bool,
    nonblock: bool,
    out: &mut [u8],
) -> Result<usize, HostError> {
    let q = if side_a { &bus.b_to_a } else { &bus.a_to_b };
    let mut q = q.lock().map_err(|_| HostError::Invalid)?;
    if q.is_empty() && !bus_open(bus, !side_a) {
        return Ok(0);
    }
    if q.is_empty() && !nonblock {
        q = bus.wake.wait(q).map_err(|_| HostError::Invalid)?;
    }
    if q.is_empty() {
        if !bus_open(bus, !side_a) {
            return Ok(0);
        }
        return Err(HostError::Other(crate::EAGAIN));
    }
    let n = out.len().min(q.len());
    for dst in &mut out[..n] {
        *dst = q.pop_front().unwrap();
    }
    Ok(n)
}

fn parse_sockaddr(bytes: &[u8], domain: u16) -> Result<SocketAddr, HostError> {
    if bytes.len() < 2 {
        return Err(HostError::Invalid);
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    if family != domain && !(domain == crate::AF_INET && family == 0) {
        return Err(HostError::Invalid);
    }
    match family {
        crate::AF_INET => {
            if bytes.len() < 8 {
                return Err(HostError::Invalid);
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let ip = Ipv4Addr::from(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        crate::AF_INET6 => {
            if bytes.len() < 28 {
                return Err(HostError::Invalid);
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[8..24]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => Err(HostError::Unimplemented),
    }
}

fn sockaddr_bytes(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(a) => {
            let mut b = vec![0u8; 16];
            b[0..2].copy_from_slice(&crate::AF_INET.to_ne_bytes());
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            b[4..8].copy_from_slice(&u32::from(*a.ip()).to_be_bytes());
            b
        }
        SocketAddr::V6(a) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&crate::AF_INET6.to_ne_bytes());
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            b[8..24].copy_from_slice(&a.ip().octets());
            b
        }
    }
}

fn map_io(e: std::io::Error) -> HostError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock => HostError::Other(crate::EAGAIN),
        std::io::ErrorKind::ConnectionRefused => HostError::Other(crate::ECONNREFUSED),
        std::io::ErrorKind::ConnectionReset => HostError::Other(crate::ECONNRESET),
        std::io::ErrorKind::AddrInUse => HostError::Other(crate::EADDRINUSE),
        std::io::ErrorKind::NotConnected => HostError::Other(crate::ENOTCONN),
        std::io::ErrorKind::BrokenPipe => HostError::Other(crate::EPIPE),
        std::io::ErrorKind::InvalidInput => HostError::Invalid,
        _ => HostError::Other(e.raw_os_error().unwrap_or(crate::EINVAL)),
    }
}
