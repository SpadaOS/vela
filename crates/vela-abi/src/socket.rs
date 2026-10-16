//! Linux x86_64 socket ABI constants and address helpers.

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_NONBLOCK: u32 = 0x800;
pub const SOCK_CLOEXEC: u32 = 0x80000;
pub const SOCK_TYPE_MASK: u32 = 0xf;

pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

pub const SOL_SOCKET: u32 = 1;
pub const SO_REUSEADDR: u32 = 2;
pub const SO_ERROR: u32 = 4;
pub const SO_RCVTIMEO: u32 = 20;
pub const SO_SNDTIMEO: u32 = 21;
pub const IPPROTO_TCP: u32 = 6;
pub const TCP_NODELAY: u32 = 1;

pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_PEEK: u32 = 0x2;
pub const MSG_TRUNC: u32 = 0x20;
pub const MSG_NOSIGNAL: u32 = 0x4000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SockAddrIn {
    pub family: u16,
    pub port: u16,
    pub addr: u32,
    pub zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SockAddrIn6 {
    pub family: u16,
    pub port: u16,
    pub flowinfo: u32,
    pub addr: [u8; 16],
    pub scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrUn {
    pub family: u16,
    pub path: [u8; 108],
}

impl Default for SockAddrUn {
    fn default() -> Self {
        Self {
            family: AF_UNIX,
            path: [0; 108],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoVecMsg {
    pub iov_base: u64,
    pub iov_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsgHdr {
    pub name: u64,
    pub namelen: u32,
    pub _pad: u32,
    pub iov: u64,
    pub iovlen: u64,
    pub control: u64,
    pub controllen: u64,
    pub flags: u32,
}

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLPRI: u32 = 0x002;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLET: u32 = 1 << 31;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLL_CTL_ADD: u32 = 1;
pub const EPOLL_CTL_DEL: u32 = 2;
pub const EPOLL_CTL_MOD: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn linux_socket_layouts() {
        assert_eq!(size_of::<SockAddrIn>(), 16);
        assert_eq!(size_of::<SockAddrIn6>(), 28);
        assert_eq!(size_of::<EpollEvent>(), 12);
        assert_eq!(size_of::<MsgHdr>(), 56);
    }
}
