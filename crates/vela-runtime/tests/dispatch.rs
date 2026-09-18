//! dispatch 单元测试：用 MockHost（分配器模拟内存）验证 syscall 翻译。
//! 纯 CPU/小内存操作（规格 9.3：测试 dispatch 单元即可）。

use std::sync::Mutex;

use vela_abi as abi;
use vela_runtime::mem::{LoadedImage, MemRange, Segment};
use vela_runtime::{dispatch, GuestFd, GuestProcess};
use vela_sys::{Host, HostError, HostFile, HostFileKind, HostOpen, HostPath, HostProt, HostStat, StdioHandles};

// ---------------------------------------------------------------- MockHost

struct MockHost {
    out: Mutex<Vec<u8>>,
    allocs: Mutex<std::collections::HashMap<usize, std::alloc::Layout>>,
}

impl MockHost {
    fn new() -> Self {
        MockHost { out: Mutex::new(Vec::new()), allocs: Mutex::new(std::collections::HashMap::new()) }
    }

    fn out(&self) -> Vec<u8> {
        self.out.lock().unwrap().clone()
    }
}

impl Host for MockHost {
    unsafe fn map(&self, _hint: usize, len: usize, _prot: HostProt, _anon: bool) -> Result<usize, HostError> {
        let layout = std::alloc::Layout::from_size_align(len.max(1), 16).map_err(|_| HostError::Invalid)?;
        // SAFETY: 布局非零大小；测试专用
        let p = unsafe { std::alloc::alloc_zeroed(layout) };
        if p.is_null() {
            return Err(HostError::NoMemory);
        }
        self.allocs.lock().unwrap().insert(p as usize, layout);
        Ok(p as usize)
    }
    unsafe fn protect(&self, _addr: usize, _len: usize, _prot: HostProt) -> Result<(), HostError> {
        Ok(())
    }
    unsafe fn unmap(&self, addr: usize, _len: usize) -> Result<(), HostError> {
        if let Some(l) = self.allocs.lock().unwrap().remove(&addr) {
            // SAFETY: addr 由本实现 alloc，配对 dealloc
            unsafe { std::alloc::dealloc(addr as *mut u8, l) };
        }
        Ok(())
    }
    fn open(&self, _p: &HostPath, _o: HostOpen) -> Result<HostFile, HostError> {
        Err(HostError::Unimplemented)
    }
    fn read(&self, f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError> {
        match &f.0 {
            HostFileKind::StdIn => Ok(0), // v0 stdin 先返回 0（规格 5.4）
            _ => Err(HostError::Access),
        }
    }
    fn write(&self, f: &HostFile, buf: &[u8]) -> Result<usize, HostError> {
        match &f.0 {
            HostFileKind::StdOut | HostFileKind::StdErr => {
                self.out.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            _ => Err(HostError::Access),
        }
    }
    fn seek(&self, _f: &HostFile, _off: i64, _w: i32) -> Result<u64, HostError> {
        Err(HostError::Invalid)
    }
    fn stat_path(&self, _p: &HostPath) -> Result<HostStat, HostError> {
        Err(HostError::Unimplemented)
    }
    fn close(&self, _f: HostFile) -> Result<(), HostError> {
        Ok(())
    }
    fn stdio(&self) -> StdioHandles {
        StdioHandles {
            stdin: HostFile(HostFileKind::StdIn),
            stdout: HostFile(HostFileKind::StdOut),
            stderr: HostFile(HostFileKind::StdErr),
        }
    }
    fn monotonic_ns(&self) -> u64 {
        42
    }
    fn realtime(&self) -> (i64, u32) {
        (1_700_000_000, 500_000_000)
    }
    fn random(&self, buf: &mut [u8]) -> Result<(), HostError> {
        buf.fill(0xA5);
        Ok(())
    }
    fn thread_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
    fn process_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
}

// ---------------------------------------------------------------- 辅助

fn setup(len: usize) -> (MockHost, GuestProcess, usize) {
    let host = MockHost::new();
    // SAFETY: 测试内 mock map，返回真实可写内存
    let addr = unsafe { host.map(0, len, HostProt::READ | HostProt::WRITE, true) }.unwrap();
    let img = LoadedImage {
        bias: 0x4000_0000,
        entry: 0x4000_0078,
        phdr: 0x4000_0040,
        phnum: 1,
        phentsize: 56,
        segments: vec![Segment { vaddr: 0x4000_0000, host_addr: addr, file_size: len as u64, mem_size: len as u64, prot: 5 }],
        exec_ranges: vec![],
        span: MemRange { start: addr as u64, len: len as u64 },
    };
    let mut proc = GuestProcess::new(1000, img);
    proc.attach_stdio(&host);
    (host, proc, addr)
}

// ---------------------------------------------------------------- 测试

#[test]
fn write_syscall_forwards_to_host() {
    let (host, mut proc, addr) = setup(4096);
    // SAFETY: addr 为 mock 分配的可写内存
    unsafe {
        std::ptr::copy_nonoverlapping(b"hello".as_ptr(), (addr + 0x100) as *mut u8, 5);
    }
    let r = dispatch(&mut proc, &host, abi::SYS_WRITE, [1, (addr + 0x100) as u64, 5, 0, 0, 0]);
    assert_eq!(r, 5);
    assert_eq!(host.out(), b"hello");
}

#[test]
fn write_outside_mappings_gives_efault() {
    let (host, mut proc, _addr) = setup(4096);
    let r = dispatch(&mut proc, &host, abi::SYS_WRITE, [1, u64::MAX - 4096, 8, 0, 0, 0]);
    assert_eq!(r, -(abi::EFAULT as i64));
}

#[test]
fn writev_concatenates() {
    let (host, mut proc, addr) = setup(4096);
    // SAFETY: addr 为 mock 分配的可写内存
    unsafe {
        std::ptr::copy_nonoverlapping(b"AB".as_ptr(), (addr + 0x10) as *mut u8, 2);
        std::ptr::copy_nonoverlapping(b"CDE".as_ptr(), (addr + 0x20) as *mut u8, 3);
        // iovec[0] = (addr+0x10, 2), iovec[1] = (addr+0x20, 3)
        std::ptr::write((addr + 0x30) as *mut u64, (addr + 0x10) as u64);
        std::ptr::write((addr + 0x38) as *mut u64, 2);
        std::ptr::write((addr + 0x40) as *mut u64, (addr + 0x20) as u64);
        std::ptr::write((addr + 0x48) as *mut u64, 3);
    }
    let r = dispatch(&mut proc, &host, abi::SYS_WRITEV, [1, (addr + 0x30) as u64, 2, 0, 0, 0]);
    assert_eq!(r, 5);
    assert_eq!(host.out(), b"ABCDE");
}

#[test]
fn brk_grows_within_heap() {
    let (host, mut proc, _addr) = setup(4096);
    let heap = proc.init_heap(&host, 0, 8192).unwrap();
    let r0 = dispatch(&mut proc, &host, abi::SYS_BRK, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r0, heap as i64);
    let r1 = dispatch(&mut proc, &host, abi::SYS_BRK, [(heap + 0x100) as u64, 0, 0, 0, 0, 0]);
    assert_eq!(r1, (heap + 0x100) as i64);
    // 越界增长失败，返回当前断点
    let r2 = dispatch(&mut proc, &host, abi::SYS_BRK, [(heap + 0x10000) as u64, 0, 0, 0, 0, 0]);
    assert_eq!(r2, (heap + 0x100) as i64);
}

#[test]
fn mmap_anonymous_registers_mapping() {
    let (host, mut proc, _addr) = setup(4096);
    let flags = (abi::MAP_PRIVATE | abi::MAP_ANONYMOUS) as u64;
    let r = dispatch(&mut proc, &host, abi::SYS_MMAP, [0, 8192, 3, flags, (-1i64) as u64, 0]);
    assert!(r > 0);
    let mapped = r as u64;
    assert!(proc.mem.contains(mapped, 8192));
    // 新映射区可直接 write
    // SAFETY: mapped 为 mock 分配的可写内存
    unsafe {
        std::ptr::copy_nonoverlapping(b"X".as_ptr(), mapped as *mut u8, 1);
    }
    let w = dispatch(&mut proc, &host, abi::SYS_WRITE, [1, mapped, 1, 0, 0, 0]);
    assert_eq!(w, 1);
}

#[test]
fn mmap_rejects_file_backed() {
    let (host, mut proc, _addr) = setup(4096);
    let r = dispatch(&mut proc, &host, abi::SYS_MMAP, [0, 4096, 3, abi::MAP_PRIVATE as u64, 5, 0]);
    assert_eq!(r, -(abi::ENOSYS as i64));
}

#[test]
fn uname_fills_linux_fields() {
    let (host, mut proc, addr) = setup(4096);
    let r = dispatch(&mut proc, &host, abi::SYS_UNAME, [addr as u64, 0, 0, 0, 0, 0]);
    assert_eq!(r, 0);
    // SAFETY: addr 为 mock 分配的可读内存
    let sysname = unsafe { std::slice::from_raw_parts(addr as *const u8, 5) };
    assert_eq!(sysname, b"Linux");
    let machine = unsafe { std::slice::from_raw_parts((addr + 260) as *const u8, 6) };
    assert_eq!(machine, b"x86_64");
}

#[test]
fn arch_prctl_set_get_fs() {
    let (host, mut proc, addr) = setup(4096);
    let r = dispatch(&mut proc, &host, abi::SYS_ARCH_PRCTL, [abi::ARCH_SET_FS, 0x1234_5678, 0, 0, 0, 0]);
    assert_eq!(r, 0);
    assert_eq!(proc.fs_base, 0x1234_5678);
    let r = dispatch(&mut proc, &host, abi::SYS_ARCH_PRCTL, [abi::ARCH_GET_FS, (addr + 0x80) as u64, 0, 0, 0, 0]);
    assert_eq!(r, 0);
    // SAFETY: addr+0x80 为 mock 分配的可读内存
    let v = unsafe { std::ptr::read_unaligned((addr + 0x80) as *const u64) };
    assert_eq!(v, 0x1234_5678);
    let bad = dispatch(&mut proc, &host, abi::SYS_ARCH_PRCTL, [0x9999, 0, 0, 0, 0, 0]);
    assert_eq!(bad, -(abi::EINVAL as i64));
}

#[test]
fn getrandom_fills_buffer() {
    let (host, mut proc, addr) = setup(4096);
    let r = dispatch(&mut proc, &host, abi::SYS_GETRANDOM, [(addr + 0x100) as u64, 16, 0, 0, 0, 0]);
    assert_eq!(r, 16);
    // SAFETY: addr+0x100 为 mock 分配的可读内存
    let b = unsafe { std::slice::from_raw_parts((addr + 0x100) as *const u8, 16) };
    assert!(b.iter().all(|&x| x == 0xA5));
}

#[test]
fn unimplemented_returns_enosys() {
    let (host, mut proc, _addr) = setup(4096);
    let r = dispatch(&mut proc, &host, 9999, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::ENOSYS as i64));
    let r = dispatch(&mut proc, &host, abi::SYS_FSTAT, [1, 0, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::ENOSYS as i64));
}

#[test]
fn ioctl_is_not_tty() {
    let (host, mut proc, _addr) = setup(4096);
    let r = dispatch(&mut proc, &host, abi::SYS_IOCTL, [1, 0x5413, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::ENOTTY as i64));
}

#[test]
fn fd_alloc_and_close() {
    let (host, mut proc, _addr) = setup(4096);
    assert!(matches!(proc.fds.get(1), Some(GuestFd::Host(_))));
    assert!(matches!(proc.fds.get(99), None));
    let fd = proc.fds.alloc_fd(GuestFd::Null);
    assert_eq!(fd, 3); // 0/1/2 被占用
    let r = dispatch(&mut proc, &host, abi::SYS_CLOSE, [3, 0, 0, 0, 0, 0]);
    assert_eq!(r, 0);
    let r = dispatch(&mut proc, &host, abi::SYS_CLOSE, [77, 0, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::EBADF as i64));
}
