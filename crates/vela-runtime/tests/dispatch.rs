//! dispatch 单元测试：用 MockHost（分配器模拟内存）验证 syscall 翻译。
//! 纯 CPU/小内存操作（规格 9.3：测试 dispatch 单元即可）。

use std::sync::Mutex;

use vela_abi as abi;
use vela_runtime::mem::{LoadedImage, MemRange, Segment};
use vela_runtime::{dispatch, GuestFd, GuestProcess};
use vela_sys::{
    Host, HostDir, HostDirEntry, HostError, HostFile, HostFileKind, HostFileOps, HostMem, HostOpen,
    HostPath, HostProt, HostStat, HostTime, HostTls, StdioHandles,
};

// ---------------------------------------------------------------- MockHost

struct MockHost {
    out: Mutex<Vec<u8>>,
    allocs: Mutex<std::collections::HashMap<usize, std::alloc::Layout>>,
    /// map_file 分配的"视图"基址集合（跨 kind 释放原语校验用）。
    views: Mutex<std::collections::HashSet<usize>>,
}

impl MockHost {
    fn new() -> Self {
        MockHost {
            out: Mutex::new(Vec::new()),
            allocs: Mutex::new(std::collections::HashMap::new()),
            views: Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn out(&self) -> Vec<u8> {
        self.out.lock().unwrap().clone()
    }
}

impl HostMem for MockHost {
    unsafe fn map(
        &self,
        _hint: usize,
        len: usize,
        _prot: HostProt,
        _anon: bool,
    ) -> Result<usize, HostError> {
        // 页对齐模拟真实宿主（VirtualAlloc 64K / munmap 页粒度语义）
        let layout = std::alloc::Layout::from_size_align(len.max(1), 4096)
            .map_err(|_| HostError::Invalid)?;
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
        assert!(
            !self.views.lock().unwrap().contains(&addr),
            "reserve unmap used on a file view {addr:#x}"
        );
        if let Some(l) = self.allocs.lock().unwrap().remove(&addr) {
            // SAFETY: addr 由本实现 alloc，配对 dealloc
            unsafe { std::alloc::dealloc(addr as *mut u8, l) };
        }
        Ok(())
    }
    // 模拟文件视图：分配一块零内存并登记为 view（真实内容语义由 Windows 宿主
    // 测试覆盖；这里验证 runtime 的登记/释放原语分发）。
    unsafe fn map_file(
        &self,
        _f: &HostFile,
        _off: u64,
        len: usize,
        _hint: usize,
        _prot: HostProt,
    ) -> Result<usize, HostError> {
        let layout = std::alloc::Layout::from_size_align(len.max(1), 4096)
            .map_err(|_| HostError::Invalid)?;
        // SAFETY: 布局非零大小；测试专用
        let p = unsafe { std::alloc::alloc_zeroed(layout) };
        if p.is_null() {
            return Err(HostError::NoMemory);
        }
        self.allocs.lock().unwrap().insert(p as usize, layout);
        self.views.lock().unwrap().insert(p as usize);
        Ok(p as usize)
    }
    unsafe fn unmap_view(&self, addr: usize) -> Result<(), HostError> {
        assert!(
            self.views.lock().unwrap().remove(&addr),
            "unmap_view on a non-view address {addr:#x}"
        );
        if let Some(l) = self.allocs.lock().unwrap().remove(&addr) {
            // SAFETY: addr 由本实现 alloc，配对 dealloc
            unsafe { std::alloc::dealloc(addr as *mut u8, l) };
        }
        Ok(())
    }
}

impl HostFileOps for MockHost {
    fn open(&self, _p: &HostPath, _o: HostOpen) -> Result<HostFile, HostError> {
        Err(HostError::Unimplemented)
    }
    fn open_dir(&self, _p: &HostPath) -> Result<HostDir, HostError> {
        Err(HostError::Unimplemented)
    }
    fn mkdir(&self, _p: &HostPath) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn remove(&self, _p: &HostPath, _dir: bool) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn rename(&self, _o: &HostPath, _n: &HostPath) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn sync_file(&self, _f: &HostFile, _d: bool) -> Result<(), HostError> {
        Ok(())
    }
    fn dup_file(&self, f: &HostFile) -> Result<HostFile, HostError> {
        Ok(match &f.0 {
            HostFileKind::StdIn => HostFile(HostFileKind::StdIn),
            HostFileKind::StdOut => HostFile(HostFileKind::StdOut),
            HostFileKind::StdErr => HostFile(HostFileKind::StdErr),
            HostFileKind::Disk { .. } => return Err(HostError::Unimplemented),
        })
    }
    fn read(&self, f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError> {
        match &f.0 {
            HostFileKind::StdIn => Ok(0), // v0 stdin 先返回 0（规格 5.4）
            HostFileKind::Disk { file, .. } => {
                use std::io::Read;
                (&*file)
                    .read(buf)
                    .map_err(|e| HostError::Other(e.raw_os_error().unwrap_or(5)))
            }
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
    fn seek(&self, f: &HostFile, off: i64, w: i32) -> Result<u64, HostError> {
        match &f.0 {
            HostFileKind::Disk { file, .. } => {
                use std::io::{Seek, SeekFrom};
                let from = match w {
                    0 => SeekFrom::Start(off as u64),
                    1 => SeekFrom::Current(off),
                    _ => SeekFrom::End(off),
                };
                (&*file)
                    .seek(from)
                    .map_err(|e| HostError::Other(e.raw_os_error().unwrap_or(5)))
            }
            _ => Err(HostError::Invalid),
        }
    }
    fn stat_path(&self, _p: &HostPath) -> Result<HostStat, HostError> {
        // 目录元数据（chdir 校验与 stat 路径测试用）
        Ok(HostStat {
            size: 0,
            is_dir: true,
            is_readonly: false,
            mtime_ns: 0,
            mode: abi::S_IFDIR | 0o755,
            nlink: 1,
            ino: 11,
            dev: 7,
            atime_ns: 0,
            ctime_ns: 0,
        })
    }
    fn stat_file(&self, _f: &HostFile) -> Result<HostStat, HostError> {
        Ok(HostStat {
            size: 123,
            is_dir: false,
            is_readonly: false,
            mtime_ns: 1_700_000_000_000_000_000,
            mode: abi::S_IFREG | 0o644,
            nlink: 2,
            ino: 42,
            dev: 7,
            atime_ns: 1_700_000_000_000_000_000,
            ctime_ns: 1_700_000_000_000_000_000,
        })
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
}

impl HostTime for MockHost {
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
}

impl HostTls for MockHost {}

impl Host for MockHost {
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
        segments: vec![Segment {
            vaddr: 0x4000_0000,
            host_addr: addr,
            file_size: len as u64,
            mem_size: len as u64,
            prot: 5,
        }],
        exec_ranges: vec![],
        span: MemRange::reserve(addr as u64, len as u64),
        interp: None,
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
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_WRITE,
        [1, (addr + 0x100) as u64, 5, 0, 0, 0],
    );
    assert_eq!(r, 5);
    assert_eq!(host.out(), b"hello");
}

#[test]
fn write_outside_mappings_gives_efault() {
    let (host, mut proc, _addr) = setup(4096);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_WRITE,
        [1, u64::MAX - 4096, 8, 0, 0, 0],
    );
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
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_WRITEV,
        [1, (addr + 0x30) as u64, 2, 0, 0, 0],
    );
    assert_eq!(r, 5);
    assert_eq!(host.out(), b"ABCDE");
}

#[test]
fn brk_grows_within_heap() {
    let (host, mut proc, _addr) = setup(4096);
    let heap = proc.init_heap(&host, 0, 8192).unwrap();
    let r0 = dispatch(&mut proc, &host, abi::SYS_BRK, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r0, heap as i64);
    let r1 = dispatch(
        &mut proc,
        &host,
        abi::SYS_BRK,
        [(heap + 0x100) as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(r1, (heap + 0x100) as i64);
    // 越界增长失败，返回当前断点
    let r2 = dispatch(
        &mut proc,
        &host,
        abi::SYS_BRK,
        [(heap + 0x10000) as u64, 0, 0, 0, 0, 0],
    );
    assert_eq!(r2, (heap + 0x100) as i64);
}

#[test]
fn mmap_anonymous_registers_mapping() {
    let (host, mut proc, _addr) = setup(4096);
    let flags = (abi::MAP_PRIVATE | abi::MAP_ANONYMOUS) as u64;
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [0, 8192, 3, flags, (-1i64) as u64, 0],
    );
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
fn mmap_file_readback_matches_content_and_zero_fills_past_eof() {
    let (host, mut proc, _addr) = setup(4096);
    // 文件 8192 字节，映射 offset 4096（非 64K 对齐 → 强制读入回退路径），
    // 内容 4096 字节 + EOF 之后零填充
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let dir = std::env::temp_dir().join(format!("vela_rt_mmap_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("payload.bin");
    let mut file_bytes = vec![0u8; 8192];
    file_bytes[4096..].copy_from_slice(&payload);
    std::fs::write(&p, &file_bytes).unwrap();
    let hf = HostFile(HostFileKind::Disk {
        file: std::fs::File::open(&p).unwrap(),
        path: p,
    });
    let fd = proc.fds.alloc_fd(GuestFd::Host(hf));
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [
            0,
            8192,
            1, /* PROT_READ */
            abi::MAP_PRIVATE as u64,
            fd as u64,
            4096,
        ],
    );
    assert!(r > 0, "mmap file failed: {r}");
    let mapped = r as u64;
    assert!(proc.mem.contains(mapped, 8192));
    // SAFETY: mapped 已登记且 mock 内存可读
    let data = unsafe { std::slice::from_raw_parts(mapped as *const u8, 8192) };
    assert_eq!(&data[..4096], &payload[..]);
    assert!(data[4096..].iter().all(|&b| b == 0));
    // fd 游标未被读入过程移动
    let cur = dispatch(&mut proc, &host, abi::SYS_LSEEK, [fd as u64, 0, 1, 0, 0, 0]);
    assert_eq!(cur, 0);
    // munmap 走 reserve 原语（读入副本登记为 Reserve；mock 断言原语不混用）
    let u = dispatch(
        &mut proc,
        &host,
        abi::SYS_MUNMAP,
        [mapped, 8192, 0, 0, 0, 0],
    );
    assert_eq!(u, 0);
    assert!(!proc.mem.contains(mapped, 1));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn mmap_file_fixed_inside_reservation_carves_readback() {
    let (host, mut proc, _addr) = setup(4096);
    let payload: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 256) as u8).collect();
    let dir = std::env::temp_dir().join(format!("vela_rt_carve_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("seg.bin");
    std::fs::write(&p, &payload).unwrap();
    let hf = HostFile(HostFileKind::Disk {
        file: std::fs::File::open(&p).unwrap(),
        path: p,
    });
    let fd = proc.fds.alloc_fd(GuestFd::Host(hf));

    // ld-musl 模式：先 PROT_NONE 匿名预留（2 页），再 MAP_FIXED 文件映射覆盖前 1 页
    let anon_flags = (abi::MAP_PRIVATE | abi::MAP_ANONYMOUS) as u64;
    let res = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [
            0,
            8192,
            0, /* PROT_NONE */
            anon_flags,
            (-1i64) as u64,
            0,
        ],
    );
    assert!(res > 0);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [
            res as u64,
            4096,
            1,
            (abi::MAP_PRIVATE | abi::MAP_FIXED) as u64,
            fd as u64,
            0,
        ],
    );
    assert_eq!(r, res, "fixed carve must return the requested address");
    // SAFETY: carve 已把文件内容写入预留区首页
    let data = unsafe { std::slice::from_raw_parts(res as *const u8, 4096) };
    assert_eq!(data, &payload[..]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn mmap_file_view_registers_and_unmaps_via_view_primitive() {
    let (host, mut proc, _addr) = setup(4096);
    let dir = std::env::temp_dir().join(format!("vela_rt_view_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("lib.bin");
    std::fs::write(&p, vec![0x5A; 0x10000]).unwrap();
    let hf = HostFile(HostFileKind::Disk {
        file: std::fs::File::open(&p).unwrap(),
        path: p,
    });
    let fd = proc.fds.alloc_fd(GuestFd::Host(hf));
    // offset 0（对齐）→ 真视图路径
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [0, 8192, 1, abi::MAP_PRIVATE as u64, fd as u64, 0],
    );
    assert!(r > 0);
    let mapped = r as u64;
    assert!(host.views.lock().unwrap().contains(&(mapped as usize)));
    assert!(proc.mem.contains(mapped, 8192));
    let u = dispatch(
        &mut proc,
        &host,
        abi::SYS_MUNMAP,
        [mapped, 8192, 0, 0, 0, 0],
    );
    assert_eq!(u, 0);
    assert!(host.views.lock().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn mmap_file_error_semantics() {
    let (host, mut proc, _addr) = setup(4096);
    // fd 越界 → EBADF
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [0, 4096, 1, abi::MAP_PRIVATE as u64, 77, 0],
    );
    assert_eq!(r, -(abi::EBADF as i64));
    // /dev/null 型 fd（Null）→ ENODEV
    let nfd = proc.fds.alloc_fd(GuestFd::Null);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [0, 4096, 1, abi::MAP_PRIVATE as u64, nfd as u64, 0],
    );
    assert_eq!(r, -(abi::ENODEV as i64));
    // MAP_SHARED 文件映射 → ENOSYS（PLAN-0.0.4 延后）
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [0, 4096, 1, abi::MAP_SHARED as u64, 0, 0],
    );
    assert_eq!(r, -(abi::ENOSYS as i64));
    // flags 缺 PRIVATE/SHARED → EINVAL
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [0, 4096, 1, abi::MAP_ANONYMOUS as u64, (-1i64) as u64, 0],
    );
    assert_eq!(r, -(abi::EINVAL as i64));
}

#[test]
fn msync_validates_and_noops() {
    let (host, mut proc, _addr) = setup(4096);
    let flags = (abi::MAP_PRIVATE | abi::MAP_ANONYMOUS) as u64;
    let m = dispatch(
        &mut proc,
        &host,
        abi::SYS_MMAP,
        [0, 8192, 3, flags, (-1i64) as u64, 0],
    );
    assert!(m > 0);
    // 未对齐 / 零长度 → EINVAL
    assert_eq!(
        dispatch(
            &mut proc,
            &host,
            abi::SYS_MSYNC,
            [m as u64 + 1, 4096, 0, 0, 0, 0]
        ),
        -(abi::EINVAL as i64)
    );
    assert_eq!(
        dispatch(&mut proc, &host, abi::SYS_MSYNC, [m as u64, 0, 0, 0, 0, 0]),
        -(abi::EINVAL as i64)
    );
    // 区间未登记 → ENOMEM
    assert_eq!(
        dispatch(
            &mut proc,
            &host,
            abi::SYS_MSYNC,
            [m as u64, 0x1_0000, 0, 0, 0, 0]
        ),
        -(abi::ENOMEM as i64)
    );
    // 合法区间 → 0（MAP_PRIVATE 无回写语义）
    assert_eq!(
        dispatch(
            &mut proc,
            &host,
            abi::SYS_MSYNC,
            [m as u64, 8192, 0, 0, 0, 0]
        ),
        0
    );
}

#[test]
fn uname_fills_linux_fields() {
    let (host, mut proc, addr) = setup(4096);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_UNAME,
        [addr as u64, 0, 0, 0, 0, 0],
    );
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
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_ARCH_PRCTL,
        [abi::ARCH_SET_FS, 0x1234_5678, 0, 0, 0, 0],
    );
    assert_eq!(r, 0);
    assert_eq!(proc.fs_base, 0x1234_5678);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_ARCH_PRCTL,
        [abi::ARCH_GET_FS, (addr + 0x80) as u64, 0, 0, 0, 0],
    );
    assert_eq!(r, 0);
    // SAFETY: addr+0x80 为 mock 分配的可读内存
    let v = unsafe { std::ptr::read_unaligned((addr + 0x80) as *const u64) };
    assert_eq!(v, 0x1234_5678);
    let bad = dispatch(
        &mut proc,
        &host,
        abi::SYS_ARCH_PRCTL,
        [0x9999, 0, 0, 0, 0, 0],
    );
    assert_eq!(bad, -(abi::EINVAL as i64));
}

#[test]
fn getrandom_fills_buffer() {
    let (host, mut proc, addr) = setup(4096);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETRANDOM,
        [(addr + 0x100) as u64, 16, 0, 0, 0, 0],
    );
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
    let r = dispatch(&mut proc, &host, abi::SYS_GETDENTS64, [99, 0, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::EBADF as i64));
}

// ---------------------------------------------------------------- stat 家族

#[test]
fn fstat_fills_linux_stat_layout() {
    let (host, mut proc, addr) = setup(4096);
    let buf = (addr + 0x100) as u64;
    let r = dispatch(&mut proc, &host, abi::SYS_FSTAT, [1, buf, 0, 0, 0, 0]);
    assert_eq!(r, 0);
    // SAFETY: buf 为 mock 分配的可写内存，write_guest 已登记校验
    let st = unsafe { std::ptr::read_unaligned(buf as *const abi::Stat) };
    assert_eq!(st.st_size, 123);
    assert_eq!(st.st_ino, 42);
    assert_eq!(st.st_dev, 7);
    assert_eq!(st.st_nlink, 2);
    assert_eq!(st.st_mode, abi::S_IFREG | 0o644);
    assert_eq!(st.st_uid, 1000);
    assert_eq!(st.st_gid, 1000);
    assert_eq!(st.st_mtime, 1_700_000_000);
    assert_eq!(st.st_mtime_nsec, 0);
    assert_eq!(st.st_blksize, 4096);
    assert_eq!(st.st_blocks, 1); // ceil(123/512)
}

#[test]
fn fstat_bad_fd_is_ebadf() {
    let (host, mut proc, addr) = setup(4096);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FSTAT,
        [99, (addr + 0x100) as u64, 0, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EBADF as i64));
}

#[test]
fn fstat_null_fd_is_char_device() {
    let (host, mut proc, addr) = setup(4096);
    let fd = proc.fds.alloc_fd(GuestFd::Null);
    let buf = (addr + 0x100) as u64;
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FSTAT,
        [fd as u64, buf, 0, 0, 0, 0],
    );
    assert_eq!(r, 0);
    // SAFETY: buf 为 mock 分配的可写内存
    let st = unsafe { std::ptr::read_unaligned(buf as *const abi::Stat) };
    assert_eq!(st.st_mode & abi::S_IFMT, abi::S_IFCHR);
    assert_eq!(st.st_size, 0);
}

#[test]
fn newfstatat_empty_path_with_at_empty_path_falls_back_to_fstat() {
    let (host, mut proc, addr) = setup(4096);
    // 把一段路径字符串写进客户内存
    let p = (addr + 0x200) as u64;
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        std::ptr::copy_nonoverlapping(b"\0".as_ptr(), p as *mut u8, 1);
    }
    let buf = (addr + 0x100) as u64;
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_NEWFSTATAT,
        [1, p, buf, abi::AT_EMPTY_PATH, 0, 0],
    );
    assert_eq!(r, 0);
    // SAFETY: buf 为 mock 分配的可写内存
    let st = unsafe { std::ptr::read_unaligned(buf as *const abi::Stat) };
    assert_eq!(st.st_size, 123);
    // 缺 AT_EMPTY_PATH 时空路径必须 EINVAL
    let bad = dispatch(&mut proc, &host, abi::SYS_NEWFSTATAT, [1, p, buf, 0, 0, 0]);
    assert_eq!(bad, -(abi::EINVAL as i64));
}

#[test]
fn stat_on_translatable_path_fills_dir_stat() {
    let (host, mut proc, addr) = setup(4096);
    let p = (addr + 0x200) as u64;
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"/mnt/c/Windows\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_STAT,
        [p, (addr + 0x100) as u64, 0, 0, 0, 0],
    );
    assert_eq!(r, 0);
    // SAFETY: buf 为 mock 分配的可写内存
    let st = unsafe { std::ptr::read_unaligned((addr + 0x100) as *const abi::Stat) };
    assert_eq!(st.st_mode & abi::S_IFMT, abi::S_IFDIR);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_LSTAT,
        [p, (addr + 0x100) as u64, 0, 0, 0, 0],
    );
    assert_eq!(r, 0);
}

#[test]
fn stat_untranslatable_path_is_enoent() {
    let (host, mut proc, addr) = setup(4096);
    let p = (addr + 0x200) as u64;
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"/nonexistent-prefix/file\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_STAT,
        [p, (addr + 0x100) as u64, 0, 0, 0, 0],
    );
    assert_eq!(r, -(abi::ENOENT as i64));
}

// ---------------------------------------------------------------- 工作目录 / 身份

#[test]
fn getcwd_returns_current_directory() {
    let (host, mut proc, addr) = setup(4096);
    let buf = (addr + 0x100) as u64;
    let r = dispatch(&mut proc, &host, abi::SYS_GETCWD, [buf, 256, 0, 0, 0, 0]);
    assert_eq!(r, buf as i64);
    // SAFETY: buf 为 mock 分配的可写内存
    let s = unsafe { std::slice::from_raw_parts(buf as *const u8, 7) };
    assert_eq!(s, b"/mnt/c\0");
    // 缓冲不足 → ERANGE
    let r = dispatch(&mut proc, &host, abi::SYS_GETCWD, [buf, 2, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::ERANGE as i64));
}

#[test]
fn chdir_updates_cwd_accounting() {
    let (host, mut proc, addr) = setup(4096);
    let p = (addr + 0x200) as u64;
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"/mnt/c/Windows\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    let r = dispatch(&mut proc, &host, abi::SYS_CHDIR, [p, 0, 0, 0, 0, 0]);
    assert_eq!(r, 0);
    assert_eq!(proc.cwd, "/mnt/c/Windows");
    // 相对路径 chdir 基于 cwd 拼接
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"Temp\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    let r = dispatch(&mut proc, &host, abi::SYS_CHDIR, [p, 0, 0, 0, 0, 0]);
    assert_eq!(r, 0);
    assert_eq!(proc.cwd, "/mnt/c/Windows/Temp");
    // getcwd 读回
    let buf = (addr + 0x100) as u64;
    let r = dispatch(&mut proc, &host, abi::SYS_GETCWD, [buf, 256, 0, 0, 0, 0]);
    assert_eq!(r, buf as i64);
    // SAFETY: buf 为 mock 分配的可写内存
    let s = unsafe { std::slice::from_raw_parts(buf as *const u8, 20) };
    assert_eq!(&s[..20], b"/mnt/c/Windows/Temp\0");
    // 不可翻译路径 → ENOENT
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"/etc\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    let r = dispatch(&mut proc, &host, abi::SYS_CHDIR, [p, 0, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::ENOENT as i64));
    assert_eq!(proc.cwd, "/mnt/c/Windows/Temp"); // 失败不改变 cwd
}

#[test]
fn getuid_getgid_use_process_identity() {
    let (host, mut proc, _addr) = setup(4096);
    proc.uid = 4242;
    proc.gid = 4343;
    let r = dispatch(&mut proc, &host, abi::SYS_GETUID, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r, 4242);
    let r = dispatch(&mut proc, &host, abi::SYS_GETEUID, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r, 4242);
    let r = dispatch(&mut proc, &host, abi::SYS_GETGID, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r, 4343);
    let r = dispatch(&mut proc, &host, abi::SYS_GETEGID, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r, 4343);
}

// ---------------------------------------------------------------- getdents64

/// 注入一个预填快照的目录 fd：a.txt (REG, ino=100) + sub (DIR, ino=200)。
fn make_dir_fd(proc: &mut GuestProcess) -> i32 {
    let dir = HostDir::from_parts(
        std::path::PathBuf::from(r"C:\tmpdir"),
        vec![
            HostDirEntry {
                name: "a.txt".into(),
                is_dir: false,
                ino: 100,
            },
            HostDirEntry {
                name: "sub".into(),
                is_dir: true,
                ino: 200,
            },
        ],
    );
    proc.fds.alloc_fd(GuestFd::HostDir(dir))
}

#[test]
fn getdents64_fills_dirent64_entries() {
    let (host, mut proc, addr) = setup(4096);
    let fd = make_dir_fd(&mut proc);
    let buf = (addr + 0x100) as u64;
    // a.txt: reclen=(19+5+1+7)&!7=32；sub: (19+3+1+7)&!7=24 → 共 56
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [fd as u64, buf, 4096, 0, 0, 0],
    );
    assert_eq!(r, 56);
    // SAFETY: buf 为 mock 分配的可写内存
    let d_ino = unsafe { std::ptr::read_unaligned(buf as *const u64) };
    assert_eq!(d_ino, 100);
    let d_type = unsafe { std::ptr::read_unaligned((buf + 18) as *const u8) };
    assert_eq!(d_type, abi::DT_REG);
    let name = unsafe { std::slice::from_raw_parts((buf + 19) as *const u8, 5) };
    assert_eq!(name, b"a.txt");
    let second = buf + 32;
    let d_ino2 = unsafe { std::ptr::read_unaligned(second as *const u64) };
    assert_eq!(d_ino2, 200);
    let d_type2 = unsafe { std::ptr::read_unaligned((second + 18) as *const u8) };
    assert_eq!(d_type2, abi::DT_DIR);
    // 读完后再次调用返回 0
    let r2 = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [fd as u64, buf, 4096, 0, 0, 0],
    );
    assert_eq!(r2, 0);
}

#[test]
fn getdents64_partial_reads_resume() {
    let (host, mut proc, addr) = setup(4096);
    let fd = make_dir_fd(&mut proc);
    let buf = (addr + 0x100) as u64;
    // count=32：第一次填 a.txt(32)，第二次填 sub(24)，第三次 0
    let r1 = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [fd as u64, buf, 32, 0, 0, 0],
    );
    assert_eq!(r1, 32);
    let r2 = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [fd as u64, buf, 32, 0, 0, 0],
    );
    assert_eq!(r2, 24);
    let r3 = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [fd as u64, buf, 32, 0, 0, 0],
    );
    assert_eq!(r3, 0);
    // 第二条应是 sub
    let d_ino = unsafe { std::ptr::read_unaligned(buf as *const u64) };
    assert_eq!(d_ino, 200);
}

#[test]
fn getdents64_count_too_small_is_einval() {
    let (host, mut proc, addr) = setup(4096);
    let fd = make_dir_fd(&mut proc);
    let buf = (addr + 0x100) as u64;
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [fd as u64, buf, 8, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EINVAL as i64));
}

#[test]
fn getdents64_non_dir_fd_is_enotdir() {
    let (host, mut proc, addr) = setup(4096);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [1, (addr + 0x100) as u64, 4096, 0, 0, 0],
    );
    assert_eq!(r, -(abi::ENOTDIR as i64));
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETDENTS64,
        [99, (addr + 0x100) as u64, 4096, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EBADF as i64));
}

// ---------------------------------------------------------------- fcntl / ioctl

#[test]
fn fcntl_flags_roundtrip() {
    let (host, mut proc, _addr) = setup(4096);
    let fd = proc.fds.alloc_fd(GuestFd::Null);
    // F_SETFL(O_APPEND) → F_GETFL 返回 O_APPEND
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FCNTL,
        [fd as u64, abi::F_SETFL, abi::O_APPEND, 0, 0, 0],
    );
    assert_eq!(r, 0);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FCNTL,
        [fd as u64, abi::F_GETFL, 0, 0, 0, 0],
    );
    assert_eq!(r, abi::O_APPEND as i64);
    // F_SETFD(FD_CLOEXEC) → F_GETFD 返回 1
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FCNTL,
        [fd as u64, abi::F_SETFD, abi::FD_CLOEXEC, 0, 0, 0],
    );
    assert_eq!(r, 0);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FCNTL,
        [fd as u64, abi::F_GETFD, 0, 0, 0, 0],
    );
    assert_eq!(r, 1);
    // 坏 fd
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FCNTL,
        [77, abi::F_GETFL, 0, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EBADF as i64));
    // 未知 cmd
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FCNTL,
        [fd as u64, 99, 0, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EINVAL as i64));
}

#[test]
fn ioctl_tiocgwinsz_returns_winsize() {
    let (host, mut proc, addr) = setup(4096);
    let buf = (addr + 0x100) as u64;
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_IOCTL,
        [1, abi::TIOCGWINSZ, buf, 0, 0, 0],
    );
    assert_eq!(r, 0);
    // SAFETY: buf 为 mock 分配的可写内存
    let row = unsafe { std::ptr::read_unaligned(buf as *const u16) };
    let col = unsafe { std::ptr::read_unaligned((buf + 2) as *const u16) };
    assert_eq!((row, col), (25, 80));
    // TCGETS 诚实返回 ENOTTY；坏 fd 返回 EBADF
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_IOCTL,
        [1, abi::TCGETS, buf, 0, 0, 0],
    );
    assert_eq!(r, -(abi::ENOTTY as i64));
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_IOCTL,
        [99, abi::TIOCGWINSZ, buf, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EBADF as i64));
}

// ---------------------------------------------------------------- openat dirfd

#[test]
fn openat_dirfd_relative_rejects_escape_and_bad_fd() {
    let (host, mut proc, addr) = setup(4096);
    let fd = make_dir_fd(&mut proc);
    let p = (addr + 0x200) as u64;
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"../x\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    // 目录 fd 相对路径含 ".." → EINVAL（逃逸防护）
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_OPENAT,
        [fd as u64, p, abi::O_RDONLY as u64, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EINVAL as i64));
    // 相对路径 + 坏 dirfd → EBADF
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"child\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_OPENAT,
        [99, p, abi::O_RDONLY as u64, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EBADF as i64));
    // 相对路径 + 非目录 fd（Null）→ EBADF
    let nullfd = proc.fds.alloc_fd(GuestFd::Null);
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_OPENAT,
        [nullfd as u64, p, abi::O_RDONLY as u64, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EBADF as i64));
}

// ---------------------------------------------------------------- M2 广度

#[test]
fn dup_and_dup2_semantics() {
    let (host, mut proc, _addr) = setup(4096);
    // dup(1) → 新 fd 3（最小可用），Host 句柄复制
    let r = dispatch(&mut proc, &host, abi::SYS_DUP, [1, 0, 0, 0, 0, 0]);
    assert_eq!(r, 3);
    assert!(matches!(proc.fds.get(3), Some(GuestFd::Host(_))));
    // dup2(1, 5) → 强制占用 5
    let r = dispatch(&mut proc, &host, abi::SYS_DUP2, [1, 5, 0, 0, 0, 0]);
    assert_eq!(r, 5);
    assert!(matches!(proc.fds.get(5), Some(GuestFd::Host(_))));
    // dup3(1, 1) → EINVAL（dup3 禁止同 fd）
    let r = dispatch(&mut proc, &host, abi::SYS_DUP3, [1, 1, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::EINVAL as i64));
    // dup 坏 fd
    let r = dispatch(&mut proc, &host, abi::SYS_DUP, [99, 0, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::EBADF as i64));
    // fcntl F_DUPFD_CLOEXEC → 最小可用 fd（3 被 dup 占用，落在 4）
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_FCNTL,
        [1, abi::F_DUPFD_CLOEXEC, 0, 0, 0, 0],
    );
    assert_eq!(r, 4);
    assert!(matches!(proc.fds.get(4), Some(GuestFd::Host(_))));
}

#[test]
fn statx_fills_basic_layout() {
    let (host, mut proc, addr) = setup(4096);
    let p = (addr + 0x200) as u64;
    // SAFETY: p 为 mock 分配的可写内存
    unsafe {
        let s = b"/mnt/c/Windows\0";
        std::ptr::copy_nonoverlapping(s.as_ptr(), p as *mut u8, s.len());
    }
    let buf = (addr + 0x100) as u64;
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_STATX,
        [
            abi::AT_FDCWD as u64,
            p,
            buf,
            0,
            abi::STATX_BASIC_STATS as u64,
            0,
        ],
    );
    assert_eq!(r, 0);
    // SAFETY: buf 为 mock 分配的可写内存
    let mask = unsafe { std::ptr::read_unaligned(buf as *const u32) };
    let nlink = unsafe { std::ptr::read_unaligned((buf + 16) as *const u32) };
    let mode = unsafe { std::ptr::read_unaligned((buf + 28) as *const u16) };
    let ino = unsafe { std::ptr::read_unaligned((buf + 32) as *const u64) };
    assert_eq!(mask, abi::STATX_BASIC_STATS);
    assert_eq!(nlink, 1);
    assert_eq!(mode, (abi::S_IFDIR | 0o755) as u16);
    assert_eq!(ino, 11);
}

#[test]
fn honest_stubs_and_errors() {
    let (host, mut proc, addr) = setup(4096);
    // 信号类诚实 stub：记录返回 0
    for nr in [
        abi::SYS_RT_SIGACTION,
        abi::SYS_RT_SIGPROCMASK,
        abi::SYS_MADVISE,
    ] {
        let r = dispatch(&mut proc, &host, nr, [0, 0, 0, 0, 0, 0]);
        assert_eq!(r, 0, "nr={nr}");
    }
    // getrusage 填零结构
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_GETRUSAGE,
        [0, (addr + 0x100) as u64, 0, 0, 0, 0],
    );
    assert_eq!(r, 0);
    // prlimit64 上报 RLIM_INFINITY
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_PRLIMIT64,
        [0, 0, 0, (addr + 0x180) as u64, 0, 0],
    );
    assert_eq!(r, 0);
    // SAFETY: mock 分配内存
    let lim = unsafe { std::ptr::read_unaligned((addr + 0x180) as *const u64) };
    assert_eq!(lim, abi::RLIM_INFINITY);
    // socket 体系明确 ENOSYS
    let r = dispatch(&mut proc, &host, abi::SYS_SOCKET, [0, 0, 0, 0, 0, 0]);
    assert_eq!(r, -(abi::ENOSYS as i64));
}

#[test]
fn clock_gettime_monotonic_variants() {
    let (host, mut proc, addr) = setup(4096);
    for clk in [
        abi::CLOCK_MONOTONIC,
        abi::CLOCK_MONOTONIC_RAW,
        abi::CLOCK_BOOTTIME,
    ] {
        let r = dispatch(
            &mut proc,
            &host,
            abi::SYS_CLOCK_GETTIME,
            [clk, (addr + 0x100) as u64, 0, 0, 0, 0],
        );
        assert_eq!(r, 0, "clk={clk}");
    }
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_CLOCK_GETTIME,
        [99, (addr + 0x100) as u64, 0, 0, 0, 0],
    );
    assert_eq!(r, -(abi::EINVAL as i64));
}

#[test]
fn ioctl_is_not_tty() {
    let (host, mut proc, _addr) = setup(4096);
    // TCGETS 诚实返回 ENOTTY（不是终端）；未知 cmd 同样
    let r = dispatch(
        &mut proc,
        &host,
        abi::SYS_IOCTL,
        [1, abi::TCGETS, 0, 0, 0, 0],
    );
    assert_eq!(r, -(abi::ENOTTY as i64));
    let r = dispatch(&mut proc, &host, abi::SYS_IOCTL, [1, 0xDEAD, 0, 0, 0, 0]);
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
