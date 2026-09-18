//! linux_dev：仅用于在 Linux 上做 loader/runtime 逻辑测试的空跑 Host。
//! map 用分配器模拟（可写、零填充）；真实执行客户 ELF 必须在 Windows 上测（规格 0）。

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use crate::file_ops::{self, io_err};
use crate::{Host, HostDir, HostError, HostFile, HostOpen, HostPath, HostProt, HostStat, StdioHandles};

pub struct LinuxDevHost {
    start: Instant,
    allocs: Mutex<HashMap<usize, std::alloc::Layout>>,
}

impl LinuxDevHost {
    pub fn new() -> Self {
        LinuxDevHost { start: Instant::now(), allocs: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<usize, std::alloc::Layout>> {
        match self.allocs.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Default for LinuxDevHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Host for LinuxDevHost {
    unsafe fn map(&self, _hint: usize, len: usize, _prot: HostProt, _anon: bool) -> Result<usize, HostError> {
        let layout = std::alloc::Layout::from_size_align(len.max(1), 4096).map_err(|_| HostError::Invalid)?;
        // SAFETY: 布局非零大小；dev 宿主仅做逻辑测试
        let p = unsafe { std::alloc::alloc_zeroed(layout) };
        if p.is_null() {
            return Err(HostError::NoMemory);
        }
        self.lock().insert(p as usize, layout);
        Ok(p as usize)
    }

    unsafe fn protect(&self, _addr: usize, _len: usize, _prot: HostProt) -> Result<(), HostError> {
        Ok(()) // dev 宿主不强制 W^X
    }

    unsafe fn unmap(&self, addr: usize, _len: usize) -> Result<(), HostError> {
        if let Some(l) = self.lock().remove(&addr) {
            // SAFETY: addr 由本实现 alloc，配对 dealloc
            unsafe { std::alloc::dealloc(addr as *mut u8, l) };
        }
        Ok(())
    }

    fn open(&self, path: &HostPath, opt: HostOpen) -> Result<HostFile, HostError> {
        file_ops::open(path, opt)
    }
    fn open_dir(&self, path: &HostPath) -> Result<HostDir, HostError> {
        file_ops::open_dir(path)
    }
    fn mkdir(&self, path: &HostPath) -> Result<(), HostError> {
        file_ops::mkdir(path)
    }
    fn remove(&self, path: &HostPath, dir: bool) -> Result<(), HostError> {
        file_ops::remove(path, dir)
    }
    fn rename(&self, old: &HostPath, new: &HostPath) -> Result<(), HostError> {
        file_ops::rename(old, new)
    }
    fn sync_file(&self, f: &HostFile, data_only: bool) -> Result<(), HostError> {
        file_ops::sync_file(f, data_only)
    }
    fn dup_file(&self, f: &HostFile) -> Result<HostFile, HostError> {
        file_ops::dup_file(f)
    }
    fn read(&self, f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError> {
        file_ops::read(f, buf)
    }
    fn write(&self, f: &HostFile, buf: &[u8]) -> Result<usize, HostError> {
        file_ops::write(f, buf)
    }
    fn seek(&self, f: &HostFile, off: i64, whence: i32) -> Result<u64, HostError> {
        file_ops::seek(f, off, whence)
    }
    fn stat_path(&self, path: &HostPath) -> Result<HostStat, HostError> {
        file_ops::stat_path(path)
    }
    fn stat_file(&self, f: &HostFile) -> Result<HostStat, HostError> {
        file_ops::stat_file(f)
    }
    fn close(&self, f: HostFile) -> Result<(), HostError> {
        file_ops::close(f)
    }
    fn stdio(&self) -> StdioHandles {
        file_ops::stdio()
    }
    fn monotonic_ns(&self) -> u64 {
        file_ops::monotonic_ns(&self.start)
    }
    fn realtime(&self) -> (i64, u32) {
        file_ops::realtime()
    }
    fn random(&self, buf: &mut [u8]) -> Result<(), HostError> {
        use std::io::Read;
        if buf.is_empty() {
            return Ok(());
        }
        let mut f = std::fs::File::open("/dev/urandom").map_err(|e| io_err(&e))?;
        f.read_exact(buf).map_err(|e| io_err(&e))
    }
    fn thread_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
    fn process_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
}
