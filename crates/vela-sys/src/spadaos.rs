//! SpadaOS Host 空壳：仅保证编译通过（规格 0 成功标准 6）。
//! 未来在 SpadaOS 上把 map/file/time/thread/futex 五组填满（规格 13）。
//! 任何方法被调用即返回 `Unimplemented`。

use crate::{
    Host, HostDir, HostError, HostFile, HostFileKind, HostFileOps, HostMem, HostOpen, HostPath,
    HostProc, HostProt, HostStat, HostTime, HostTls, HostTrap, StdioHandles,
};

/// 占位实现：所有方法返回 Unimplemented。
pub struct SpadaOsHost;

impl SpadaOsHost {
    pub fn new() -> Self {
        SpadaOsHost
    }
}

impl Default for SpadaOsHost {
    fn default() -> Self {
        Self::new()
    }
}

impl HostMem for SpadaOsHost {
    unsafe fn map(
        &self,
        _hint: usize,
        _len: usize,
        _prot: HostProt,
        _anon: bool,
    ) -> Result<usize, HostError> {
        Err(HostError::Unimplemented)
    }
    unsafe fn protect(&self, _addr: usize, _len: usize, _prot: HostProt) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    unsafe fn unmap(&self, _addr: usize, _len: usize) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
}

impl HostFileOps for SpadaOsHost {
    fn open(&self, _path: &HostPath, _opt: HostOpen) -> Result<HostFile, HostError> {
        Err(HostError::Unimplemented)
    }
    fn open_dir(&self, _path: &HostPath) -> Result<HostDir, HostError> {
        Err(HostError::Unimplemented)
    }
    fn mkdir(&self, _path: &HostPath) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn remove(&self, _path: &HostPath, _dir: bool) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn rename(&self, _old: &HostPath, _new: &HostPath) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn sync_file(&self, _f: &HostFile, _data_only: bool) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn dup_file(&self, _f: &HostFile) -> Result<HostFile, HostError> {
        Err(HostError::Unimplemented)
    }
    fn read(&self, _f: &HostFile, _buf: &mut [u8]) -> Result<usize, HostError> {
        Err(HostError::Unimplemented)
    }
    fn write(&self, _f: &HostFile, _buf: &[u8]) -> Result<usize, HostError> {
        Err(HostError::Unimplemented)
    }
    fn seek(&self, _f: &HostFile, _off: i64, _whence: i32) -> Result<u64, HostError> {
        Err(HostError::Unimplemented)
    }
    fn stat_path(&self, _path: &HostPath) -> Result<HostStat, HostError> {
        Err(HostError::Unimplemented)
    }
    fn stat_file(&self, _f: &HostFile) -> Result<HostStat, HostError> {
        Err(HostError::Unimplemented)
    }
    fn close(&self, _f: HostFile) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
    fn stdio(&self) -> StdioHandles {
        StdioHandles {
            stdin: HostFile(HostFileKind::StdIn),
            stdout: HostFile(HostFileKind::StdOut),
            stderr: HostFile(HostFileKind::StdErr),
        }
    }
}

impl HostTime for SpadaOsHost {
    fn monotonic_ns(&self) -> u64 {
        0
    }
    fn realtime(&self) -> (i64, u32) {
        (0, 0)
    }
    fn random(&self, _buf: &mut [u8]) -> Result<(), HostError> {
        Err(HostError::Unimplemented)
    }
}

impl HostTls for SpadaOsHost {}

// trap/proc 组（0.1.0 T1.5）：全部走默认 Unimplemented 桩，不写假实现。
impl HostTrap for SpadaOsHost {}
impl HostProc for SpadaOsHost {}

impl Host for SpadaOsHost {
    fn thread_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
    fn process_exit(&self, code: i32) -> ! {
        std::process::exit(code)
    }
}
