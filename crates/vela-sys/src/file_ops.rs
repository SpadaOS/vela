//! 基于 std 的文件/时间公共实现，供 windows 与 linux_dev 两个宿主复用。

use std::time::Instant;

use crate::{HostError, HostFile, HostFileKind, HostOpen, HostPath, HostStat, StdioHandles};

pub(crate) fn io_err(e: &std::io::Error) -> HostError {
    match e.kind() {
        std::io::ErrorKind::NotFound => HostError::NotFound,
        std::io::ErrorKind::PermissionDenied => HostError::Access,
        std::io::ErrorKind::InvalidInput => HostError::Invalid,
        _ => HostError::Other(e.raw_os_error().unwrap_or(0)),
    }
}

pub(crate) fn open(path: &HostPath, opt: HostOpen) -> Result<HostFile, HostError> {
    let mut o = std::fs::OpenOptions::new();
    if opt.read {
        o.read(true);
    }
    if opt.write {
        o.write(true);
    }
    if opt.append {
        o.append(true);
        o.write(true);
    }
    if opt.create {
        o.create(true);
    }
    if opt.truncate {
        o.write(true);
        o.truncate(true);
    }
    let f = o.open(&path.0).map_err(|e| io_err(&e))?;
    Ok(HostFile(HostFileKind::Disk(f)))
}

pub(crate) fn read(f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError> {
    use std::io::Read;
    match &f.0 {
        HostFileKind::StdIn => std::io::stdin().read(buf).map_err(|e| io_err(&e)),
        HostFileKind::Disk(file) => (&*file).read(buf).map_err(|e| io_err(&e)),
        _ => Err(HostError::Access),
    }
}

pub(crate) fn write(f: &HostFile, buf: &[u8]) -> Result<usize, HostError> {
    use std::io::Write;
    match &f.0 {
        HostFileKind::StdOut => std::io::stdout().write_all(buf).map(|_| buf.len()).map_err(|e| io_err(&e)),
        HostFileKind::StdErr => std::io::stderr().write_all(buf).map(|_| buf.len()).map_err(|e| io_err(&e)),
        HostFileKind::Disk(file) => (&*file).write_all(buf).map(|_| buf.len()).map_err(|e| io_err(&e)),
        HostFileKind::StdIn => Err(HostError::Access),
    }
}

pub(crate) fn seek(f: &HostFile, off: i64, whence: i32) -> Result<u64, HostError> {
    use std::io::{Seek, SeekFrom};
    let from = match whence {
        0 => SeekFrom::Start(off as u64),
        1 => SeekFrom::Current(off),
        2 => SeekFrom::End(off),
        _ => return Err(HostError::Invalid),
    };
    match &f.0 {
        HostFileKind::Disk(file) => (&*file).seek(from).map_err(|e| io_err(&e)),
        _ => Err(HostError::Invalid),
    }
}

pub(crate) fn stat_path(path: &HostPath) -> Result<HostStat, HostError> {
    let md = std::fs::metadata(&path.0).map_err(|e| io_err(&e))?;
    Ok(HostStat {
        size: md.len() as i64,
        is_dir: md.is_dir(),
        is_readonly: md.permissions().readonly(),
        mtime_ns: md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0),
    })
}

pub(crate) fn close(f: HostFile) -> Result<(), HostError> {
    match f.0 {
        // stdio 生命周期归宿主，不允许真正关闭
        HostFileKind::StdIn | HostFileKind::StdOut | HostFileKind::StdErr => Ok(()),
        HostFileKind::Disk(_) => Ok(()), // Drop 关闭
    }
}

pub(crate) fn stdio() -> StdioHandles {
    StdioHandles {
        stdin: HostFile(HostFileKind::StdIn),
        stdout: HostFile(HostFileKind::StdOut),
        stderr: HostFile(HostFileKind::StdErr),
    }
}

pub(crate) fn monotonic_ns(start: &Instant) -> u64 {
    start.elapsed().as_nanos() as u64
}

pub(crate) fn realtime() -> (i64, u32) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as i64, d.subsec_nanos())
}
