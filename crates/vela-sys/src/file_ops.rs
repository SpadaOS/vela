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
    Ok(HostFile(HostFileKind::Disk { file: f, path: path.0.clone() }))
}

pub(crate) fn read(f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError> {
    use std::io::Read;
    match &f.0 {
        HostFileKind::StdIn => std::io::stdin().read(buf).map_err(|e| io_err(&e)),
        HostFileKind::Disk { file, .. } => (&*file).read(buf).map_err(|e| io_err(&e)),
        _ => Err(HostError::Access),
    }
}

pub(crate) fn write(f: &HostFile, buf: &[u8]) -> Result<usize, HostError> {
    use std::io::Write;
    match &f.0 {
        HostFileKind::StdOut => std::io::stdout().write_all(buf).map(|_| buf.len()).map_err(|e| io_err(&e)),
        HostFileKind::StdErr => std::io::stderr().write_all(buf).map(|_| buf.len()).map_err(|e| io_err(&e)),
        HostFileKind::Disk { file, .. } => (&*file).write_all(buf).map(|_| buf.len()).map_err(|e| io_err(&e)),
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
        HostFileKind::Disk { file, .. } => (&*file).seek(from).map_err(|e| io_err(&e)),
        _ => Err(HostError::Invalid),
    }
}

pub(crate) fn stat_path(path: &HostPath) -> Result<HostStat, HostError> {
    let md = std::fs::metadata(&path.0).map_err(|e| io_err(&e))?;
    Ok(host_stat_from(&md, Some(&path.0)))
}

pub(crate) fn stat_file(f: &HostFile) -> Result<HostStat, HostError> {
    match &f.0 {
        // stdio 语义为字符设备，无宿主文件元数据
        HostFileKind::StdIn | HostFileKind::StdOut | HostFileKind::StdErr => Ok(HostStat::char_device()),
        HostFileKind::Disk { file, path } => {
            let md = file.metadata().map_err(|e| io_err(&e))?;
            Ok(host_stat_from(&md, Some(path)))
        }
    }
}

/// std::fs::Metadata → 完整 HostStat（Windows 与 linux_dev 共用）。
/// `path` 用于推导稳定 ino（路径哈希）；拿不到时 ino 置 0。
pub(crate) fn host_stat_from(md: &std::fs::Metadata, path: Option<&std::path::Path>) -> HostStat {
    let is_dir = md.is_dir();
    let ro = md.permissions().readonly();
    let (mode, nlink, ino, dev) = platform_meta(md, path);
    let ns = |t: Option<std::time::SystemTime>| -> i64 {
        t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    };
    HostStat {
        size: md.len() as i64,
        is_dir,
        is_readonly: ro,
        mtime_ns: ns(md.modified().ok()),
        atime_ns: ns(md.accessed().ok()),
        // Windows created() = 创建时间，可作 ctime；拿不到时退回 mtime
        ctime_ns: ns(md.created().ok().or_else(|| md.modified().ok())),
        mode,
        nlink,
        ino,
        dev,
    }
}

/// FNV-1a 64：同进程内稳定的 ino 来源（stable std 无 file_index API）。
/// 大小写规范化以匹配 Windows 路径不敏感语义；同一文件经不同大小写路径
/// stat 会得到同一 ino。
fn path_ino(path: &std::path::Path) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.to_string_lossy().to_ascii_lowercase().as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(windows)]
fn platform_meta(md: &std::fs::Metadata, path: Option<&std::path::Path>) -> (u32, u64, u64, u64) {
    let ino = path.map(path_ino).unwrap_or(0);
    let ro = md.permissions().readonly();
    let mode = if md.is_dir() {
        0o0040000 | if ro { 0o555 } else { 0o755 }
    } else if ro {
        0o0100000 | 0o444
    } else {
        0o0100000 | 0o644
    };
    (mode, 1, ino, 0)
}

#[cfg(unix)]
fn platform_meta(md: &std::fs::Metadata, _path: Option<&std::path::Path>) -> (u32, u64, u64, u64) {
    use std::os::unix::fs::MetadataExt as _;
    (md.mode(), md.nlink() as u64, md.ino(), md.dev())
}

#[cfg(not(any(windows, unix)))]
fn platform_meta(md: &std::fs::Metadata, path: Option<&std::path::Path>) -> (u32, u64, u64, u64) {
    let ino = path.map(path_ino).unwrap_or(0);
    let ro = md.permissions().readonly();
    let mode = if md.is_dir() { 0o0040000 | 0o755 } else { 0o0100000 | if ro { 0o444 } else { 0o644 } };
    (mode, 1, ino, 0)
}

pub(crate) fn close(f: HostFile) -> Result<(), HostError> {
    match f.0 {
        // stdio 生命周期归宿主，不允许真正关闭
        HostFileKind::StdIn | HostFileKind::StdOut | HostFileKind::StdErr => Ok(()),
        HostFileKind::Disk { .. } => Ok(()), // Drop 关闭
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
