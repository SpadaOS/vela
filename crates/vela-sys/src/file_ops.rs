//! 基于 std 的文件/时间公共实现，供 windows 与 linux_dev 两个宿主复用。

use std::time::Instant;

use crate::{
    HostDir, HostDirEntry, HostError, HostFile, HostFileKind, HostOpen, HostPath, HostStat,
    StdioHandles,
};

pub(crate) fn io_err(e: &std::io::Error) -> HostError {
    match e.kind() {
        std::io::ErrorKind::NotFound => HostError::NotFound,
        std::io::ErrorKind::PermissionDenied => HostError::Access,
        std::io::ErrorKind::InvalidInput => HostError::Invalid,
        std::io::ErrorKind::AlreadyExists => HostError::Exist,
        _ => match e.raw_os_error() {
            // Windows raw code → Linux errno（见 win32_to_errno）
            Some(c) => HostError::Other(os_to_errno(c)),
            None => HostError::Invalid,
        },
    }
}

/// 把宿主原始错误码翻译成 Linux errno，作为 `HostError::Other` 的约定载荷
/// （host_err_to_errno 直传给客户）。高频码 std 的 ErrorKind 已覆盖，
/// 这里兜底翻译剩余高频 Win32 码；未知码保守映射 EINVAL——比 0（成功语义）
/// 诚实，且排障时可从原始码日志定位。
#[cfg(windows)]
pub(crate) fn os_to_errno(code: i32) -> i32 {
    match code {
        4 => 24,       // ERROR_TOO_MANY_OPEN_FILES → EMFILE
        32 | 33 => 11, // SHARING_VIOLATION / LOCK_VIOLATION → EAGAIN
        36 => 36,      // ERROR_FILENAME_EXCED_RANGE → ENAMETOOLONG
        112 => 28,     // ERROR_DISK_FULL → ENOSPC
        145 => 39,     // ERROR_DIR_NOT_EMPTY → ENOTEMPTY
        206 => 36,     // ERROR_META_EXPANSION_TOO_LONG → ENAMETOOLONG
        _ => 22,       // 未知 → EINVAL（注释见上）
    }
}

#[cfg(not(windows))]
pub(crate) fn os_to_errno(code: i32) -> i32 {
    code // Linux：raw_os_error 即 errno
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
    if opt.create && opt.excl {
        o.create_new(true);
    } else if opt.create {
        o.create(true);
    }
    if opt.truncate {
        o.write(true);
        o.truncate(true);
    }
    let f = o.open(&path.0).map_err(|e| io_err(&e))?;
    Ok(HostFile(HostFileKind::Disk {
        file: f,
        path: path.0.clone(),
    }))
}

/// 目录快照遍历：一次读全目录，按名称排序（确定性，getdents64 输出可测）。
pub(crate) fn open_dir(path: &HostPath) -> Result<HostDir, HostError> {
    let rd = std::fs::read_dir(&path.0).map_err(|e| io_err(&e))?;
    let mut v: Vec<HostDirEntry> = Vec::new();
    for e in rd {
        let e = e.map_err(|e| io_err(&e))?;
        let md = e.metadata().map_err(|e| io_err(&e))?;
        v.push(HostDirEntry {
            name: e.file_name().to_string_lossy().into_owned(),
            is_dir: md.is_dir(),
            ino: path_ino(&e.path()),
        });
    }
    v.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(HostDir::from_parts(path.0.clone(), v))
}

pub(crate) fn mkdir(path: &HostPath) -> Result<(), HostError> {
    std::fs::create_dir(&path.0).map_err(|e| io_err(&e))
}

pub(crate) fn remove(path: &HostPath, dir: bool) -> Result<(), HostError> {
    let r = if dir {
        std::fs::remove_dir(&path.0)
    } else {
        std::fs::remove_file(&path.0)
    };
    r.map_err(|e| io_err(&e))
}

pub(crate) fn rename(old: &HostPath, new: &HostPath) -> Result<(), HostError> {
    std::fs::rename(&old.0, &new.0).map_err(|e| io_err(&e))
}

pub(crate) fn sync_file(f: &HostFile, data_only: bool) -> Result<(), HostError> {
    match &f.0 {
        HostFileKind::Disk { file, .. } => {
            if data_only {
                file.sync_data().map_err(|e| io_err(&e))
            } else {
                file.sync_all().map_err(|e| io_err(&e))
            }
        }
        // stdio 无持久化语义，no-op 成功
        _ => Ok(()),
    }
}

pub(crate) fn dup_file(f: &HostFile) -> Result<HostFile, HostError> {
    match &f.0 {
        HostFileKind::Disk { file, path } => {
            let nf = file.try_clone().map_err(|e| io_err(&e))?;
            Ok(HostFile(HostFileKind::Disk {
                file: nf,
                path: path.clone(),
            }))
        }
        _ => Ok(HostFile(f.0.clone_kind())),
    }
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
        HostFileKind::StdOut => std::io::stdout()
            .write_all(buf)
            .map(|_| buf.len())
            .map_err(|e| io_err(&e)),
        HostFileKind::StdErr => std::io::stderr()
            .write_all(buf)
            .map(|_| buf.len())
            .map_err(|e| io_err(&e)),
        HostFileKind::Disk { file, .. } => (&*file)
            .write_all(buf)
            .map(|_| buf.len())
            .map_err(|e| io_err(&e)),
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
        HostFileKind::StdIn | HostFileKind::StdOut | HostFileKind::StdErr => {
            Ok(HostStat::char_device())
        }
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
    let mode = if md.is_dir() {
        0o0040000 | 0o755
    } else {
        0o0100000 | if ro { 0o444 } else { 0o644 }
    };
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
