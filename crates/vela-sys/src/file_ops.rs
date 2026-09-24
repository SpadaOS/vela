//! 基于 std 的文件/时间公共实现，供 windows 与 linux_dev 两个宿主复用。

use std::time::Instant;

use crate::{
    HostDir, HostDirEntry, HostError, HostFile, HostFileKind, HostOpen, HostPath, HostStat,
    PipeEnd, PipeEndInner, StdioHandles,
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
        109 => 32,     // ERROR_BROKEN_PIPE（读端全关）→ EPIPE
        232 => 32,     // ERROR_NO_DATA（同上，写管道变体）→ EPIPE
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
        file: crate::DiskFile(f),
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
                file.0.sync_data().map_err(|e| io_err(&e))
            } else {
                file.0.sync_all().map_err(|e| io_err(&e))
            }
        }
        // stdio 无持久化语义，no-op 成功
        _ => Ok(()),
    }
}

pub(crate) fn dup_file(f: &HostFile) -> Result<HostFile, HostError> {
    match &f.0 {
        HostFileKind::Disk { file, path } => {
            let nf = file.0.try_clone().map_err(|e| io_err(&e))?;
            Ok(HostFile(HostFileKind::Disk {
                file: crate::DiskFile(nf),
                path: path.clone(),
            }))
        }
        // 管道端：真实句柄必须 DuplicateHandle（裸 clone 会 double-close）
        HostFileKind::Pipe(e) => Ok(HostFile(HostFileKind::Pipe(e.dup()?))),
        _ => Ok(HostFile(f.0.clone_kind())),
    }
}

pub(crate) fn read(f: &HostFile, buf: &mut [u8]) -> Result<usize, HostError> {
    use std::io::Read;
    match &f.0 {
        HostFileKind::StdIn => std::io::stdin().read(buf).map_err(|e| io_err(&e)),
        HostFileKind::Disk { file, .. } => (&file.0).read(buf).map_err(|e| io_err(&e)),
        HostFileKind::Pipe(e) => e.read(buf),
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
        HostFileKind::Disk { file, .. } => (&file.0)
            .write_all(buf)
            .map(|_| buf.len())
            .map_err(|e| io_err(&e)),
        HostFileKind::Pipe(e) => e.write(buf),
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
        HostFileKind::Disk { file, .. } => (&file.0).seek(from).map_err(|e| io_err(&e)),
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
        HostFileKind::Pipe(_) => Ok(fifo_stat()),
        HostFileKind::Disk { file, path } => {
            let md = file.0.metadata().map_err(|e| io_err(&e))?;
            Ok(host_stat_from(&md, Some(path)))
        }
    }
}

/// FIFO 元数据（pipe fd 的 fstat；S_IFIFO | 0600，Linux 管道默认权限）。
pub fn fifo_stat() -> HostStat {
    HostStat {
        size: 0,
        is_dir: false,
        is_readonly: false,
        mtime_ns: 0,
        mode: 0o0010000 | 0o600, // S_IFIFO | 0600
        nlink: 1,
        ino: 1,
        dev: 1,
        atime_ns: 0,
        ctime_ns: 0,
    }
}

/// utimensat 语义：设置 atime/mtime（T3.5）。None = UTIME_OMIT。
/// std File::set_times（1.75+）：需写方式打开以取 FILE_WRITE_ATTRIBUTES。
/// ctime 无 Windows 对应，诚实忽略。
pub(crate) fn set_times(
    path: &HostPath,
    atime: Option<(i64, i64)>,
    mtime: Option<(i64, i64)>,
) -> Result<(), HostError> {
    use std::fs::FileTimes;
    if atime.is_none() && mtime.is_none() {
        return Ok(()); // 全 OMIT：no-op
    }
    let ts = |t: Option<(i64, i64)>| -> Option<std::time::SystemTime> {
        t.map(|(sec, nsec)| {
            let dur = std::time::Duration::new(sec.unsigned_abs(), nsec.unsigned_abs().min(999_999_999) as u32);
            if sec >= 0 {
                std::time::UNIX_EPOCH + dur
            } else {
                std::time::UNIX_EPOCH - dur
            }
        })
    };
    let mut times = FileTimes::new();
    if let Some(a) = ts(atime) {
        times = times.set_accessed(a);
    }
    if let Some(m) = ts(mtime) {
        times = times.set_modified(m);
    }
    // SAFETY: 无；std 接口
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&path.0)
        .map_err(|e| io_err(&e))?;
    f.set_times(times).map_err(|e| io_err(&e))
}

/// ftruncate 语义：截断/扩展已打开文件（std File::set_len，含 Windows）。
pub(crate) fn set_len(f: &HostFile, len: u64) -> Result<(), HostError> {
    match &f.0 {
        HostFileKind::Disk { file, .. } => file.0.set_len(len).map_err(|e| io_err(&e)),
        _ => Err(HostError::Invalid),
    }
}

/// fchmod 的 Windows 诚实近似：仅读写位（readonly=true → 去写权限）。
pub(crate) fn set_readonly(f: &HostFile, readonly: bool) -> Result<(), HostError> {
    match &f.0 {
        HostFileKind::Disk { path, .. } => {
            let md = std::fs::metadata(path).map_err(|e| io_err(&e))?;
            let mut perm = md.permissions();
            perm.set_readonly(readonly);
            std::fs::set_permissions(path, perm).map_err(|e| io_err(&e))
        }
        _ => Err(HostError::Invalid),
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
        // 管道端：真实句柄 CloseHandle；内存端标记半关（对端看到 EOF/EPIPE）
        HostFileKind::Pipe(e) => e.close_half(),
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

// ---------------------------------------------------------------- 匿名管道

/// pipe2 的宿主实现（0.0.6 M1 T1.1）。Windows：CreatePipe + 两端句柄
/// inheritable（fork 的跨进程传递前提）；测试/逻辑宿主：内存管道。
pub(crate) fn create_pipe() -> Result<(HostFile, HostFile), HostError> {
    #[cfg(windows)]
    {
        let (r, w) = pipe_handles()?;
        Ok((
            HostFile(HostFileKind::Pipe(PipeEnd(PipeEndInner::Handle(r)))),
            HostFile(HostFileKind::Pipe(PipeEnd(PipeEndInner::Handle(w)))),
        ))
    }
    #[cfg(not(windows))]
    {
        let m = std::sync::Arc::new(crate::PipeMem::new());
        Ok((
            HostFile(HostFileKind::Pipe(PipeEnd(PipeEndInner::Mem(
                m.clone(),
                true,
            )))),
            HostFile(HostFileKind::Pipe(PipeEnd(PipeEndInner::Mem(m, false)))),
        ))
    }
}

impl PipeEnd {
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, HostError> {
        match &self.0 {
            #[cfg(windows)]
            PipeEndInner::Handle(h) => {
                let mut got: u32 = 0;
                // SAFETY: h 为 CreatePipe 返回的有效读句柄；buf/n 配对
                let ok = unsafe {
                    ReadFile(
                        *h,
                        buf.as_mut_ptr(),
                        buf.len().min(u32::MAX as usize) as u32,
                        &mut got,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    let e = unsafe { GetLastError() };
                    // ERROR_BROKEN_PIPE 表示写端已全关——对读端是 EOF 而非错误
                    if e == 109 {
                        return Ok(0);
                    }
                    return Err(HostError::Other(os_to_errno(e as i32)));
                }
                Ok(got as usize)
            }
            #[cfg(not(windows))]
            PipeEndInner::Handle(_) => Err(HostError::Unimplemented),
            PipeEndInner::Mem(m, _is_read) => {
                let mut b = m.buf.lock().unwrap_or_else(|p| p.into_inner());
                if b.is_empty() {
                    // mock 语义：空且写端开 → EAGAIN（假非阻塞，供单测驱动）
                    if m.write_open.load(std::sync::atomic::Ordering::SeqCst) {
                        return Err(HostError::Other(11)); // EAGAIN
                    }
                    return Ok(0); // 写端全关 → EOF
                }
                let n = buf.len().min(b.len());
                buf[..n].copy_from_slice(&b[..n]);
                b.drain(..n);
                Ok(n)
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, HostError> {
        match &self.0 {
            #[cfg(windows)]
            PipeEndInner::Handle(h) => {
                let mut put: u32 = 0;
                // SAFETY: h 为 CreatePipe 返回的有效写句柄；buf/n 配对
                let ok = unsafe {
                    WriteFile(
                        *h,
                        buf.as_ptr(),
                        buf.len().min(u32::MAX as usize) as u32,
                        &mut put,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    let e = unsafe { GetLastError() };
                    return Err(HostError::Other(os_to_errno(e as i32)));
                }
                Ok(put as usize)
            }
            #[cfg(not(windows))]
            PipeEndInner::Handle(_) => Err(HostError::Unimplemented),
            PipeEndInner::Mem(m, _is_read) => {
                if !m.read_open.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(HostError::Other(32)); // EPIPE
                }
                m.buf
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
        }
    }

    /// 关闭本端（close 语义）。Handle → CloseHandle；Mem → 标记本端半关。
    pub fn close_half(&self) -> Result<(), HostError> {
        match &self.0 {
            #[cfg(windows)]
            PipeEndInner::Handle(h) => {
                // SAFETY: h 为本端独占句柄，close 后不再使用
                if unsafe { CloseHandle(*h) } == 0 {
                    return Err(HostError::Other(os_to_errno(
                        unsafe { GetLastError() } as i32
                    )));
                }
                Ok(())
            }
            #[cfg(not(windows))]
            PipeEndInner::Handle(_) => Err(HostError::Unimplemented),
            PipeEndInner::Mem(m, is_read) => {
                use std::sync::atomic::Ordering;
                if *is_read {
                    // 读端关闭 → 写端写时 EPIPE
                    m.read_open.store(false, Ordering::SeqCst);
                } else {
                    // 写端关闭 → 读端读到 EOF
                    m.write_open.store(false, Ordering::SeqCst);
                }
                Ok(())
            }
        }
    }

    /// dup 语义：Windows DuplicateHandle（新句柄独立可关），内存端共享克隆。
    pub fn dup(&self) -> Result<PipeEnd, HostError> {
        match &self.0 {
            #[cfg(windows)]
            PipeEndInner::Handle(h) => {
                const DUPLICATE_SAME_ACCESS: u32 = 2;
                let mut nh: isize = 0;
                // SAFETY: -1 = 伪当前进程句柄；h/nh 均为有效句柄位址
                let ok = unsafe {
                    DuplicateHandleI(
                        -1,
                        *h,
                        -1,
                        &mut nh,
                        0,
                        1, // inheritable —— fork 传递语义与原句柄一致
                        DUPLICATE_SAME_ACCESS,
                    )
                };
                if ok == 0 {
                    return Err(HostError::Other(os_to_errno(
                        unsafe { GetLastError() } as i32
                    )));
                }
                Ok(PipeEnd(PipeEndInner::Handle(nh)))
            }
            #[cfg(not(windows))]
            PipeEndInner::Handle(_) => Err(HostError::Unimplemented),
            PipeEndInner::Mem(m, is_read) => Ok(PipeEnd(PipeEndInner::Mem(m.clone(), *is_read))),
        }
    }

    /// 原始句柄（fork 元数据传递用；内存端返回 None）。
    pub fn raw_handle(&self) -> Option<isize> {
        match &self.0 {
            #[cfg(windows)]
            PipeEndInner::Handle(h) => Some(*h),
            #[cfg(not(windows))]
            PipeEndInner::Handle(_) => None,
            PipeEndInner::Mem(..) => None,
        }
    }
}

#[cfg(windows)]
pub(crate) fn pipe_handles() -> Result<(isize, isize), HostError> {
    use std::mem::size_of;
    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        desc: *mut core::ffi::c_void,
        inherit: i32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreatePipe(
            read: *mut isize,
            write: *mut isize,
            attr: *const SecurityAttributes,
            size: u32,
        ) -> i32;
        fn SetHandleInformation(h: isize, mask: u32, flags: u32) -> i32;
    }
    let mut r: isize = 0;
    let mut w: isize = 0;
    let sa = SecurityAttributes {
        n_length: size_of::<SecurityAttributes>() as u32,
        desc: std::ptr::null_mut(),
        inherit: 1, // fork 的句柄继承前提
    };
    // SAFETY: 输出指针与 SA 均有效；64KiB 缓冲与 Linux 默认一致
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 64 * 1024) } == 0 {
        return Err(HostError::Other(os_to_errno(
            unsafe { GetLastError() } as i32
        )));
    }
    const HANDLE_FLAG_INHERIT: u32 = 0x1;
    // SAFETY: 两个句柄均为本函数刚创建的有效句柄
    if unsafe { SetHandleInformation(r, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0
        || unsafe { SetHandleInformation(w, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0
    {
        let e = unsafe { GetLastError() };
        unsafe {
            CloseHandle(r);
            CloseHandle(w);
        }
        return Err(HostError::Other(os_to_errno(e as i32)));
    }
    Ok((r, w))
}

/// 原始管道句柄写（fork 元数据通道用）。Some(raw_err) = 失败。
#[cfg(windows)]
pub(crate) fn pipe_write_raw(h: isize, data: &[u8]) -> Option<u32> {
    let mut off = 0;
    while off < data.len() {
        let mut put: u32 = 0;
        // SAFETY: h 为有效写句柄；切片边界配对
        let ok = unsafe {
            WriteFile(
                h,
                data[off..].as_ptr(),
                (data.len() - off).min(u32::MAX as usize) as u32,
                &mut put,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Some(unsafe { GetLastError() });
        }
        off += put as usize;
    }
    None
}

/// 原始管道句柄读（fork 元数据通道用）。Some(raw_err) = 失败。
#[cfg(windows)]
pub(crate) fn pipe_read_raw(h: isize, buf: &mut [u8]) -> Result<usize, u32> {
    let mut got: u32 = 0;
    // SAFETY: h 为有效读句柄；切片边界配对
    let ok = unsafe {
        ReadFile(
            h,
            buf.as_mut_ptr(),
            buf.len().min(u32::MAX as usize) as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(got as usize)
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn ReadFile(
        h: isize,
        buf: *mut u8,
        n: u32,
        read: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn WriteFile(
        h: isize,
        buf: *const u8,
        n: u32,
        written: *mut u32,
        overlapped: *mut core::ffi::c_void,
    ) -> i32;
    fn CloseHandle(h: isize) -> i32;
    fn GetLastError() -> u32;
    #[link_name = "DuplicateHandle"]
    fn DuplicateHandleI(
        src_proc: isize,
        src: isize,
        dst_proc: isize,
        dst: *mut isize,
        access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
}
