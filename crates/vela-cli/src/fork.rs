//! 用户态 fork（PLAN-0.0.6 M1）：spawn-self + 内存快照 + 上下文传递。
//!
//! Linux fork 的本质 = 地址空间副本 + 上下文副本 + fd 表副本。Vela 客户
//! 地址空间完全由本进程持有且规模受控（映像 + 栈/堆，默认 ≤ 24 MiB），
//! 按区间用 inheritable section 传递，子进程 MapViewOfFileEx 回**原地址**
//! （指针一致性的前提），再注入快照的 CONTEXT 从 syscall 返回点继续——
//! 父返回子 pid、子返回 0，Linux 语义完整。
//!
//! 诚实边界（发版写进 SYSCALLS/NONGOALS）：
//! - 快照为全量拷贝（性能非目标）；
//! - mprotect 的运行时历史不传递（恢复时按映像段 prot 收敛）；
//! - HostDir fd 的目录游标重置到开头；
//! - 孤儿子进程无 init 收养，wait4 诚实 -ECHILD。

use std::cell::RefCell;
use std::collections::BTreeMap;

use vela_abi as abi;
use vela_runtime::mem::{InterpImage, LoadedImage, MemKind, MemRange, Segment};
use vela_runtime::{FdTable, GuestFd, GuestProcess};
use vela_sys::{
    HostDir, HostFile, HostFileKind, HostFileOps, HostMem, HostProc, HostProt, TrapFrame,
};

use crate::GuestState;

const META_MAGIC: u32 = 0x5645_4C46; // "VELF"
const META_VERSION: u32 = 2; // 0.1.0 T3.2：+mprotect 账本
/// Linux SIGCHLD；musl fork() = clone(SIGCHLD, 0)。
pub const SIGCHLD_FLAGS: u64 = 17;

// ---------------------------------------------------------------- 定长编解码

struct W {
    buf: Vec<u8>,
}

impl W {
    fn new() -> Self {
        W { buf: Vec::new() }
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    fn u32(&mut self) -> Result<u32, ()> {
        let s = self.b.get(self.p..self.p + 4).ok_or(())?;
        self.p += 4;
        Ok(u32::from_le_bytes(s.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ()> {
        let s = self.b.get(self.p..self.p + 8).ok_or(())?;
        self.p += 8;
        Ok(u64::from_le_bytes(s.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, ()> {
        Ok(self.u64()? as i64)
    }
    fn bytes(&mut self) -> Result<&'a [u8], ()> {
        let n = self.u32()? as usize;
        let s = self.b.get(self.p..self.p + n).ok_or(())?;
        self.p += n;
        Ok(s)
    }
    fn str(&mut self) -> Result<String, ()> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| ())
    }
}

// ---------------------------------------------------------------- 元数据结构

struct RangeSer {
    start: u64,
    len: u64,
    kind: u32, // 0 = Reserve, 1 = FileView
    sec: isize,
}

struct SegSer {
    vaddr: u64,
    file_size: u64,
    mem_size: u64,
    prot: u8,
}

struct LoadSer {
    bias: u64,
    entry: u64,
    phdr: u64,
    phnum: u16,
    phentsize: u16,
    segs: Vec<SegSer>,
    exec_ranges: Vec<(u64, u64)>,
    span_start: u64,
    span_len: u64,
    interp: Option<Box<LoadSer>>,
}

enum FdSer {
    StdIn,
    StdOut,
    StdErr,
    Disk {
        path: String,
        handle: isize,
    },
    PipeRead {
        handle: isize,
    },
    PipeWrite {
        handle: isize,
    },
    HostDir {
        path: String,
        entries: Vec<(String, bool, u64)>,
    },
    Null,
    Zero,
}

struct FdEntrySer {
    fd: i32,
    flags: u32,
    kind: FdSer,
}

struct Meta {
    ppid: u32,
    uid: u32,
    gid: u32,
    fs_base: u64,
    brk_start: u64,
    brk: u64,
    stack_mb: u64,
    heap_mb: u64,
    soft_tls: bool,
    cwd: String,
    heap_start: u64,
    heap_len: u64,
    /// 父 trap 时的客户 CONTEXT（已改写为「clone 已返回 0」形态）。
    ctx: Vec<u8>,
    ranges: Vec<RangeSer>,
    load: LoadSer,
    fds: Vec<FdEntrySer>,
    /// mprotect 账本（T3.2；按应用顺序）。
    prots: Vec<(u64, u64, u8)>,
}

fn w_img(w: &mut W, l: &LoadSer) {
    w.u64(l.bias);
    w.u64(l.entry);
    w.u64(l.phdr);
    w.u32(l.phnum as u32);
    w.u32(l.phentsize as u32);
    w.u32(l.segs.len() as u32);
    for s in &l.segs {
        w.u64(s.vaddr);
        w.u64(s.file_size);
        w.u64(s.mem_size);
        w.u32(s.prot as u32);
    }
    w.u32(l.exec_ranges.len() as u32);
    for (a, b) in &l.exec_ranges {
        w.u64(*a);
        w.u64(*b);
    }
    w.u64(l.span_start);
    w.u64(l.span_len);
    match &l.interp {
        None => w.u32(0),
        Some(i) => {
            w.u32(1);
            w_img(w, i);
        }
    }
}

fn r_img(r: &mut R) -> Result<LoadSer, ()> {
    let bias = r.u64()?;
    let entry = r.u64()?;
    let phdr = r.u64()?;
    let phnum = r.u32()? as u16;
    let phentsize = r.u32()? as u16;
    let ns = r.u32()?;
    let mut segs = Vec::with_capacity(ns as usize);
    for _ in 0..ns {
        segs.push(SegSer {
            vaddr: r.u64()?,
            file_size: r.u64()?,
            mem_size: r.u64()?,
            prot: r.u32()? as u8,
        });
    }
    let ne = r.u32()?;
    let mut exec_ranges = Vec::with_capacity(ne as usize);
    for _ in 0..ne {
        exec_ranges.push((r.u64()?, r.u64()?));
    }
    let span_start = r.u64()?;
    let span_len = r.u64()?;
    let interp = if r.u32()? == 0 {
        None
    } else {
        Some(Box::new(r_img(r)?))
    };
    Ok(LoadSer {
        bias,
        entry,
        phdr,
        phnum,
        phentsize,
        segs,
        exec_ranges,
        span_start,
        span_len,
        interp,
    })
}

fn encode(meta: &Meta) -> Vec<u8> {
    let mut w = W::new();
    w.u32(META_MAGIC);
    w.u32(META_VERSION);
    w.u32(meta.ppid);
    w.u32(meta.uid);
    w.u32(meta.gid);
    w.u64(meta.fs_base);
    w.u64(meta.brk_start);
    w.u64(meta.brk);
    w.u32(meta.stack_mb as u32);
    w.u32(meta.heap_mb as u32);
    w.u32(meta.soft_tls as u32);
    w.str(&meta.cwd);
    w.u64(meta.heap_start);
    w.u64(meta.heap_len);
    w.bytes(&meta.ctx);
    w.u32(meta.ranges.len() as u32);
    for r in &meta.ranges {
        w.u64(r.start);
        w.u64(r.len);
        w.u32(r.kind);
        w.i64(r.sec as i64);
    }
    w_img(&mut w, &meta.load);
    w.u32(meta.fds.len() as u32);
    for f in &meta.fds {
        w.u32(f.fd as u32);
        w.u32(f.flags);
        match &f.kind {
            FdSer::StdIn => w.u32(0),
            FdSer::StdOut => w.u32(1),
            FdSer::StdErr => w.u32(2),
            FdSer::Disk { path, handle } => {
                w.u32(3);
                w.str(path);
                w.i64(*handle as i64);
            }
            FdSer::PipeRead { handle } => {
                w.u32(4);
                w.i64(*handle as i64);
            }
            FdSer::PipeWrite { handle } => {
                w.u32(5);
                w.i64(*handle as i64);
            }
            FdSer::HostDir { path, entries } => {
                w.u32(6);
                w.str(path);
                w.u32(entries.len() as u32);
                for (n, d, i) in entries {
                    w.str(n);
                    w.u32(*d as u32);
                    w.u64(*i);
                }
            }
            FdSer::Null => w.u32(7),
            FdSer::Zero => w.u32(8),
        }
    }
    // mprotect 账本（T3.2）
    w.u32(meta.prots.len() as u32);
    for (start, len, prot) in &meta.prots {
        w.u64(*start);
        w.u64(*len);
        w.u32(*prot as u32);
    }
    w.finish()
}

fn decode(b: &[u8]) -> Result<Meta, ()> {
    let mut r = R { b, p: 0 };
    if r.u32()? != META_MAGIC || r.u32()? != META_VERSION {
        return Err(());
    }
    let ppid = r.u32()?;
    let uid = r.u32()?;
    let gid = r.u32()?;
    let fs_base = r.u64()?;
    let brk_start = r.u64()?;
    let brk = r.u64()?;
    let stack_mb = r.u32()? as u64;
    let heap_mb = r.u32()? as u64;
    let soft_tls = r.u32()? != 0;
    let cwd = r.str()?;
    let heap_start = r.u64()?;
    let heap_len = r.u64()?;
    let ctx = r.bytes()?.to_vec();
    let nr = r.u32()?;
    let mut ranges = Vec::with_capacity(nr as usize);
    for _ in 0..nr {
        ranges.push(RangeSer {
            start: r.u64()?,
            len: r.u64()?,
            kind: r.u32()?,
            sec: r.i64()? as isize,
        });
    }
    let load = r_img(&mut r)?;
    let nf = r.u32()?;
    let mut fds = Vec::with_capacity(nf as usize);
    for _ in 0..nf {
        let fd = r.u32()? as i32;
        let flags = r.u32()?;
        let kind = match r.u32()? {
            0 => FdSer::StdIn,
            1 => FdSer::StdOut,
            2 => FdSer::StdErr,
            3 => FdSer::Disk {
                path: r.str()?,
                handle: r.i64()? as isize,
            },
            4 => FdSer::PipeRead {
                handle: r.i64()? as isize,
            },
            5 => FdSer::PipeWrite {
                handle: r.i64()? as isize,
            },
            6 => {
                let path = r.str()?;
                let n = r.u32()?;
                let mut entries = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let name = r.str()?;
                    let is_dir = r.u32()? != 0;
                    let ino = r.u64()?;
                    entries.push((name, is_dir, ino));
                }
                FdSer::HostDir { path, entries }
            }
            7 => FdSer::Null,
            8 => FdSer::Zero,
            _ => return Err(()),
        };
        fds.push(FdEntrySer { fd, flags, kind });
    }
    // mprotect 账本（T3.2）
    let np = r.u32()?;
    let mut prots = Vec::with_capacity(np as usize);
    for _ in 0..np {
        prots.push((r.u64()?, r.u64()?, r.u32()? as u8));
    }
    Ok(Meta {
        ppid,
        uid,
        gid,
        fs_base,
        brk_start,
        brk,
        stack_mb,
        heap_mb,
        soft_tls,
        cwd,
        heap_start,
        heap_len,
        ctx,
        ranges,
        load,
        fds,
        prots,
    })
}

// ---------------------------------------------------------------- 父侧

/// fd 表序列化（句柄值继承后不变，直接传递）。
fn ser_fds(st: &GuestState) -> Result<Vec<FdEntrySer>, i64> {
    let eio = -(vela_abi::EIO as i64);
    let mut out = Vec::new();
    for (fd, gf) in st.proc.fds.iter() {
        let kind = match gf {
            GuestFd::Host(f) if matches!(f.0, HostFileKind::Disk { .. }) => {
                // Disk 句柄默认不可继承——fork 传递前显式打开继承标志
                let h = f.raw_handle().ok_or(eio)?;
                st.host.set_inherit(h).map_err(|_| eio)?;
                FdSer::Disk {
                    path: f.disk_path().ok_or(eio)?.to_string_lossy().into_owned(),
                    handle: h,
                }
            }
            GuestFd::Host(f) => match f.0 {
                HostFileKind::StdIn => FdSer::StdIn,
                HostFileKind::StdOut => FdSer::StdOut,
                HostFileKind::StdErr => FdSer::StdErr,
                _ => continue, // 未知宿主形态：不继承（诚实缺失）
            },
            GuestFd::PipeRead(f) => FdSer::PipeRead {
                handle: f.raw_handle().ok_or(eio)?,
            },
            GuestFd::PipeWrite(f) => FdSer::PipeWrite {
                handle: f.raw_handle().ok_or(eio)?,
            },
            GuestFd::HostDir(d) => FdSer::HostDir {
                path: d.host_path().to_string_lossy().into_owned(),
                entries: d
                    .clone_remaining()
                    .into_iter()
                    .map(|e| (e.name, e.is_dir, e.ino))
                    .collect(),
            },
            GuestFd::Null => FdSer::Null,
            GuestFd::Zero => FdSer::Zero,
            GuestFd::Reserved => continue,
        };
        let flags = st.proc.fds.get_flags(fd).unwrap_or(0);
        out.push(FdEntrySer { fd, flags, kind });
    }
    Ok(out)
}

/// 把 LoadedImage 转为序列化结构（host_addr == vaddr，见 loader 同进程映射）。
fn ser_img(l: &LoadedImage) -> LoadSer {
    LoadSer {
        bias: l.bias,
        entry: l.entry,
        phdr: l.phdr,
        phnum: l.phnum,
        phentsize: l.phentsize,
        segs: l
            .segments
            .iter()
            .map(|s| SegSer {
                vaddr: s.vaddr,
                file_size: s.file_size,
                mem_size: s.mem_size,
                prot: s.prot,
            })
            .collect(),
        exec_ranges: l.exec_ranges.clone(),
        span_start: l.span.start,
        span_len: l.span.len,
        interp: l.interp.as_ref().map(|i| {
            Box::new(LoadSer {
                bias: i.bias,
                entry: i.entry,
                phdr: 0,
                phnum: 0,
                phentsize: 0,
                segs: vec![],
                exec_ranges: i.exec_ranges.clone(),
                span_start: i.span.start,
                span_len: i.span.len,
                interp: None,
            })
        }),
    }
}

/// fork(2)（CLI trap 层拦截 SYS_CLONE 的 SIGCHLD 形态）。
/// 返回子进程 pid（写入 regs.rax 由 trap 返回路径完成）。
pub fn do_fork(st: &mut GuestState, args: &[u64; 6], frame: &mut TrapFrame) -> Result<u32, i64> {
    let _ = args;
    let eio = -(vela_abi::EIO as i64);
    // 诊断：fork 每步失败点（临时；发版前降为 -v 日志）
    macro_rules! bail {
        ($step:expr, $e:expr) => {{
            eprintln!("[vela] fork: {} failed ({:?})", $step, $e);
            return Err(eio);
        }};
    }

    // 1. 按登记区间创建 section 并拷贝客户内存（父此刻独占客户线程）
    let mut range_sers: Vec<RangeSer> = Vec::new();
    for r in st.proc.mem.ranges.values().copied().collect::<Vec<_>>() {
        let sec = match st.host.shared_section(r.len) {
            Ok(s) => s,
            Err(e) => bail!("create_section", e),
        };
        if let Err(e) = st.host.set_inherit(sec) {
            bail!("inherit(section)", e);
        }
        // SAFETY: view 为本进程刚映射的可写视图；客户区间已登记可读
        let view = match unsafe { st.host.map_section_anywhere(sec) } {
            Ok(v) => v,
            Err(e) => bail!("map_section_anywhere", e),
        };
        // SAFETY: view 为本进程刚映射的可写视图；客户区间已登记可读
        unsafe {
            std::ptr::copy_nonoverlapping(r.start as *const u8, view as *mut u8, r.len as usize);
        }
        let _ = st.host.unmap_section_view(view);
        range_sers.push(RangeSer {
            start: r.start,
            len: r.len,
            kind: match r.kind {
                MemKind::FileView => 1,
                MemKind::Island => 2, // 岛页随快照原样传递（T2.7：子同 VA，E9 有效）
                MemKind::Reserve => 0,
            },
            sec,
        });
    }

    // 2. 元数据：子 CONTEXT = 父快照（宿主完整上下文，含 XSAVE）改写为
    //    「clone 已返回 0」形态——CONTEXT 布局与 flags 细节由宿主封装（T1.2）
    let ctx_bytes = st.host.fork_child_context(frame);

    let meta = Meta {
        ppid: st.host.current_pid(),
        uid: st.proc.uid,
        gid: st.proc.gid,
        fs_base: st.proc.fs_base,
        brk_start: st.proc.brk_start,
        brk: st.proc.brk,
        stack_mb: st.stack_mb,
        heap_mb: st.heap_mb,
        soft_tls: st.soft_tls,
        cwd: st.proc.cwd.clone(),
        heap_start: st.proc.heap.map(|h| h.start).unwrap_or(0),
        heap_len: st.proc.heap.map(|h| h.len).unwrap_or(0),
        ctx: ctx_bytes,
        ranges: range_sers,
        load: ser_img(&st.proc.load),
        fds: ser_fds(st)?,
        prots: st
            .proc
            .prot_ledger
            .iter()
            .map(|p| (p.start, p.len, p.prot))
            .collect(),
    };
    let payload = encode(&meta);

    // 3. 元数据管道（inheritable）+ 长度帧
    let (wmeta, rmeta) = match st.host.create_inherit_pipe() {
        Ok(x) => x,
        Err(e) => bail!("create_inherit_pipe", e),
    };
    if let Err(e) = st.host.set_inherit(wmeta) {
        bail!("inherit(wmeta)", e);
    }
    if let Err(e) = st.host.set_inherit(rmeta) {
        bail!("inherit(rmeta)", e);
    }
    let mut frame_meta = Vec::with_capacity(8 + payload.len());
    frame_meta.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    frame_meta.extend_from_slice(&payload);

    // 4. spawn vela 自身：完整透传父命令行 + --internal-fork <读端句柄>
    let mut cmd = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => bail!("current_exe", e),
    };
    cmd.push_str(" --internal-fork ");
    cmd.push_str(&rmeta.to_string());
    for a in std::env::args().skip(1) {
        cmd.push(' ');
        cmd.push_str(&a);
    }
    // 子进程内 stdio/stderr 继承；元数据写与 spawn 的次序说明：管道缓冲
    //（64KiB）足够容纳元数据（映像内容在 section，不在元数据），先写后
    // spawn 不会阻塞。
    if let Err(e) = st.host.pipe_write_all(wmeta, &frame_meta) {
        bail!("pipe_write_all", e);
    }
    let (child_pid, child_handle) = match st.host.spawn_self(&cmd) {
        Ok(c) => c,
        Err(e) => bail!("create_child_process", e),
    };
    // 写端关闭后子进程读到 EOF；读端句柄归子进程，父侧关闭
    st.host.close_handle(wmeta);
    st.host.close_handle(rmeta);
    for r in &meta.ranges {
        st.host.close_handle(r.sec);
    }

    // 5. 记入子进程表（wait4/kill 用），返回子 pid
    st.children.borrow_mut().insert(child_pid, child_handle);
    Ok(child_pid)
}

// ---------------------------------------------------------------- 子侧

/// `--internal-fork <handle>` 入口：恢复现场并从 fork 返回点继续。
/// opts 为父命令行重放（fs 映射表/stack/heap 配置一致）；不返回。
pub fn internal_fork_main(opts: &crate::RunOpts, meta_handle: isize) -> i32 {
    #[cfg(windows)]
    {
        use vela_sys::HostTrap;
        let host = crate::PlatformHost::new();
        vela_sys::windows::set_console_utf8();

        // 1. 读元数据（长度帧 + payload）
        let mut lenb = [0u8; 8];
        if host.pipe_read_exact(meta_handle, &mut lenb).is_err() {
            return 1;
        }
        let len = u64::from_le_bytes(lenb) as usize;
        let mut payload = vec![0u8; len];
        if host.pipe_read_exact(meta_handle, &mut payload).is_err() {
            return 1;
        }
        host.close_handle(meta_handle);
        let meta = match decode(&payload) {
            Ok(m) => m,
            Err(_) => return 1,
        };

        // 2. 区间恢复：MapViewOfFileEx 回客户原地址（指针一致性前提）
        let mut mem = vela_runtime::mem::MemRegistry::default();
        for r in &meta.ranges {
            let kind = match r.kind {
                1 => MemKind::FileView,
                2 => MemKind::Island,
                _ => MemKind::Reserve,
            };
            // SAFETY: base 在本进程为空闲地址；section 由父继承
            if unsafe { host.map_section_at(r.sec, r.start) }.is_err() {
                return 1;
            }
            let range = match kind {
                MemKind::FileView => MemRange::view(r.start, r.len),
                MemKind::Island => MemRange::island(r.start, r.len),
                MemKind::Reserve => MemRange::reserve(r.start, r.len),
            };
            mem.add(range);
        }

        // 3. 重建 LoadedImage（host_addr == vaddr，同进程映射约定）
        // syscall_sites 置空：子进程不重建岛（快照已含岛页，E9 保持有效）
        let rebuild = |l: &LoadSer| -> LoadedImage {
            LoadedImage {
                bias: l.bias,
                entry: l.entry,
                phdr: l.phdr,
                phnum: l.phnum,
                phentsize: l.phentsize,
                segments: l
                    .segs
                    .iter()
                    .map(|s| Segment {
                        vaddr: s.vaddr,
                        host_addr: s.vaddr as usize,
                        file_size: s.file_size,
                        mem_size: s.mem_size,
                        prot: s.prot,
                    })
                    .collect(),
                exec_ranges: l.exec_ranges.clone(),
                syscall_sites: Vec::new(),
                span: MemRange::reserve(l.span_start, l.span_len),
                interp: None,
            }
        };
        let mut load = rebuild(&meta.load);
        if let Some(i) = &meta.load.interp {
            let irebuild = rebuild(i);
            load.interp = Some(InterpImage {
                bias: irebuild.bias,
                entry: irebuild.entry,
                span: irebuild.span,
                exec_ranges: irebuild.exec_ranges,
                syscall_sites: Vec::new(),
            });
        }

        // 4. 组装 GuestProcess（pid = 真实 Windows pid；ppid 来自父）
        let mut proc = GuestProcess::new(host.current_pid(), load);
        proc.ppid = meta.ppid;
        proc.uid = meta.uid;
        proc.gid = meta.gid;
        proc.fs_base = meta.fs_base;
        proc.brk_start = meta.brk_start;
        proc.brk = meta.brk;
        proc.cwd = meta.cwd.clone();
        proc.mem = mem;
        if meta.heap_len > 0 {
            proc.heap = Some(MemRange::reserve(meta.heap_start, meta.heap_len));
        }

        // 5. fd 表重建（句柄已继承，值不变）
        let mut fds = FdTable::empty();
        for f in &meta.fds {
            let entry = match &f.kind {
                FdSer::StdIn | FdSer::StdOut | FdSer::StdErr => {
                    // stdio 经宿主 stdio() 重取（继承的标准句柄）
                    let s = host.stdio();
                    match f.kind {
                        FdSer::StdIn => GuestFd::Host(s.stdin),
                        FdSer::StdOut => GuestFd::Host(s.stdout),
                        _ => GuestFd::Host(s.stderr),
                    }
                }
                FdSer::Disk { path, handle } => {
                    // SAFETY: handle 为父进程继承而来的有效文件句柄
                    GuestFd::Host(unsafe {
                        HostFile::disk_from_raw_handle(*handle, std::path::PathBuf::from(path))
                    })
                }
                FdSer::PipeRead { handle } => GuestFd::PipeRead(HostFile(HostFileKind::Pipe(
                    host.pipe_end_from_raw(*handle, true),
                ))),
                FdSer::PipeWrite { handle } => GuestFd::PipeWrite(HostFile(HostFileKind::Pipe(
                    host.pipe_end_from_raw(*handle, false),
                ))),
                FdSer::HostDir { path, entries } => GuestFd::HostDir(HostDir::from_parts(
                    std::path::PathBuf::from(path),
                    entries
                        .iter()
                        .map(|(n, d, i)| vela_sys::HostDirEntry {
                            name: n.clone(),
                            is_dir: *d,
                            ino: *i,
                        })
                        .collect(),
                )),
                FdSer::Null => GuestFd::Null,
                FdSer::Zero => GuestFd::Zero,
            };
            fds.insert_at(f.fd, entry);
            fds.set_flags(f.fd, f.flags);
        }
        proc.fds = fds;

        // 6. fs 映射表：从父命令行重放（--root/--map 语义一致）
        let mut fs = vela_fs::FsMap::legacy();
        if let Some(root) = &opts.root {
            let _ = fs.add("/", std::path::Path::new(root));
        }
        for m in &opts.maps {
            if let Some((g, h)) = m.split_once('=') {
                let _ = fs.add(g, std::path::Path::new(h));
            }
        }
        proc.fs = fs;

        // 7. 保护位收敛：mprotect 运行时历史不传递，按映像段 prot 恢复
        for s in &proc.load.segments {
            // SAFETY: 区间来自本进程 section 映射，归客户管理
            let _ = unsafe {
                host.protect(
                    s.vaddr as usize,
                    s.mem_size as usize,
                    HostProt::from_bits(s.prot as u32),
                )
            };
        }
        if let Some(i) = &proc.load.interp {
            // 解释器段信息未逐段传递（exec_ranges/span 已含）；保持 RW→由
            // 客户按需 mprotect——与 0.0.4 的 donate 语义一致性已标注
            let _ = i;
        }
        // 7b. mprotect 账本重放（T3.2）：映像段收敛后按父进程运行时顺序
        //     重放保护变更（子进程区间为 section 视图非 COW，W 合法）
        for (start, len, prot) in &meta.prots {
            // SAFETY: 区间来自快照 section 映射，归客户管理
            let _ = unsafe {
                host.protect(
                    *start as usize,
                    *len as usize,
                    HostProt::from_bits(*prot as u32),
                )
            };
        }

        // 8. VELA 客户机制装配
        let state = Box::new(GuestState {
            proc,
            host,
            stack_mb: meta.stack_mb,
            heap_mb: meta.heap_mb,
            soft_tls: meta.soft_tls,
            children: RefCell::new(BTreeMap::new()),
            sigchld_reaped: std::cell::Cell::new(0),
            trap: crate::TrapBackend::Auto, // 父进程已建岛（快照含岛页），子进程沿用
        });
        let ptr = Box::into_raw(state);
        crate::GUEST.store(ptr, std::sync::atomic::Ordering::Relaxed);
        let st = unsafe { &*ptr };
        let mut exec_ranges = st.proc.load.exec_ranges.clone();
        if let Some(i) = &st.proc.load.interp {
            exec_ranges.extend(i.exec_ranges.iter().copied());
        }
        st.host.replace_exec_ranges(&exec_ranges);
        if st.host.install_trap(crate::trap).is_err() {
            return 1;
        }
        if meta.soft_tls {
            st.host.enable_soft_tls();
            if meta.fs_base != 0 {
                st.host.set_soft_tls_base(meta.fs_base);
            }
        } else if st.host.fs_base_supported() && meta.fs_base != 0 {
            // 真实 TLS 基址一次到位；commit 强制内核按此值重建保存状态
            let _ = st.host.preset_fs_base(meta.fs_base);
            st.host.commit_fs_base();
        }

        // 9. 注入 CONTEXT 从 fork 返回点继续（rax=0 = 子返回值）
        if meta.ctx.len() != 0x4D0 {
            return 1;
        }
        // SAFETY: 客户栈/代码/堆均已恢复到原地址且登记
        unsafe { st.host.resume_child(&meta.ctx) }
    }
    #[cfg(not(windows))]
    {
        let _ = (opts, meta_handle);
        1
    }
}

// ---------------------------------------------------------------- wait4 / kill

/// wait4(61) 真实化（CLI trap 层）：等子进程句柄，编码 Linux status。
/// status/rusage 由本函数写入客户内存，返回等待到的子 pid（WNOHANG 无子退出 → 0）。
pub fn do_wait4(st: &mut GuestState, args: &[u64; 6]) -> i64 {
    let (pid, stat_ptr, opts, _r0, rusage, _r5) =
        (args[0] as i64, args[1], args[2], args[3], args[4], args[5]);
    const WNOHANG: u64 = 1;

    // 选子进程：pid>0 精确；-1 任意；其余（pgid 形态）诚实 ECHILD
    let find = |children: &BTreeMap<u32, isize>| -> Option<u32> {
        if pid > 0 {
            let p = pid as u32;
            children.contains_key(&p).then_some(p)
        } else if pid == -1 {
            children.keys().next().copied()
        } else {
            None
        }
    };
    let child = match find(&st.children.borrow()) {
        Some(c) => c,
        None => return -(abi::ECHILD as i64),
    };
    let handle = st.children.borrow()[&child];

    const INFINITE: u32 = 0xFFFF_FFFF;
    let timeout = if opts & WNOHANG != 0 { 0 } else { INFINITE };
    let code = match st.host.wait(handle, timeout) {
        Ok(Some(c)) => c,
        Ok(None) => return 0, // WNOHANG 无子退出 → 返回 0
        Err(_) => return -(abi::ECHILD as i64),
    };

    // Linux status 编码：退出码 <128 → WIFEXITED（code<<8）；
    // ≥128（128+sig 惯例：崩溃 139 / kill 137 等）→ WIFSIGNALED
    let status: u32 = if (128..160).contains(&code) {
        code - 128 // WIFSIGNALED: 低 7 位 = 终止信号
    } else {
        (code & 0xFF) << 8 // WIFEXITED
    };
    if stat_ptr != 0
        && vela_runtime::write_guest(&st.proc, stat_ptr, &status.to_le_bytes()).is_err()
    {
        return -(abi::EFAULT as i64);
    }
    if rusage != 0 {
        // rusage 诚实填零（无记账）
        let _ = vela_runtime::write_guest(&st.proc, rusage, &[0u8; 144]);
    }
    st.children.borrow_mut().remove(&child);
    st.host.close_handle(handle);
    // T3.6 SIGCHLD 记账：wait 回收即置位（不投递 handler，NONGOALS）
    st.sigchld_reaped.set(st.sigchld_reaped.get() + 1);
    child as i64
}

/// kill(62) 最小集（M3）：SIGKILL/SIGTERM → TerminateProcess；sig 0 → 探测。
pub fn do_kill(st: &mut GuestState, pid: u64, sig: u64) -> i64 {
    let pid = pid as i64;
    if pid <= 0 {
        // 进程组形态：诚实 ENOSYS（vela 无进程组记账）
        return -(abi::ENOSYS as i64);
    }
    let pid = pid as u32;
    if sig == 0 {
        // 探测：子进程表命中即存在；否则试探性 OpenProcess
        if st.children.borrow().contains_key(&pid) {
            return 0;
        }
        return match st.host.open_process(pid) {
            Ok(h) => {
                st.host.close_handle(h);
                0
            }
            Err(vela_sys::HostError::NotFound) => -(abi::ESRCH as i64),
            Err(_) => 0, // 存在但无权限——探测语义按存在处理
        };
    }
    if sig != 9 && sig != 15 {
        // 信号投递未实现（NONGOALS）：SIGKILL/SIGTERM 之外诚实 ENOSYS
        return -(abi::ENOSYS as i64);
    }
    // 优先子进程表（常驻句柄）；否则按 pid 打开
    let h = match st.children.borrow().get(&pid) {
        Some(h) => Some(*h),
        None => st.host.open_process(pid).ok(),
    };
    match h {
        Some(h) => {
            let r = st.host.kill(h, 128 + sig as u32);
            // open 出来的句柄用完即关；children 里的句柄留给 wait4 回收
            if !st.children.borrow().contains_key(&pid) {
                st.host.close_handle(h);
            }
            match r {
                Ok(()) => 0,
                Err(_) => -(abi::ESRCH as i64),
            }
        }
        None => -(abi::ESRCH as i64),
    }
}

/// Ctrl+C：终止全部子进程（控制台进程组近似）。
#[allow(dead_code)] // M3 接线 SetConsoleCtrlHandler 时启用
pub fn terminate_all_children(st: &GuestState) {
    for h in st.children.borrow().values() {
        let _ = st.host.kill(*h, 128 + 15); // SIGTERM 惯例码
    }
}
