//! vela：Windows 用户态 Linux x86_64 ELF 翻译运行时 CLI（规格 5.6）。
//!
//! 用法：
//!   vela run <linux-elf> [guest-args...]
//!   vela --version
//!   vela --help
//!
//! 退出码：客户 exit 的码；文件缺失 127；ELF 格式错误 1；CLI 用法错误 2。

mod fork;
mod guest_start;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicPtr, Ordering};

use vela_loader as loader;
use vela_runtime::{GuestProcess, InterpImage};
#[cfg(windows)]
use vela_sys::{HostMem, HostProc, HostTrap, TrapFrame};

#[cfg(target_os = "linux")]
use vela_sys::linux_dev::LinuxDevHost;
#[cfg(windows)]
use vela_sys::windows::{set_console_utf8, WindowsHost};

#[cfg(windows)]
type PlatformHost = WindowsHost;
#[cfg(target_os = "linux")]
type PlatformHost = LinuxDevHost;

// 规格建议的映射提示基址（0x0000_4000_0000 附近空洞）；冲突时 host 回退让系统自选
const GUEST_HINT: u64 = 0x0000_4000_0000;

struct GuestState {
    proc: GuestProcess,
    host: PlatformHost,
    /// execve 重载时重建堆/栈所需（PLAN-0.0.4 T3.1）。
    stack_mb: u64,
    heap_mb: u64,
    /// soft-tls 开关（fork 子进程继承，0.0.6 M1）。
    soft_tls: bool,
    /// 存活子进程表（0.0.6 M1：pid → hProcess 常驻句柄，wait4/kill 用）。
    children: RefCell<BTreeMap<u32, isize>>,
    /// 陷阱后端选择（0.1.0 T2.6；execve 重载沿用）。
    trap: TrapBackend,
}

static GUEST: AtomicPtr<GuestState> = AtomicPtr::new(std::ptr::null_mut());

fn main() {
    logx::init();
    let code = real_main();
    std::process::exit(code);
}

fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {
            print_usage();
            2
        }
        Some("--help" | "-h") => {
            print_usage();
            0
        }
        Some("--version" | "-V") => {
            println!("vela {}", env!("CARGO_PKG_VERSION"));
            0
        }
        // fork 子进程入口（0.0.6 M1）：父 spawn 自身并透传全部原始参数，
        // 本分支在正常解析前拦截元数据句柄，随后按原路径重放（fs 表等）
        Some("--internal-fork") => {
            let h: isize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            if h == 0 {
                eprintln!("vela: --internal-fork requires a handle (internal use only)");
                return 2;
            }
            cmd_run(&args[2..], Some(h))
        }
        Some("run") => cmd_run(&args[1..], None),
        Some("doctor") => cmd_doctor(),
        Some(other) => {
            eprintln!("vela: unknown command '{other}'");
            print_usage();
            2
        }
    }
}

fn print_usage() {
    eprintln!("usage: vela run [options] <linux-elf> [guest-args...]");
    eprintln!("       vela --version");
    eprintln!("       vela --help");
    eprintln!("options:");
    eprintln!("  --root <dir>       把宿主目录挂为客户根（guest / = <dir>）");
    eprintln!("  --map <g>=<host>   追加前缀映射（可多次；默认 /mnt/c -> C:\\）");
    eprintln!("  --env K=V          传递/覆盖环境变量；K= 表示删除（默认继承宿主全部）");
    eprintln!("  --uid <n> --gid <n>  客户 uid/gid（默认 1000）");
    eprintln!("  --interp <host-path> 动态链接解释器（默认：fs 映射解析 PT_INTERP 路径，");
    eprintln!("                       回退到 guest ELF 同目录下的同名文件）");
    eprintln!("  --stack-mb <n>     客户栈大小 MiB（默认 8，1-512）");
    eprintln!("  --heap-mb <n>      客户堆大小 MiB（默认 8，1-1024）");
    eprintln!("  -v                 syscall 日志到 stderr（或 VELA_LOG=1）");
    eprintln!("  --soft-tls         实验开关：FSGSBASE 缺失环境下软件模拟客户 fs 段");
    eprintln!("                     访问（诊断/CI 可用，性能不承诺）");
    eprintln!("  --trap=<backend>   陷阱后端：island|veh|auto（默认 auto = 岛页跳板，");
    eprintln!("                     校验不过的点位混合 VEH；veh = 0.0.6 行为）");
    eprintln!("env:   VELA_LOG=1 或 -v 打印 syscall 日志到 stderr");
}

/// 陷阱后端选择（PLAN-0.1.0 T2.6）。auto = 岛页优先、校验不过的点混合 VEH。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrapBackend {
    Auto,
    Veh,
    Island,
}

/// run 子命令的选项（解析自 elf 路径之前）。
struct RunOpts {
    verbose: bool,
    root: Option<String>,
    maps: Vec<String>,
    envs: Vec<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    stack_mb: u64,
    heap_mb: u64,
    interp: Option<String>,
    soft_tls: bool,
    trap: TrapBackend,
}

fn cmd_run(rest: &[String], internal_fork: Option<isize>) -> i32 {
    let mut opts = RunOpts {
        verbose: false,
        root: None,
        maps: Vec::new(),
        envs: Vec::new(),
        uid: None,
        gid: None,
        stack_mb: 8,
        heap_mb: 8,
        interp: None,
        soft_tls: false,
        trap: TrapBackend::Auto,
    };
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0;
    // 选项只在 elf 路径之前；elf 之后的参数全部透传给客户
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "-v" => opts.verbose = true,
            "--root" => {
                let Some(v) = rest.get(i + 1) else {
                    return usage_err("--root 需要参数");
                };
                opts.root = Some(v.clone());
                i += 1;
            }
            "--map" => {
                let Some(v) = rest.get(i + 1) else {
                    return usage_err("--map 需要参数");
                };
                opts.maps.push(v.clone());
                i += 1;
            }
            "--env" => {
                let Some(v) = rest.get(i + 1) else {
                    return usage_err("--env 需要参数");
                };
                opts.envs.push(v.clone());
                i += 1;
            }
            "--interp" => {
                let Some(v) = rest.get(i + 1) else {
                    return usage_err("--interp 需要参数");
                };
                opts.interp = Some(v.clone());
                i += 1;
            }
            "--soft-tls" => {
                opts.soft_tls = true;
            }
            a if a == "--trap" || a.starts_with("--trap=") => {
                // --trap=veh|island|auto 与 --trap veh|island|auto 两种形式
                let (v, consumed) = match a.split_once('=') {
                    Some((_, v)) => (v, false),
                    None => match rest.get(i + 1) {
                        Some(v) => (v.as_str(), true),
                        None => return usage_err("--trap 需要参数"),
                    },
                };
                opts.trap = match v {
                    "veh" => TrapBackend::Veh,
                    "island" => TrapBackend::Island,
                    "auto" => TrapBackend::Auto,
                    other => {
                        return usage_err(&format!("--trap 未知后端 '{other}'（veh|island|auto）"))
                    }
                };
                if consumed {
                    i += 1;
                }
            }
            "--uid" | "--gid" | "--stack-mb" | "--heap-mb" => {
                let Some(v) = rest.get(i + 1) else {
                    return usage_err(&format!("{a} 需要参数"));
                };
                let n: u64 = match v.parse() {
                    Ok(n) => n,
                    Err(_) => return usage_err(&format!("{a} 需要非负整数")),
                };
                match a {
                    "--uid" => opts.uid = Some(n as u32),
                    "--gid" => opts.gid = Some(n as u32),
                    "--stack-mb" => opts.stack_mb = n.clamp(1, 512),
                    "--heap-mb" => opts.heap_mb = n.clamp(1, 1024),
                    _ => unreachable!(),
                }
                i += 1;
            }
            s if s.starts_with('-') && s != "-" => {
                eprintln!("vela: unknown option '{s}'");
                print_usage();
                return 2;
            }
            _ => {
                // elf 路径：从这里开始全部是位置参数
                while i < rest.len() {
                    pos.push(rest[i].clone());
                    i += 1;
                }
                break;
            }
        }
        i += 1;
    }
    if opts.verbose {
        logx::enable();
    }
    // fork 子进程分支（0.0.6 M1）：跳过 ELF 读/装载，直接从快照恢复现场
    if let Some(h) = internal_fork {
        #[cfg(windows)]
        return fork::internal_fork_main(&opts, h);
        #[cfg(not(windows))]
        {
            let _ = h;
            eprintln!("vela: guest execution is only supported on Windows in v0");
            return 1;
        }
    }
    let Some(elf) = pos.first() else {
        print_usage();
        return 2;
    };
    // 客户 argv[0] = 传入的 ELF 路径，其余为附加参数（规格 4）
    let guest_argv: Vec<String> = pos.clone();
    match run_elf(elf, &guest_argv, &opts) {
        Ok(never) => match never {},
        Err(code) => code,
    }
}

fn usage_err(msg: &str) -> i32 {
    eprintln!("vela: {msg}");
    print_usage();
    2
}

/// 解释器宿主路径解析（PLAN-0.0.4 T2.2）：
/// 1. --interp 显式指定（最高优先）；
/// 2. fs 映射翻译 PT_INTERP 客户路径（如 --map /lib=D:\musl\lib）；
/// 3. 回退：guest ELF 同目录下的同名文件（guest/bin/hello-dyn + ld-musl-*.so.1）。
fn resolve_interp(
    fs: &vela_fs::FsMap,
    gpath: &str,
    elf_path: &str,
    explicit: &Option<String>,
) -> std::path::PathBuf {
    if let Some(p) = explicit {
        return std::path::PathBuf::from(p);
    }
    if let Some(hp) = fs.translate(gpath) {
        if hp.exists() {
            return hp;
        }
    }
    let base = std::path::Path::new(elf_path)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let name = gpath.rsplit('/').next().unwrap_or(gpath);
    base.join(name)
}

/// execve 的可执行文件路径解析（PLAN-0.0.4 T3.1）。vela 把宿主目录挂为
/// guest 根，argv[0] 常为宿主风格路径，故按三种形态依次尝试：
/// 1. POSIX 绝对路径 → fs 翻译；
/// 2. POSIX 相对路径 → cwd 拼接后 fs 翻译；
/// 3. 宿主风格路径（含 \ 或 :，或不带 / 的相对宿主路径）→ 直接按宿主路径。
fn resolve_exec_path(proc: &GuestProcess, path: &str) -> Option<std::path::PathBuf> {
    if path.starts_with('/') {
        return proc.fs.translate(path);
    }
    let g = format!("{}/{}", proc.cwd.trim_end_matches('/'), path);
    if let Some(hp) = proc.fs.translate(&g) {
        if hp.exists() {
            return Some(hp);
        }
    }
    let p = std::path::PathBuf::from(path);
    if p.exists() {
        return Some(p);
    }
    proc.fs.translate(path)
}

/// execve(59) 的进程内重载（PLAN-0.0.4 T3.1）。vela 无 fork，重载是唯一
/// 诚实路径：新映像装载成功后，卸载全部旧客户内存（含映像/堆/栈/解释器）、
/// 关闭 CLOEXEC fd（管道等跨重载保留）、重建堆/栈/auxv，返回新入口与新栈。
/// 失败返回 -errno，客户继续运行原映像（与 Linux execve 失败语义一致）。
#[cfg(windows)]
fn do_execve(st: &mut GuestState, args: &[u64; 6]) -> Result<(u64, u64), i64> {
    let (path_ptr, argv_ptr, envp_ptr) = (args[0], args[1], args[2]);
    let err = |e: i32| -> i64 { -(e as i64) };

    // 1. 路径与参数读取（旧映像仍完整可读）
    let path = vela_runtime::read_cstr(&st.proc, path_ptr).map_err(err)?;
    let mut argv: Vec<String> = Vec::new();
    let mut p = argv_ptr;
    loop {
        let ent = vela_runtime::read_guest(&st.proc, p, 8).map_err(err)?;
        let ptr = u64::from_le_bytes(ent[0..8].try_into().unwrap());
        if ptr == 0 {
            break;
        }
        argv.push(vela_runtime::read_cstr(&st.proc, ptr).map_err(err)?);
        p += 8;
    }
    if argv.is_empty() {
        argv.push(path.clone());
    }
    let mut envp: Vec<String> = Vec::new();
    p = envp_ptr;
    loop {
        let ent = vela_runtime::read_guest(&st.proc, p, 8).map_err(err)?;
        let ptr = u64::from_le_bytes(ent[0..8].try_into().unwrap());
        if ptr == 0 {
            break;
        }
        envp.push(vela_runtime::read_cstr(&st.proc, ptr).map_err(err)?);
        p += 8;
    }

    // 2. 路径解析：绝对走 fs 翻译；POSIX 相对按 cwd 拼接；argv[0] 为
    //    宿主风格路径（vela 常见用法）时直接按宿主路径接受
    let host_path = resolve_exec_path(&st.proc, &path).ok_or(err(vela_abi::ENOENT))?;

    // 3. 读文件 + 装载新映像（失败即 execve 失败，旧映像不动）
    let bytes = std::fs::read(&host_path).map_err(|_| err(vela_abi::ENOENT))?;
    let info = loader::parse(&bytes).map_err(|_| err(vela_abi::ENOEXEC))?;
    let mut img = loader::load(&bytes, &st.host, 0).map_err(|_| err(vela_abi::ENOEXEC))?;
    if let Some(gipath) = &info.interp {
        // 解释器：fs 翻译优先，回退到新映像宿主目录下的同名文件
        let ipath = st
            .proc
            .fs
            .translate(gipath)
            .or_else(|| {
                let name = gipath.rsplit('/').next()?;
                host_path.parent()?.join(name).into()
            })
            .ok_or(err(vela_abi::ENOENT))?;
        let ibytes = std::fs::read(&ipath).map_err(|_| err(vela_abi::ENOENT))?;
        let iimg = loader::load(&ibytes, &st.host, 0).map_err(|_| err(vela_abi::ENOEXEC))?;
        // 解释器 syscall sites 并入主映像清单（build_islands_for 统一处理）
        img.syscall_sites.extend(iimg.syscall_sites.iter().copied());
        img.interp = Some(InterpImage {
            bias: iimg.bias,
            entry: iimg.entry,
            span: iimg.span,
            exec_ranges: iimg.exec_ranges,
            syscall_sites: iimg.syscall_sites,
        });
    }

    // 4. 卸载旧客户地址空间（新映像仍在 host 内存中，不受影响；
    //    exec-range 表由第 7 步 replace 原地重注册覆盖）
    let old: Vec<vela_runtime::MemRange> = st.proc.mem.ranges.values().copied().collect();
    for r in old {
        // Reserve 块（映像/堆/栈）不调用 VirtualFree：实测对含 musl donate
        // PROT_NONE 页的堆块做 free/decommit 会让进程在内核路径死亡（无 VEH、
        // 无诊断）。解除登记后保留地址空间，进程退出时由 OS 统一回收——
        // 单 guest 进程内存寿命有限，泄漏代价可接受（记录于 SYSCALLS.md）。
        // FileView 的 UnmapViewOfFile 是安全的，正常释放。
        if r.kind == vela_runtime::mem::MemKind::FileView {
            let _ = unsafe { st.host.unmap_view(r.start as usize) };
        }
    }
    st.proc.mem = vela_runtime::mem::MemRegistry::default();
    st.proc.heap = None;

    // 5. CLOEXEC fd 关闭（管道等跨重载保留，T3.2）
    let _ = st.proc.fds.close_cloexec(&st.host);

    // 6a. 新映像建岛（T2.6/T2.7）：旧岛地址空间随旧映像泄漏（T4.5 计债）
    let island_ranges = build_islands_for(&st.host, &img, st.trap);

    // 6. 换上新映像 + 重建堆/栈/auxv
    st.proc.load = img;
    st.proc.mem.add(st.proc.load.span);
    if let Some(i) = &st.proc.load.interp {
        st.proc.mem.add(i.span);
    }
    for (s, e) in island_ranges {
        st.proc
            .mem
            .add(vela_runtime::mem::MemRange::island(s, e - s));
    }
    st.proc
        .init_heap(&st.host, 0, st.heap_mb * 1024 * 1024)
        .map_err(|_| err(vela_abi::ENOMEM))?;
    let (rsp, stack_range) =
        guest_start::build_stack(&st.host, &st.proc.load, &argv, &envp, st.stack_mb)
            .map_err(|_| err(vela_abi::ENOMEM))?;
    st.proc.mem.add(stack_range);

    // execve 清空线程指针：新程序需重新 arch_prctl(SET_FS)
    st.proc.fs_base = 0;
    st.proc.gs_base = 0;
    st.proc.fs_apply_pending = None;
    st.host.set_soft_tls_base(0);

    // 7. 原地重注册新可执行范围，返回新入口
    let mut ranges = st.proc.load.exec_ranges.clone();
    if let Some(i) = &st.proc.load.interp {
        ranges.extend(i.exec_ranges.iter().copied());
    }
    st.host.replace_exec_ranges(&ranges);
    let entry = match &st.proc.load.interp {
        Some(i) => i.entry,
        None => st.proc.load.entry,
    };
    Ok((entry, rsp))
}

/// 环境自检（PLAN-0.0.2 T4.3）：排障入口，报告宿主能力与常见问题。
fn cmd_doctor() -> i32 {
    println!("vela doctor");
    println!("  version      : {}", env!("CARGO_PKG_VERSION"));
    println!(
        "  host         : {} ({})",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    // TLS 能力：musl/glibc 等依赖 FS 的程序的硬前提
    #[cfg(windows)]
    {
        let fs_ok = vela_sys::windows::probe_fs_base_support();
        println!(
            "  FSGSBASE     : {}",
            if fs_ok {
                "available (guest TLS works)"
            } else {
                "UNAVAILABLE — TLS-dependent guests (musl/glibc) cannot run here"
            }
        );
        if !fs_ok {
            println!("                 (typical on Hyper-V / cloud VMs / VBS; see docs/DESIGN.md TLS/FS)");
        }
    }

    // 路径映射约定
    println!("  path mapping : default /mnt/c -> C:\\; override with --root <dir> / --map <g>=<h>");

    // 陷阱后端（0.1.0 T2.6）：island 为默认 auto 的首选，混合模式是预期形态
    println!(
        "  trap         : island trampoline supported (default --trap=auto; mixed island/veh expected)"
    );

    // 杀软提示（README 安全节）：进程内改可执行内存可能被拦截
    println!("  antivirus    : if guests are blocked, exclude vela.exe (Vela patches syscall in-process; no packing/obfuscation)");

    // guest 产物
    let manifest = env!("CARGO_MANIFEST_DIR");
    for g in ["hello", "hello-musl", "torture", "tls", "file-io", "bench"] {
        let p = std::path::Path::new(manifest).join(format!("../../guest/bin/{g}"));
        let mark = if p.exists() {
            "ok"
        } else {
            "missing (generators: vela-mkhello/vela-mkguest, see guest/README.md)"
        };
        println!("  guest/bin/{g:<9} : {mark}");
    }

    // 内存资源
    println!("  limits       : --stack-mb/--heap-mb adjustable (default 8/8 MiB)");
    0
}

/// 组装客户环境块：默认继承宿主全部环境变量，再应用 --env（K=V 覆盖/追加，K= 删除）。
fn build_envp(envs: &[String]) -> Vec<String> {
    let mut list: Vec<(String, String)> = std::env::vars().collect();
    for e in envs {
        match e.split_once('=') {
            Some((k, v)) => {
                if let Some(slot) = list.iter_mut().find(|(ek, _)| ek == k) {
                    slot.1 = v.to_string();
                } else {
                    list.push((k.to_string(), v.to_string()));
                }
            }
            None => {
                // --env K（无 =）：删除
                list.retain(|(ek, _)| ek != e);
            }
        }
    }
    list.into_iter().map(|(k, v)| format!("{k}={v}")).collect()
}

/// 岛页跳板构建（PLAN-0.1.0 T2.1/T2.6）：--trap=veh 时跳过（保持 0.0.6
/// 行为）。主映像 + 解释器的全部 syscall site 一次建岛；通过校验的点改写
/// E9 进岛页，其余留 UD2+VEH（混合模式）。返回岛页区间（调用方登记进
/// MemRegistry——fork 快照经此原样传递，T2.7：子进程同 VA 映射，E9 有效）。
#[cfg(windows)]
fn build_islands_for(
    host: &PlatformHost,
    img: &vela_runtime::mem::LoadedImage,
    trap: TrapBackend,
) -> Vec<(u64, u64)> {
    if trap == TrapBackend::Veh {
        return Vec::new();
    }
    let mut sites = img.syscall_sites.clone();
    if let Some(i) = &img.interp {
        sites.extend(i.syscall_sites.iter().copied());
    }
    if sites.is_empty() {
        return Vec::new();
    }
    // 可执行段（分支目标扫描域）：主映像逐段 + 解释器 exec_ranges
    // （解释器 span 含 PROT_NONE 捐赠页，不可整体扫描）
    let mut segs: Vec<(u64, u64)> = img
        .segments
        .iter()
        .filter(|s| s.prot & 4 != 0)
        .map(|s| (s.vaddr, s.vaddr + s.mem_size))
        .collect();
    if let Some(i) = &img.interp {
        segs.extend(i.exec_ranges.iter().copied());
    }
    match host.build_islands(&sites, &segs) {
        Ok((ni, nv, ranges)) => {
            if logx::enabled() {
                eprintln!(
                    "[vela] island trampoline: {ni} sites → island, {nv} sites → VEH (mixed mode expected)"
                );
            }
            ranges
        }
        Err(e) => {
            eprintln!("[vela] island build failed: {e} (continuing with VEH backend)");
            Vec::new()
        }
    }
}

fn run_elf(
    elf_path: &str,
    guest_argv: &[String],
    opts: &RunOpts,
) -> Result<std::convert::Infallible, i32> {
    let bytes = match std::fs::read(elf_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("vela: cannot open '{elf_path}': No such file or directory");
            return Err(127);
        }
        Err(e) => {
            eprintln!("vela: cannot read '{elf_path}': {e}");
            return Err(1);
        }
    };

    #[cfg(windows)]
    set_console_utf8();

    // 提前探测 wrfsbase（FSGSBASE），避免在 VEH 分发链里嵌套注册处理器
    #[cfg(windows)]
    {
        use vela_sys::windows::probe_fs_base_support;
        if !probe_fs_base_support() && logx::enabled() {
            eprintln!("[vela] FSGSBASE 不可用：arch_prctl(SET_FS) 仅记录，客户 TLS 不可用");
        }
    }

    let host = PlatformHost::new();

    // 先解析：格式错误尽早失败，同时取 PT_INTERP 路径（PLAN-0.0.4 T2.1）
    let info = match loader::parse(&bytes) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("vela: {elf_path}: {e}");
            return Err(1);
        }
    };

    let mut img = match loader::load(&bytes, &host, GUEST_HINT) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("vela: {elf_path}: {e}");
            return Err(1);
        }
    };

    // 路径映射提前构建：解释器解析（T2.2）与客户运行共用同一张表
    let mut fs = vela_fs::FsMap::legacy();
    if let Some(root) = &opts.root {
        if let Err(e) = fs.add("/", std::path::Path::new(root)) {
            eprintln!("vela: --root: {e}");
            return Err(2);
        }
    }
    for m in &opts.maps {
        let Some((g, h)) = m.split_once('=') else {
            eprintln!("vela: --map 需要 <guest>=<host> 形式，得到 '{m}'");
            return Err(2);
        };
        if let Err(e) = fs.add(g, std::path::Path::new(h)) {
            eprintln!("vela: --map: {e}");
            return Err(2);
        }
    }

    // 动态链接（T2.2/T2.3）：vela 只负责装载解释器与构造 auxv，重定位
    // 全部交给 ld-musl 自身（它是完整的 ELF 加载器）。
    if let Some(gpath) = &info.interp {
        let ipath = resolve_interp(&fs, gpath, elf_path, &opts.interp);
        let ibytes = match std::fs::read(&ipath) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("vela: cannot read interpreter '{}': {e}", ipath.display());
                eprintln!("vela: hint: use --interp <host-path> or --map /lib=<host-dir>");
                return Err(127);
            }
        };
        match loader::load(&ibytes, &host, 0) {
            Ok(iimg) => {
                if logx::enabled() {
                    eprintln!(
                        "[vela] interp {gpath} → {} base {:#x} entry {:#x}",
                        ipath.display(),
                        iimg.bias,
                        iimg.entry
                    );
                }
                img.interp = Some(InterpImage {
                    bias: iimg.bias,
                    entry: iimg.entry,
                    span: iimg.span,
                    exec_ranges: iimg.exec_ranges,
                    syscall_sites: iimg.syscall_sites,
                });
            }
            Err(e) => {
                eprintln!("vela: interpreter {}: {e}", ipath.display());
                return Err(1);
            }
        }
    }

    // 岛页跳板（T2.6）：在 proc 建立前构建（映像内存已就位），区间随后登记
    let island_ranges = build_islands_for(&host, &img, opts.trap);

    let mut proc = GuestProcess::new(host.current_pid(), img);
    proc.attach_stdio(&host);
    proc.fs = fs;
    for (s, e) in island_ranges {
        proc.mem.add(vela_runtime::mem::MemRange::island(s, e - s));
    }
    if let Some(u) = opts.uid {
        proc.uid = u;
    }
    if let Some(g) = opts.gid {
        proc.gid = g;
    }
    // 堆是 brk 的后端，失败即无法继续（T3.4：warn-继续改为 fatal）
    if proc
        .init_heap(&host, 0, opts.heap_mb * 1024 * 1024)
        .is_err()
    {
        eprintln!("vela: heap init failed");
        return Err(1);
    }

    let envp = build_envp(&opts.envs);
    let (rsp, stack_range) =
        match guest_start::build_stack(&host, &proc.load, guest_argv, &envp, opts.stack_mb) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("vela: stack setup failed: {e}");
                return Err(1);
            }
        };
    proc.mem.add(stack_range);

    // 入口语义（T2.3）：动态映像跳解释器入口（_dlstart），静态跳自身入口
    let entry = match &proc.load.interp {
        Some(i) => i.entry,
        None => proc.load.entry,
    };
    let mut exec_ranges = proc.load.exec_ranges.clone();
    if let Some(i) = &proc.load.interp {
        exec_ranges.extend(i.exec_ranges.iter().copied());
    }
    let heap_start = proc.heap.map(|h| h.start);

    #[cfg(windows)]
    {
        // --soft-tls：FSGSBASE 缺失环境的实验回退（PLAN-0.0.4 T4.1/T4.2）
        if opts.soft_tls {
            host.enable_soft_tls();
            eprintln!(
                "[vela] soft-tls enabled: fs-prefixed guest accesses will be emulated (slow; diagnostics/CI only)"
            );
        }
        let state = Box::new(GuestState {
            proc,
            host,
            stack_mb: opts.stack_mb,
            heap_mb: opts.heap_mb,
            soft_tls: opts.soft_tls,
            children: std::cell::RefCell::new(BTreeMap::new()),
            trap: opts.trap,
        });
        let ptr = Box::into_raw(state);
        GUEST.store(ptr, Ordering::Relaxed);
        let st = unsafe { &*ptr };
        // exec-range 原地注册（T1.1）：初始装载与后续 execve 重载共用同一路径
        st.host.replace_exec_ranges(&exec_ranges);
        if let Err(e) = st.host.install_trap(trap) {
            eprintln!("vela: failed to install exception trap: {e}");
            return Err(1);
        }
        // 预切 FS：进入客户前把当前线程 FS 基址切到一张**已映射**的客户占位页，
        // 让内核从进程一开始就保存/恢复「客户侧」基址（消除还原为陈旧宿主值
        // 的可能）。占位页取堆前 4KiB（已 RW 且登记），初始全零——即便内核在
        // arch_prctl 之前发生一次 fs 解引用也只是读到 0，不会 AV；arch_prctl
        // (SET_FS) 后由 trampoline 切到真实 TLS 区。
        if st.host.fs_base_supported() {
            if let Some(hs) = heap_start {
                let _ = st.host.preset_fs_base(hs);
                // 强制内核按已预切的基址重建保存值：此后偶发还原的也是客户侧
                // 基址，而非线程创建时保存的 0（CI 实测的崩溃根源）。
                // 注意必须在 VEH 安装之后调用（commit stub 依赖 VEH 吸收 UD2）。
                st.host.commit_fs_base();
                if logx::enabled() {
                    eprintln!("[vela] fs preset → {hs:#x} (committed)");
                }
            }
        }
        // SAFETY: 客户映像、堆、栈均已映射且登记；本调用不返回
        unsafe { st.host.enter_guest(entry, rsp) }
    }
    #[cfg(not(windows))]
    {
        let _ = (entry, rsp, proc);
        eprintln!("vela: guest execution is only supported on Windows in v0 (loader/runtime 逻辑可在 linux dev 上测试)");
        Err(1)
    }
}

/// 陷阱 → dispatch 的桥接（规格 5.3 方法 C）。与客户同线程执行。
/// 0.1.0 T1.1：签名改为宿主无关的 TrapFrame（M2 岛页路径无 VEH 上下文）。
#[cfg(windows)]
unsafe extern "system" fn trap(nr: u64, args: &[u64; 6], frame: &mut TrapFrame) -> i64 {
    let p = GUEST.load(Ordering::Relaxed);
    if p.is_null() {
        return -(vela_abi::ENOSYS as i64);
    }
    // SAFETY: GUEST 在进入客户前设置一次；陷阱回调与客户代码同线程
    let st = unsafe { &mut *p };
    let rip = frame.regs.rip;
    // soft-tls：同步客户 TLS 基址到模拟器（arch_prctl 记录后即生效）
    if st.proc.fs_base != 0 {
        st.host.set_soft_tls_base(st.proc.fs_base);
    }
    if logx::enabled() {
        if st.host.soft_tls_stub_hit() {
            eprintln!("[vela] stub HIT ✓");
        }
        // strace 风格：name(args...) + rip，便于与 Linux 侧 strace 对照及
        // 定位 ldso 启动期问题（M2 排障）
        eprintln!(
            "[vela] {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) [nr={}, rip={:#x}]",
            vela_abi::syscall_name(nr),
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            nr,
            rip
        );
    }
    let r = if nr == vela_abi::SYS_EXECVE {
        // execve（PLAN-0.0.4 T3.1）：进程内重载，属控制流操作，由 CLI 层
        // 编排（loader/栈构建在此 crate）；成功路径直接改写上下文返回。
        match do_execve(st, args) {
            Ok((entry, rsp)) => {
                frame.regs.rax = 0;
                frame.regs.rip = entry;
                frame.regs.rsp = rsp;
                if logx::enabled() {
                    eprintln!("[vela] execve → reloaded, entry {entry:#x} rsp {rsp:#x}");
                }
                return 0;
            }
            Err(e) => e,
        }
    } else if nr == vela_abi::SYS_FORK
        || nr == vela_abi::SYS_VFORK
        || (nr == vela_abi::SYS_CLONE && args[0] == fork::SIGCHLD_FLAGS)
    {
        // fork（0.0.6 M1）：musl x86_64 fork() 走 SYS_FORK(57)；线程类
        // clone（CLONE_VM 等 flags）维持拒绝（单线程契约，NONGOALS）。
        match fork::do_fork(st, args, frame) {
            Ok(pid) => {
                // 模拟 syscall 副作用：父返回子 pid
                frame.regs.rax = pid as u64;
                frame.regs.rcx = rip + 2;
                frame.regs.r11 = frame.e_flags;
                frame.regs.rip = rip + 2;
                if logx::enabled() {
                    eprintln!("[vela] fork → child pid {pid}");
                }
                return 0;
            }
            Err(e) => e,
        }
    } else if nr == vela_abi::SYS_CLONE {
        // 线程类 clone（CLONE_VM 等 flags）：诚实拒绝（单线程契约，NONGOALS）
        if logx::enabled() {
            eprintln!(
                "[vela] clone(flags={:#x}) → ENOSYS (threads unsupported, NONGOALS)",
                args[0]
            );
        }
        -(vela_abi::ENOSYS as i64)
    } else if nr == vela_abi::SYS_WAIT4 {
        // wait4（0.0.6 M2）：真实等待子进程句柄（CLI 层持有 children 表）
        fork::do_wait4(st, args)
    } else if nr == vela_abi::SYS_KILL {
        // kill（0.0.6 M3）：SIGKILL/SIGTERM 终止 + sig 0 探测
        fork::do_kill(st, args[0], args[1])
    } else {
        vela_runtime::dispatch(&mut st.proc, &st.host, nr, *args)
    };
    if logx::enabled() {
        eprintln!(
            "[vela] {} = {r} ({:#x})",
            vela_abi::syscall_name(nr),
            r as u64
        );
    }
    // 模拟硬件 syscall 固定副作用：Rax=返回值、Rcx=返回地址、R11=RFLAGS、Rip+=2
    frame.regs.rax = r as u64;
    frame.regs.rcx = rip + 2;
    frame.regs.r11 = frame.e_flags;
    frame.regs.rip = rip + 2;
    // SET_FS：FS 切换必须在异常返回后的用户态完成（宿主机制会还原处理器内
    // 的旧基址），改跳 trampoline：wrfsbase r10（新基址）; jmp rcx（客户返回地址）。
    // 自愈：内核在某些转换路径会把用户 fs 基址恢复为旧值——每次 syscall 返回时
    // 校验当前基址，不一致就再跳一次 trampoline 重设（rdfsbase 一条指令的成本）。
    if let Some(v) = st.proc.fs_apply_pending.take() {
        if logx::enabled() {
            eprintln!("[vela] fs trampoline → {v:#x}");
        }
        frame.regs.r10 = v;
        frame.regs.rip = st.host.fs_trampoline_addr() as u64;
    } else if st.proc.fs_base != 0 {
        if let Some(cur) = st.host.read_fs_base() {
            if cur != st.proc.fs_base {
                if logx::enabled() {
                    eprintln!("[vela] fs heal: {cur:#x} → {:#x}", st.proc.fs_base);
                }
                frame.regs.r10 = st.proc.fs_base;
                frame.regs.rip = st.host.fs_trampoline_addr() as u64;
            }
        }
    }
    r
}

// 内联日志模块：VELA_LOG=1 或 -v 时向 stderr 打印（不污染客户 stdout，规格 12）
mod logx {
    use std::sync::atomic::{AtomicBool, Ordering};

    static VERBOSE: AtomicBool = AtomicBool::new(false);

    pub fn init() {
        if let Some(v) = std::env::var_os("VELA_LOG") {
            let on = !v.is_empty() && v != "0";
            VERBOSE.store(on, Ordering::Relaxed);
        }
    }

    pub fn enable() {
        VERBOSE.store(true, Ordering::Relaxed);
    }

    pub fn enabled() -> bool {
        VERBOSE.load(Ordering::Relaxed)
    }
}
