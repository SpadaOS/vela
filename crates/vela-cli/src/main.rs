//! vela：Windows 用户态 Linux x86_64 ELF 翻译运行时 CLI（规格 5.6）。
//!
//! 用法：
//!   vela run <linux-elf> [guest-args...]
//!   vela --version
//!   vela --help
//!
//! 退出码：客户 exit 的码；文件缺失 127；ELF 格式错误 1；CLI 用法错误 2。

mod guest_start;

use std::sync::atomic::{AtomicPtr, Ordering};

use vela_loader as loader;
use vela_runtime::GuestProcess;

#[cfg(windows)]
use vela_sys::windows::{add_guest_exec_range, install_syscall_trap, set_console_utf8, set_trap_fn, WindowsHost};
#[cfg(target_os = "linux")]
use vela_sys::linux_dev::LinuxDevHost;

#[cfg(windows)]
type PlatformHost = WindowsHost;
#[cfg(target_os = "linux")]
type PlatformHost = LinuxDevHost;

// 规格建议的映射提示基址（0x0000_4000_0000 附近空洞）；冲突时 host 回退让系统自选
const GUEST_HINT: u64 = 0x0000_4000_0000;

struct GuestState {
    proc: GuestProcess,
    host: PlatformHost,
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
        Some("run") => cmd_run(&args[1..]),
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
    eprintln!("  --stack-mb <n>     客户栈大小 MiB（默认 8，1-512）");
    eprintln!("  --heap-mb <n>      客户堆大小 MiB（默认 8，1-1024）");
    eprintln!("  -v                 syscall 日志到 stderr（或 VELA_LOG=1）");
    eprintln!("env:   VELA_LOG=1 或 -v 打印 syscall 日志到 stderr");
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
}

fn cmd_run(rest: &[String]) -> i32 {
    let mut opts = RunOpts {
        verbose: false,
        root: None,
        maps: Vec::new(),
        envs: Vec::new(),
        uid: None,
        gid: None,
        stack_mb: 8,
        heap_mb: 8,
    };
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0;
    // 选项只在 elf 路径之前；elf 之后的参数全部透传给客户
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "-v" => opts.verbose = true,
            "--root" => {
                let Some(v) = rest.get(i + 1) else { return usage_err("--root 需要参数") };
                opts.root = Some(v.clone());
                i += 1;
            }
            "--map" => {
                let Some(v) = rest.get(i + 1) else { return usage_err("--map 需要参数") };
                opts.maps.push(v.clone());
                i += 1;
            }
            "--env" => {
                let Some(v) = rest.get(i + 1) else { return usage_err("--env 需要参数") };
                opts.envs.push(v.clone());
                i += 1;
            }
            "--uid" | "--gid" | "--stack-mb" | "--heap-mb" => {
                let Some(v) = rest.get(i + 1) else { return usage_err(&format!("{a} 需要参数")) };
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

/// 环境自检（PLAN-0.0.2 T4.3）：排障入口，报告宿主能力与常见问题。
fn cmd_doctor() -> i32 {
    println!("vela doctor");
    println!("  version      : {}", env!("CARGO_PKG_VERSION"));
    println!("  host         : {} ({})", std::env::consts::OS, std::env::consts::ARCH);

    // TLS 能力：musl/glibc 等依赖 FS 的程序的硬前提
    #[cfg(windows)]
    {
        let fs_ok = vela_sys::windows::probe_fs_base_support();
        println!("  FSGSBASE     : {}", if fs_ok { "available (guest TLS works)" } else { "UNAVAILABLE — TLS-dependent guests (musl/glibc) cannot run here" });
        if !fs_ok {
            println!("                 (typical on Hyper-V / cloud VMs / VBS; see docs/DESIGN.md TLS/FS)");
        }
    }

    // 路径映射约定
    println!("  path mapping : default /mnt/c -> C:\\; override with --root <dir> / --map <g>=<h>");

    // 杀软提示（README 安全节）：进程内改可执行内存可能被拦截
    println!("  antivirus    : if guests are blocked, exclude vela.exe (Vela patches syscall in-process; no packing/obfuscation)");

    // guest 产物
    let manifest = env!("CARGO_MANIFEST_DIR");
    for g in ["hello", "hello-musl", "torture", "tls", "file-io"] {
        let p = std::path::Path::new(manifest).join(format!("../../guest/{g}"));
        let mark = if p.exists() { "ok" } else { "missing (generators: vela-mkhello/vela-mkguest, see guest/README.md)" };
        println!("  guest/{g:<9} : {mark}");
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

fn run_elf(elf_path: &str, guest_argv: &[String], opts: &RunOpts) -> Result<std::convert::Infallible, i32> {
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

    let img = match loader::load(&bytes, &host, GUEST_HINT) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("vela: {elf_path}: {e}");
            return Err(1);
        }
    };

    let mut proc = GuestProcess::new(1000, img);
    proc.attach_stdio(&host);
    // T2.1/T2.5：路径映射与身份
    if let Some(root) = &opts.root {
        if let Err(e) = proc.fs.add("/", std::path::Path::new(root)) {
            eprintln!("vela: --root: {e}");
            return Err(2);
        }
    }
    for m in &opts.maps {
        let Some((g, h)) = m.split_once('=') else {
            eprintln!("vela: --map 需要 <guest>=<host> 形式，得到 '{m}'");
            return Err(2);
        };
        if let Err(e) = proc.fs.add(g, std::path::Path::new(h)) {
            eprintln!("vela: --map: {e}");
            return Err(2);
        }
    }
    if let Some(u) = opts.uid {
        proc.uid = u;
    }
    if let Some(g) = opts.gid {
        proc.gid = g;
    }
    // 堆是 brk 的后端，失败即无法继续（T3.4：warn-继续改为 fatal）
    if proc.init_heap(&host, 0, opts.heap_mb * 1024 * 1024).is_err() {
        eprintln!("vela: heap init failed");
        return Err(1);
    }

    let envp = build_envp(&opts.envs);
    let (rsp, stack_range) = match guest_start::build_stack(&host, &proc.load, guest_argv, &envp, opts.stack_mb) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("vela: stack setup failed: {e}");
            return Err(1);
        }
    };
    proc.mem.add(stack_range);

    let entry = proc.load.entry;
    let exec_ranges = proc.load.exec_ranges.clone();
    let heap_start = proc.heap.map(|h| h.start);

    #[cfg(windows)]
    {
        let state = Box::new(GuestState { proc, host });
        let ptr = Box::into_raw(state);
        GUEST.store(ptr, Ordering::Relaxed);
        set_trap_fn(trap);
        for (s, e) in &exec_ranges {
            add_guest_exec_range(*s, *e);
        }
        if let Err(e) = install_syscall_trap() {
            eprintln!("vela: failed to install exception trap: {e}");
            return Err(1);
        }
        // 预切 FS：进入客户前把当前线程 FS 基址切到一张**已映射**的客户占位页，
        // 让内核从进程一开始就保存/恢复「客户侧」基址（消除还原为陈旧宿主值
        // 的可能）。占位页取堆前 4KiB（已 RW 且登记），初始全零——即便内核在
        // arch_prctl 之前发生一次 fs 解引用也只是读到 0，不会 AV；arch_prctl
        // (SET_FS) 后由 trampoline 切到真实 TLS 区。
        if vela_sys::windows::fs_base_supported() {
            if let Some(hs) = heap_start {
                let _ = vela_sys::windows::set_thread_fs_base_now(hs);
                // 强制内核按已预切的基址重建保存值：此后偶发还原的也是客户侧
                // 基址，而非线程创建时保存的 0（CI 实测的崩溃根源）。
                // 注意必须在 VEH 安装之后调用（commit stub 依赖 VEH 吸收 UD2）。
                vela_sys::windows::commit_fs_base_after_preset();
                if logx::enabled() {
                    eprintln!("[vela] fs preset → {hs:#x} (committed)");
                }
            }
        }
        // SAFETY: 客户映像、堆、栈均已映射且登记；本调用不返回
        unsafe { guest_start::enter_guest(entry, rsp) }
    }
    #[cfg(not(windows))]
    {
        let _ = (entry, rsp, proc);
        eprintln!("vela: guest execution is only supported on Windows in v0 (loader/runtime 逻辑可在 linux dev 上测试)");
        Err(1)
    }
}

/// VEH → dispatch 的桥接（规格 5.3 方法 C）。与客户同线程执行。
#[cfg(windows)]
unsafe extern "system" fn trap(nr: u64, args: &[u64; 6], rip: u64, ctx: &mut vela_sys::windows::Context) -> i64 {
    let p = GUEST.load(Ordering::Relaxed);
    if p.is_null() {
        return -(vela_abi::ENOSYS as i64);
    }
    // SAFETY: GUEST 在进入客户前设置一次；VEH 与客户代码同线程
    let st = unsafe { &mut *p };
    if logx::enabled() {
        if vela_sys::windows::stub_hit() {
            eprintln!("[vela] stub HIT ✓");
        }
        // strace 风格：name(args...) 便于与 Linux 侧 strace 记录对照（PLAN T3.5）
        eprintln!(
            "[vela] {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) [nr={}]",
            vela_abi::syscall_name(nr),
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            nr
        );
    }
    let r = vela_runtime::dispatch(&mut st.proc, &st.host, nr, *args);
    if logx::enabled() {
        eprintln!("[vela] {} = {r} ({:#x})", vela_abi::syscall_name(nr), r as u64);
    }
    // 模拟硬件 syscall 固定副作用：Rax=返回值、Rcx=返回地址、R11=RFLAGS、Rip+=2
    ctx.rax = r as u64;
    ctx.rcx = rip + 2;
    ctx.r11 = ctx.e_flags as u64;
    ctx.rip = rip + 2;
    // SET_FS：FS 切换必须在异常返回后的用户态完成（NtContinue 会还原处理器内
    // 的旧基址），改跳 trampoline：wrfsbase r10（新基址）; jmp rcx（客户返回地址）。
    // 自愈：内核在某些转换路径会把用户 fs 基址恢复为旧值——每次 syscall 返回时
    // 校验当前基址，不一致就再跳一次 trampoline 重设（rdfsbase 一条指令的成本）。
    if let Some(v) = st.proc.fs_apply_pending.take() {
        if logx::enabled() {
            eprintln!("[vela] fs trampoline → {v:#x}");
        }
        ctx.r10 = v;
        ctx.rip = vela_sys::windows::set_fs_stub_addr() as u64;
    } else if st.proc.fs_base != 0 {
        if let Some(cur) = vela_sys::windows::read_fs_base() {
            if cur != st.proc.fs_base {
                if logx::enabled() {
                    eprintln!("[vela] fs heal: {cur:#x} → {:#x}", st.proc.fs_base);
                }
                ctx.r10 = st.proc.fs_base;
                ctx.rip = vela_sys::windows::set_fs_stub_addr() as u64;
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
