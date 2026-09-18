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

const HEAP_SIZE: u64 = 8 * 1024 * 1024;
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
        Some(other) => {
            eprintln!("vela: unknown command '{other}'");
            print_usage();
            2
        }
    }
}

fn print_usage() {
    eprintln!("usage: vela run <linux-elf> [guest-args...]");
    eprintln!("       vela --version");
    eprintln!("       vela --help");
    eprintln!("env:   VELA_LOG=1 或 -v 打印 syscall 日志到 stderr");
}

fn cmd_run(rest: &[String]) -> i32 {
    let mut verbose = false;
    let mut pos: Vec<String> = Vec::new();
    for a in rest {
        if a == "-v" {
            verbose = true;
        } else {
            pos.push(a.clone());
        }
    }
    if verbose {
        logx::enable();
    }
    let Some(elf) = pos.first() else {
        print_usage();
        return 2;
    };
    // 客户 argv[0] = 传入的 ELF 路径，其余为附加参数（规格 4）
    let guest_argv: Vec<String> = pos.clone();
    match run_elf(elf, &guest_argv) {
        Ok(never) => match never {},
        Err(code) => code,
    }
}

fn run_elf(elf_path: &str, guest_argv: &[String]) -> Result<std::convert::Infallible, i32> {
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
    if let Err(e) = proc.init_heap(&host, 0, HEAP_SIZE) {
        eprintln!("[vela] warn: heap init failed: {e}");
    }

    let (rsp, stack_range) = match guest_start::build_stack(&host, &proc.load, guest_argv) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("vela: stack setup failed: {e}");
            return Err(1);
        }
    };
    proc.mem.add(stack_range);

    let entry = proc.load.entry;
    let exec_ranges = proc.load.exec_ranges.clone();

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
        eprintln!(
            "[vela] syscall {} nr={} a={:#x},{:#x},{:#x}",
            vela_abi::syscall_name(nr),
            nr,
            args[0],
            args[1],
            args[2]
        );
    }
    let r = vela_runtime::dispatch(&mut st.proc, &st.host, nr, *args);
    if logx::enabled() {
        eprintln!("[vela]   = {r}");
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
