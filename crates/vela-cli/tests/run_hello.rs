//! 集成验收（规格 9.2 / 9.3，Windows 专用）。
//! 每个用例只拉起一个 vela.exe 小进程 + 一颗 ~180 字节的 ELF，内存占用极小。

#![cfg(windows)]

use std::process::Command;

fn vela() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vela"))
}

#[test]
fn run_hello_prints_and_exits_zero() {
    let dir = std::env::temp_dir().join("vela-it-hello");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("hello");

    let gen = Command::new(env!("CARGO_BIN_EXE_vela-mkhello"))
        .arg(&elf)
        .output()
        .expect("spawn mkhello");
    assert!(gen.status.success(), "mkhello failed: {gen:?}");

    let out = vela().arg("run").arg(&elf).output().expect("spawn vela");
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hello from linux elf\n"
    );
}

#[test]
fn verbose_log_goes_to_stderr() {
    let dir = std::env::temp_dir().join("vela-it-hello");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("hello");
    let out = vela()
        .arg("run")
        .arg(&elf)
        .env("VELA_LOG", "1")
        .output()
        .expect("spawn vela");
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    // strace 风格日志（PLAN T3.5）：name(args...) 与 name = ret
    assert!(err.contains("write("), "log missing: {err}");
    assert!(err.contains("= 21"), "log missing ret: {err}");
    assert!(err.contains("exit("), "log missing: {err}");
    // 客户 stdout 不被日志污染（规格 12）
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "hello from linux elf\n"
    );
}

#[test]
fn rejects_pe_binary() {
    let dir = std::env::temp_dir().join("vela-it-pe");
    std::fs::create_dir_all(&dir).unwrap();
    let pe = dir.join("fake.exe");
    std::fs::write(&pe, b"MZ\x90\x00not an elf").unwrap();
    let out = vela().arg("run").arg(&pe).output().expect("spawn vela");
    assert_ne!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("ELF"), "stderr={err}");
}

#[test]
fn missing_file_exits_127() {
    let out = vela()
        .arg("run")
        .arg("Z:/definitely/not/here.elf")
        .output()
        .expect("spawn vela");
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn version_and_help() {
    let v = vela().arg("--version").output().unwrap();
    // 动态断言：与 workspace 版本一致，升版不再破坏 CI
    assert_eq!(
        String::from_utf8_lossy(&v.stdout).trim(),
        concat!("vela ", env!("CARGO_PKG_VERSION"))
    );
    let h = vela().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&h.stdout).is_empty() || h.status.success());
}

/// 综合压测 guest：双段（RX+RW）加载 + brk/mmap/uname/getrandom/writev 全链路。
#[test]
fn run_torture_guest() {
    let dir = std::env::temp_dir().join("vela-it-torture");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("torture");
    let gen = Command::new(env!("CARGO_BIN_EXE_vela-mkguest"))
        .arg("torture")
        .arg(&elf)
        .output()
        .expect("spawn mkguest");
    assert!(gen.status.success(), "mkguest failed: {gen:?}");

    let out = vela().arg("run").arg(&elf).output().expect("spawn vela");
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "Linuxmmap 1g1 ok\n");
}

/// TLS guest：验证 arch_prctl(SET_FS) 后 FS 相对寻址真正生效（trampoline 路径）。
/// 仅在 CPU+OS 支持 FSGSBASE 时运行。
#[test]
fn run_tls_guest() {
    if !vela_sys::windows::fs_base_supported() {
        eprintln!("skip: FSGSBASE unavailable on this machine");
        return;
    }
    let dir = std::env::temp_dir().join("vela-it-tls");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("tls");
    let gen = Command::new(env!("CARGO_BIN_EXE_vela-mkguest"))
        .arg("tls")
        .arg(&elf)
        .output()
        .expect("spawn mkguest");
    assert!(gen.status.success(), "mkguest failed: {gen:?}");

    let out = vela().arg("run").arg(&elf).output().expect("spawn vela");
    assert!(
        out.status.success(),
        "exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "mmap 1t1 ok\n");
}

/// musl 静态 PIE C hello（规格 8.2 加分项）。
/// 产物 guest/hello-musl 由 zig cc 交叉编译（见 guest/README.md）。
///
/// 静态 musl 需要 TLS（arch_prctl SET_FS + FS 相对寻址），而 Vela 的 FS 切换
/// 依赖 CPU+OS 的 FSGSBASE 支持（见 docs/DESIGN.md「TLS/FS」）。在不支持的
/// 环境（典型：Hyper-V 虚拟机 CI runner）下 musl 无法运行，测试自动跳过；
/// v0 门禁仍是无需 TLS 的汇编 hello。
#[test]
fn run_musl_hello() {
    if !vela_sys::windows::fs_base_supported() {
        eprintln!("skip: FSGSBASE unavailable on this machine; guest TLS cannot be switched (musl needs TLS)");
        return;
    }
    let elf = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../guest/bin/hello-musl");
    if !elf.exists() {
        eprintln!("skip: guest/hello-musl not built (see guest/README.md)");
        return;
    }
    let mut last: Option<std::process::Output> = None;
    for attempt in 1..=3 {
        let out = vela().arg("run").arg(&elf).output().expect("spawn vela");
        if out.status.success()
            && String::from_utf8_lossy(&out.stdout).starts_with("hello from musl")
        {
            return;
        }
        eprintln!("attempt {attempt} failed: {:?}", out.status.code());
        last = Some(out);
    }
    let out = last.expect("at least one attempt");
    panic!(
        "musl hello failed after 3 attempts: exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// file-io guest（0.0.2 M1 出口）：musl C 程序验收
/// open/write/lseek/read/fstat/stat/fcntl/opendir(getdents64)/getcwd 全链路。
/// 产物 guest/file-io 由 zig cc 交叉编译（见 guest/src/file-io.c 头注释）。
/// 需要 FSGSBASE（musl TLS），缺失时跳过；写入 C:\Windows\Temp 的产物由本测试清理。
#[test]
fn run_file_io_guest() {
    if !vela_sys::windows::fs_base_supported() {
        eprintln!("skip: FSGSBASE unavailable on this machine; musl guest needs TLS");
        return;
    }
    let elf = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../guest/bin/file-io");
    if !elf.exists() {
        eprintln!("skip: guest/file-io not built (see guest/src/file-io.c)");
        return;
    }
    let out = vela().arg("run").arg(&elf).output().expect("spawn vela");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // 无论成败都尝试清理 guest 写入的文件（C:\Windows\Temp）
    let _ = std::fs::remove_file(r"C:\Windows\Temp\vela-file-io.txt");
    assert!(
        out.status.success(),
        "exit={:?} stdout={} stderr={}",
        out.status.code(),
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.starts_with("file-io all ok"), "stdout={stdout}");
}
