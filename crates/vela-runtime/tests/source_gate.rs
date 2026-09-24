//! 宿主闸门（PLAN-0.1.0 T1.4）：vela-runtime / vela-loader / vela-fs 源码
//! 禁止出现 Windows 宿主内部机制字样——宿主差异必须全部走 `vela_sys::Host`
//! 契约。CI 另有 PowerShell grep 双保险；本测试让 `cargo test` 本地也能拦。

use std::path::{Path, PathBuf};

/// 违禁字样（对 src/*.rs 全文匹配；`VEH`/`Nt*` 是宿主机制名词，注释里
/// 出现也说明机制泄漏进了抽象层）。
const FORBIDDEN: &[&str] = &[
    "vela_sys::windows",
    "NtContinue",
    "CreateProcessW",
    "AddVectoredExceptionHandler",
    "VEH",
    "os::windows",
    "cfg(windows)",
    "cfg(target_os = \"windows\")",
];

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

#[test]
fn runtime_loader_fs_source_gate() {
    let crates = ["vela-runtime", "vela-loader", "vela-fs"];
    let manifest = env!("CARGO_MANIFEST_DIR"); // crates/vela-runtime
    let mut files = Vec::new();
    for c in crates {
        // manifest = crates/vela-runtime → ../{c}/src = crates/{c}/src
        collect_rs(&Path::new(manifest).join(format!("../{c}/src")), &mut files);
    }
    assert!(files.len() >= 5, "gate must scan real source trees");

    let mut hits = Vec::new();
    for f in &files {
        let body = std::fs::read_to_string(f).unwrap_or_default();
        for pat in FORBIDDEN {
            if body.contains(pat) {
                hits.push(format!("{} contains {pat:?}", f.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "host internals leaked into guest-side crates:\n{}",
        hits.join("\n")
    );
}
