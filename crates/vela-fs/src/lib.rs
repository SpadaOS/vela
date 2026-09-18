//! vela-fs（v0 极简，规格 5.5）：
//! Linux 风格路径 → 宿主原生路径翻译。路径在进入 Host 之前完成转换（规格 2.4）。
//! v0 不做完整路径查找，仅支持 `/mnt/c` 前缀映射。

use std::path::PathBuf;

/// 翻译规则（规格 5.5）：
/// - `/mnt/c/Users/foo` → `C:\Users\foo`
/// - `/mnt/c` → `C:\`
/// - 出现 `..` 一律拒绝（禁止逃出约定根，简单规范化）
/// - 其他前缀（如 `/etc/...`）返回 `None`，由调用方决定 errno
pub fn translate(path: &str) -> Option<PathBuf> {
    let norm = path.replace('\\', "/");
    let mut comps: Vec<&str> = Vec::new();
    for c in norm.split('/') {
        match c {
            "" | "." => {}
            ".." => return None,
            _ => comps.push(c),
        }
    }
    if comps.len() >= 2 && comps[0] == "mnt" && comps[1] == "c" {
        let mut out = PathBuf::from(r"C:\");
        for c in &comps[2..] {
            out.push(c);
        }
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnt_c_prefix() {
        assert_eq!(translate("/mnt/c/Users/foo"), Some(PathBuf::from(r"C:\Users\foo")));
        assert_eq!(translate("/mnt/c"), Some(PathBuf::from(r"C:\")));
        assert_eq!(translate("/mnt/c/"), Some(PathBuf::from(r"C:\")));
    }

    #[test]
    fn rejects_outside_roots() {
        assert_eq!(translate("/etc/passwd"), None);
        assert_eq!(translate("relative/path"), None);
    }

    #[test]
    fn rejects_dotdot_escape() {
        assert_eq!(translate("/mnt/c/../.."), None);
        assert_eq!(translate("/mnt/c/Users/../Users/foo"), None);
    }

    #[test]
    fn normalizes_dots_and_slashes() {
        assert_eq!(translate("/mnt/c/./Users/./foo"), Some(PathBuf::from(r"C:\Users\foo")));
        assert_eq!(translate("/mnt/c//Users///foo"), Some(PathBuf::from(r"C:\Users\foo")));
        assert_eq!(translate("\\mnt\\c\\Users\\foo"), Some(PathBuf::from(r"C:\Users\foo")));
    }
}
