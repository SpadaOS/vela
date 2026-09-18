//! vela-fs：Linux 风格路径 → 宿主原生路径翻译（规格 5.5）。
//! 路径在进入 Host 之前完成转换（规格 2.4）。
//!
//! 0.0.2：由硬编码 `/mnt/c → C:\` 升级为映射表（PLAN-0.0.2 T2.1）：
//! - `FsMap::legacy()`：保留 v0 兼容映射
//! - `FsMap::root(dir)`：`--root` 语义，guest `/` = 宿主目录
//! - `add()`：`--map guest=host` 追加映射，最长前缀优先
//!
//! 约定：只做「组件级」前缀匹配（`/mnt/cd` 不会命中 `/mnt/c`）；
//! 出现 `..` 一律拒绝（禁止逃出约定根）；`.` 与空组件折叠。

use std::path::PathBuf;

#[derive(Debug, Clone)]
struct Map {
    /// 客户侧前缀，规范化形如 "/mnt/c"（无尾斜杠；"/" 根映射为空串）。
    guest: String,
    host: PathBuf,
}

/// 客户→宿主路径映射表。最长前缀优先。
#[derive(Debug, Clone)]
pub struct FsMap {
    maps: Vec<Map>,
}

impl FsMap {
    /// v0 兼容映射：`/mnt/c` → `C:\`。
    pub fn legacy() -> FsMap {
        let mut m = FsMap { maps: Vec::new() };
        m.add("/mnt/c", std::path::Path::new(r"C:\")).expect("legacy map is valid");
        m
    }

    /// `--root <dir>`：guest `/` = 宿主目录。
    pub fn root(host_dir: &std::path::Path) -> FsMap {
        let mut m = FsMap { maps: Vec::new() };
        m.add("/", host_dir).expect("root map is valid");
        m
    }

    /// 追加映射。guest 前缀必须是绝对路径；宿主目录必须绝对。
    pub fn add(&mut self, guest_prefix: &str, host_dir: &std::path::Path) -> Result<(), String> {
        let comps = split_components(guest_prefix).ok_or("guest prefix must not contain '..'")?;
        if !host_dir.is_absolute() {
            return Err("host dir must be absolute".to_string());
        }
        let guest = if comps.is_empty() { String::new() } else { format!("/{}", comps.join("/")) };
        // 长前缀优先：插入后按长度降序排（根 "/" 空串兜底在最后）
        self.maps.push(Map { guest, host: host_dir.to_path_buf() });
        self.maps.sort_by(|a, b| b.guest.len().cmp(&a.guest.len()));
        Ok(())
    }

    /// 翻译绝对 Linux 路径；不可翻译/含 `..`/相对路径返回 None。
    /// 热路径零中间分配（PLAN-0.0.3 T1.4）：仅反斜杠归一与 `.` 折叠需要拷贝，
    /// 常规正斜杠路径全程借用切片。
    pub fn translate(&self, path: &str) -> Option<PathBuf> {
        if path.is_empty() {
            return None;
        }
        if path.split('/').any(|c| c == "..") {
            return None; // 逃逸防护（与 add() 一致）
        }
        // 归一：反斜杠 → 正斜杠；含 "/./" 才折叠（罕见路径才分配）
        let norm_owned;
        let norm: &str = if path.contains('\\') {
            norm_owned = path.replace('\\', "/");
            &norm_owned
        } else if path.contains("/./") {
            norm_owned = fold_dots(path);
            &norm_owned
        } else {
            path
        };
        if norm.is_empty() || !norm.starts_with('/') {
            return None; // 相对路径不接受（调用方负责拼接 cwd）
        }
        for m in &self.maps {
            if m.guest.is_empty() {
                // 根映射：整段归入 host
                let mut out = m.host.clone();
                for c in norm.split('/').filter(|c| !c.is_empty()) {
                    out.push(c);
                }
                return Some(out);
            }
            let g = m.guest.as_str();
            if norm == g {
                return Some(m.host.clone());
            }
            if norm.starts_with(g) {
                let rest = &norm[g.len()..];
                if rest.starts_with('/') {
                    let mut out = m.host.clone();
                    for c in rest.split('/').filter(|c| !c.is_empty()) {
                        out.push(c);
                    }
                    return Some(out);
                }
                // 组件边界：/mnt/cd 不命中 /mnt/c，继续尝试更短前缀
            }
        }
        None
    }
}

/// 折叠路径中的 `.` 组件（仅该罕见情形调用，允许一次分配）。
fn fold_dots(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut need_slash = false;
    for c in path.split('/') {
        if c.is_empty() || c == "." {
            continue;
        }
        if need_slash {
            out.push('/');
        }
        out.push_str(c);
        need_slash = true;
    }
    out.insert(0, '/');
    out
}

/// 拆分路径为组件：反斜杠归一、要求绝对路径、拒绝 `..`、折叠 `.`/空段。
/// 返回 None 表示不可接受（空路径、相对路径或 `..` 逃逸）。
fn split_components(path: &str) -> Option<Vec<String>> {
    let norm = path.replace('\\', "/");
    if norm.is_empty() || !norm.starts_with('/') {
        return None; // 空路径与相对路径不接受（调用方负责拼接 cwd）
    }
    let mut comps: Vec<String> = Vec::new();
    for c in norm.split('/') {
        match c {
            "" | "." => {}
            ".." => return None,
            _ => comps.push(c.to_string()),
        }
    }
    Some(comps)
}

/// v0 兼容入口：legacy 映射（`/mnt/c → C:\`）。
pub fn translate(path: &str) -> Option<PathBuf> {
    FsMap::legacy().translate(path)
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

    #[test]
    fn root_map_maps_everything() {
        let m = FsMap::root(std::path::Path::new(r"E:\rootfs"));
        assert_eq!(m.translate("/bin/sh"), Some(PathBuf::from(r"E:\rootfs\bin\sh")));
        assert_eq!(m.translate("/"), Some(PathBuf::from(r"E:\rootfs")));
        assert_eq!(m.translate("/etc/passwd"), Some(PathBuf::from(r"E:\rootfs\etc\passwd")));
    }

    #[test]
    fn longest_prefix_wins() {
        let mut m = FsMap::root(std::path::Path::new(r"E:\rootfs"));
        m.add("/tmp", std::path::Path::new(r"C:\Temp")).unwrap();
        assert_eq!(m.translate("/tmp/x"), Some(PathBuf::from(r"C:\Temp\x")));
        assert_eq!(m.translate("/tmpx/y"), Some(PathBuf::from(r"E:\rootfs\tmpx\y")));
        assert_eq!(m.translate("/bin/ls"), Some(PathBuf::from(r"E:\rootfs\bin\ls")));
    }

    #[test]
    fn component_boundary_match() {
        // legacy：/mnt/cd 不应命中 /mnt/c 前缀
        assert_eq!(translate("/mnt/cd"), None);
        assert_eq!(translate("/mnt/cd/x"), None);
    }

    #[test]
    fn multi_map_add() {
        let mut m = FsMap::legacy();
        m.add("/data", std::path::Path::new(r"E:\data")).unwrap();
        assert_eq!(m.translate("/data/a.txt"), Some(PathBuf::from(r"E:\data\a.txt")));
        assert_eq!(m.translate("/mnt/c/Windows"), Some(PathBuf::from(r"C:\Windows")));
    }
}