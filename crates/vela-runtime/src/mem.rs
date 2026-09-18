//! 客户映像与内存登记类型。
//! 按规格依赖方向（loader → runtime），`LoadedImage` 定义在本 crate，
//! 由 vela-loader 负责构造并填充（规格 3 依赖图 + 5.4 GuestProcess.load）。

/// 单个 PT_LOAD 段加载后的描述。
#[derive(Clone, Debug)]
pub struct Segment {
    /// 已加 bias 的客户虚拟地址。
    pub vaddr: u64,
    /// 宿主内存地址（同进程映射）。
    pub host_addr: usize,
    pub file_size: u64,
    pub mem_size: u64,
    /// bit0=R bit1=W bit2=X（ELF PF_* 归一化，与 HostProt 编码一致）。
    pub prot: u8,
}

/// loader 的加载结果，直接供 GuestProcess 持有。
#[derive(Clone, Debug)]
pub struct LoadedImage {
    pub bias: u64,
    pub entry: u64,
    /// 映射后 program headers 的客户虚拟地址（AT_PHDR）。
    pub phdr: u64,
    pub phnum: u16,
    pub phentsize: u16,
    pub segments: Vec<Segment>,
    /// 客户可执行范围（VEH Rip 过滤用）。
    pub exec_ranges: Vec<(u64, u64)>,
    /// 整块映射范围（用于内存登记）。
    pub span: MemRange,
    /// 动态链接解释器（PLAN-0.0.4 T2.2）：PT_INTERP 存在时由 CLI 装载
    /// ld-musl 并挂载。真实入口 = interp.entry；AT_BASE = interp.bias；
    /// AT_PHDR/AT_ENTRY 仍指向主映像（与 Linux 内核 auxv 约定一致）。
    pub interp: Option<InterpImage>,
}

/// 解释器映像（ld-musl）的装载摘要。
#[derive(Clone, Debug)]
pub struct InterpImage {
    pub bias: u64,
    /// 已加 bias 的解释器入口（_dlstart）。
    pub entry: u64,
    /// 解释器整块映射范围（内存登记与 munmap 记账）。
    pub span: MemRange,
    pub exec_ranges: Vec<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemRange {
    pub start: u64,
    pub len: u64,
    /// 登记项类型：决定 munmap 用哪种宿主释放原语（两者在 Windows 上不可互换）。
    pub kind: MemKind,
}

/// 映射类型（PLAN-0.0.4 T1.3）。
/// - Reserve：匿名预留块（VirtualAlloc → VirtualFree 整块释放）；
/// - FileView：文件映射视图（MapViewOfFileEx → UnmapViewOfFile）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemKind {
    Reserve,
    FileView,
}

impl MemRange {
    pub fn reserve(start: u64, len: u64) -> MemRange {
        MemRange {
            start,
            len,
            kind: MemKind::Reserve,
        }
    }
    pub fn view(start: u64, len: u64) -> MemRange {
        MemRange {
            start,
            len,
            kind: MemKind::FileView,
        }
    }
}

/// 客户地址登记表：EFAULT 检查与 munmap 账本（规格 5.4）。
/// BTreeMap<u64 start, MemRange>：O(log n) 定位（v0 为线性扫描，PLAN T3.3）。
#[derive(Debug, Default)]
pub struct MemRegistry {
    /// key = start；区间不重叠（host.map 返回的去重结果保证）。
    pub ranges: std::collections::BTreeMap<u64, MemRange>,
}

impl MemRegistry {
    pub fn add(&mut self, r: MemRange) {
        if r.len == 0 {
            return;
        }
        self.ranges.insert(r.start, r);
    }

    /// [addr, addr+len) 是否完全落在某个已登记映射内。
    pub fn contains(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        let end = match addr.checked_add(len) {
            Some(e) => e,
            None => return false,
        };
        // 候选：start <= addr 的最大者（<= addr 的最后一个区间才可能覆盖 addr）
        match self.ranges.range(..=addr).next_back() {
            Some((_, r)) => addr >= r.start && end <= r.start + r.len,
            None => false,
        }
    }

    /// 返回完全包含 [addr, addr+len) 的登记项（mprotect/mmap 需要区分类型时用）。
    pub fn containing(&self, addr: u64, len: u64) -> Option<&MemRange> {
        if len == 0 {
            return None;
        }
        let end = addr.checked_add(len)?;
        self.ranges
            .range(..=addr)
            .next_back()
            .filter(|(_, r)| addr >= r.start && end <= r.start + r.len)
            .map(|(_, r)| r)
    }

    pub fn overlaps(&self, start: u64, len: u64) -> bool {
        let end = match start.checked_add(len) {
            Some(e) => e,
            None => return true, // 溢出视为覆盖全部
        };
        // 情况 1：存在区间起点落在 [start, end) 内
        if self.ranges.range(start..end).next().is_some() {
            return true;
        }
        // 情况 2：start 之前最后一个区间延伸越过 start
        self.ranges
            .range(..start)
            .next_back()
            .is_some_and(|(_, r)| r.start + r.len > start)
    }

    /// 移除完全被 [start, start+len) 覆盖的登记项并返回它们。
    /// v0 不做部分拆分（Windows 也无法部分 VirtualFree，规格 5.4）。
    pub fn remove_fully_covered(&mut self, start: u64, len: u64) -> Vec<MemRange> {
        let end = start.saturating_add(len);
        let fully: Vec<u64> = self
            .ranges
            .range(start..end)
            .filter(|(_, r)| r.start >= start && r.start + r.len <= end)
            .map(|(k, _)| *k)
            .collect();
        fully
            .into_iter()
            .filter_map(|k| self.ranges.remove(&k))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_checks_full_coverage() {
        let mut m = MemRegistry::default();
        m.add(MemRange::reserve(0x1000, 0x2000));
        assert!(m.contains(0x1000, 1));
        assert!(m.contains(0x1000, 0x2000));
        assert!(m.contains(0x1FFF, 0x1000));
        assert!(!m.contains(0x0FFF, 1));
        assert!(!m.contains(0x3000, 1));
        assert!(!m.contains(0x1000, 0x2001));
        assert!(!m.contains(0x1000, 0)); // len=0 一律 false
        assert!(!m.contains(u64::MAX, 1));
        assert_eq!(
            m.containing(0x1000, 0x2000).map(|r| r.kind),
            Some(MemKind::Reserve)
        );
    }

    #[test]
    fn overlaps_detects_any_intersection() {
        let mut m = MemRegistry::default();
        m.add(MemRange::reserve(0x1000, 0x1000));
        assert!(m.overlaps(0x1800, 0x100));
        assert!(m.overlaps(0x0800, 0x900)); // 头部相交
        assert!(m.overlaps(0x1800, 0x1000)); // 尾部相交
        assert!(m.overlaps(0x0800, 0x2000)); // 包围
        assert!(!m.overlaps(0x2000, 0x100)); // 相邻不重叠
        assert!(!m.overlaps(0x0000, 0x1000));
    }

    #[test]
    fn remove_only_fully_covered() {
        let mut m = MemRegistry::default();
        m.add(MemRange::reserve(0x1000, 0x1000));
        m.add(MemRange::reserve(0x3000, 0x1000));
        // 只完全覆盖第一个
        let r = m.remove_fully_covered(0x0, 0x2000);
        assert_eq!(r, vec![MemRange::reserve(0x1000, 0x1000)]);
        assert!(m.contains(0x3000, 1));
        // 部分覆盖不删除
        let r = m.remove_fully_covered(0x3000, 0x800);
        assert!(r.is_empty());
        assert!(m.contains(0x3000, 0x1000));
        // 全覆盖删除
        let r = m.remove_fully_covered(0x3000, 0x1000);
        assert_eq!(r.len(), 1);
        assert!(!m.contains(0x3000, 1));
    }

    #[test]
    fn view_ranges_carry_kind() {
        let mut m = MemRegistry::default();
        m.add(MemRange::view(0x5000, 0x2000));
        assert_eq!(
            m.containing(0x5000, 1).map(|r| r.kind),
            Some(MemKind::FileView)
        );
        assert_eq!(m.containing(0x4FFF, 1), None);
        assert_eq!(
            m.containing(0x6000, 0x1000).map(|r| r.kind),
            Some(MemKind::FileView)
        );
    }
}
