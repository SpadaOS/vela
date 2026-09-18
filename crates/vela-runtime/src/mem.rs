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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemRange {
    pub start: u64,
    pub len: u64,
}

/// 客户地址登记表：EFAULT 检查与 munmap 账本（规格 5.4）。
#[derive(Debug, Default)]
pub struct MemRegistry {
    pub ranges: Vec<MemRange>,
}

impl MemRegistry {
    pub fn add(&mut self, r: MemRange) {
        if r.len == 0 {
            return;
        }
        self.ranges.push(r);
    }

    /// [addr, addr+len) 是否完全落在某个已登记映射内。
    pub fn contains(&self, addr: u64, len: u64) -> bool {
        if len == 0 {
            return false;
        }
        self.ranges
            .iter()
            .any(|r| addr >= r.start && addr.checked_add(len).is_some_and(|end| end <= r.start + r.len))
    }

    pub fn overlaps(&self, start: u64, len: u64) -> bool {
        self.ranges
            .iter()
            .any(|r| start < r.start + r.len && r.start < start + len)
    }

    /// 移除完全被 [start, start+len) 覆盖的登记项并返回它们。
    /// v0 不做部分拆分（Windows 也无法部分 VirtualFree，规格 5.4）。
    pub fn remove_fully_covered(&mut self, start: u64, len: u64) -> Vec<MemRange> {
        let (mut kept, mut removed) = (Vec::new(), Vec::new());
        for r in self.ranges.drain(..) {
            if r.start >= start && r.start + r.len <= start + len {
                removed.push(r);
            } else {
                kept.push(r);
            }
        }
        self.ranges = kept;
        removed
    }
}
