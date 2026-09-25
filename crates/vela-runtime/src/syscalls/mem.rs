//! 内存子系统（PLAN-0.1.0 T5.1）：mmap / mmap_file / mprotect / munmap /
//! msync / brk——客户地址空间原语的宿主翻译。

use vela_abi as abi;
use vela_sys::{Host, HostError, HostFile, HostProt};

use crate::{host_err_to_errno, write_guest, GuestFd, GuestProcess};

const PAGE: u64 = 4096;

pub(super) fn sys_mmap(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let (addr, len, linux_prot, flags) = (a[0], a[1], a[2], a[3]);
    if len == 0 {
        return -(abi::EINVAL as i64);
    }
    let private = flags & abi::MAP_PRIVATE as u64 != 0;
    let shared = flags & abi::MAP_SHARED as u64 != 0;
    if !private && !shared {
        return -(abi::EINVAL as i64);
    }
    let anon = flags & abi::MAP_ANONYMOUS as u64 != 0;
    if shared {
        // MAP_SHARED（含共享匿名）延后：文件映射体系当前只做 MAP_PRIVATE
        //（PLAN-0.0.4 T1.2，记录于 SYSCALLS.md）
        return -(abi::ENOSYS as i64);
    }
    if !anon {
        return sys_mmap_file(proc, host, a);
    }
    let len_up = (len + PAGE - 1) & !(PAGE - 1);
    let fixed = flags & abi::MAP_FIXED as u64 != 0 && addr != 0;
    if fixed && proc.mem.overlaps(addr, len_up) {
        // Linux 语义：MAP_FIXED 替换既有映射。vela 无法部分释放 Windows 预留块；
        // 但 musl mallocng 依赖"把 brk 新增页用 MAP_FIXED 匿名映射转为可 munmap
        // 映射"（donate）。整个区间落在单个 Reserve 块内时就地接受并收敛保护位。
        // T1.4：显式清零对齐 Linux 的"替换 = 匿名零页"语义。
        if proc.mem.contains(addr, len_up)
            && proc.mem.containing(addr, len_up).map(|r| r.kind)
                == Some(crate::mem::MemKind::Reserve)
        {
            let prot = HostProt::from_bits(linux_prot as u32);
            let _ = unsafe {
                host.protect(
                    addr as usize,
                    len_up as usize,
                    HostProt::READ | HostProt::WRITE,
                )
            };
            // SAFETY: 区间已登记且此刻可写
            unsafe {
                std::ptr::write_bytes(addr as *mut u8, 0, len_up as usize);
            }
            if prot.bits() != (HostProt::READ | HostProt::WRITE).bits() {
                let _ = unsafe { host.protect(addr as usize, len_up as usize, prot) };
            }
            // T3.2 账本（fork 快照一致性）：mallocng 的 donate 用
            // MAP_FIXED+PROT_NONE 把堆首/预留区页转为不可读——不记账则
            // fork 快照整块 memcpy 读到 PAGE_NOACCESS 页 → 宿主 AV
            //（CI ash `echo hello | wc -c` 现场，addr=堆基址精确吻合）。
            proc.prot_ledger.push(crate::ProtOverride {
                start: addr,
                len: len_up,
                prot: linux_prot as u8,
            });
            return addr as i64;
        }
        return -(abi::ENOMEM as i64);
    }
    let hint = if fixed { addr as usize } else { 0 };
    // 先 RW 提交（host.map 契约），再收敛到请求保护位
    let got = match unsafe {
        host.map(
            hint,
            len_up as usize,
            HostProt::READ | HostProt::WRITE,
            true,
        )
    } {
        Ok(p) => p as u64,
        Err(e) => return -(host_err_to_errno(&e) as i64),
    };
    if fixed && got != addr {
        let _ = unsafe { host.unmap(got as usize, len_up as usize) };
        return -(abi::ENOMEM as i64);
    }
    let prot = HostProt::from_bits(linux_prot as u32);
    if prot.bits() != (HostProt::READ | HostProt::WRITE).bits() {
        let _ = unsafe { host.protect(got as usize, len_up as usize, prot) };
        // 同上：收敛保护位必须入账本（fork 快照/子进程重放一致性）
        proc.prot_ledger.push(crate::ProtOverride {
            start: got,
            len: len_up,
            prot: linux_prot as u8,
        });
    }
    proc.mem.add(crate::mem::MemRange::reserve(got, len_up));
    got as i64
}

/// 文件映射视图的对齐约束（Windows 分配粒度，见 windows::ALLOC_GRANULARITY）。
/// offset/hint 对齐时走真文件视图（demand paging + COW）；否则退化为
/// 匿名映射 + 读入内容（语义等价，仅无缺页加速）。
const MAP_VIEW_GRAN: u64 = 0x1_0000;

/// MAP_PRIVATE + fd 的文件映射（PLAN-0.0.4 T1.2）。
/// 优先真文件视图；MAP_FIXED 落在已登记预留区内时（ld-musl 先 PROT_NONE
/// 预留、再逐段 MAP_FIXED 覆盖的装载模式）直接把文件内容读入既有页——
/// Windows 预留块无法部分释放，读入副本与 Linux 的覆盖映射语义一致。
pub(super) fn sys_mmap_file(proc: &mut GuestProcess, host: &dyn Host, a: [u64; 6]) -> i64 {
    let (addr, len, linux_prot, flags, fd_raw, offset) = (a[0], a[1], a[2], a[3], a[4], a[5]);
    let fd = fd_raw as u32 as i32;
    let f = match proc.fds.get(fd) {
        Some(GuestFd::Host(f)) => f,
        // Linux 对 /dev/null、目录、管道等不可映射对象返回 ENODEV
        Some(GuestFd::HostDir(_))
        | Some(GuestFd::Null)
        | Some(GuestFd::Zero)
        | Some(GuestFd::PipeRead(_))
        | Some(GuestFd::PipeWrite(_)) => return -(abi::ENODEV as i64),
        None | Some(GuestFd::Reserved) => return -(abi::EBADF as i64),
    };
    let len_up = (len + PAGE - 1) & !(PAGE - 1);
    let fixed = flags & abi::MAP_FIXED as u64 != 0 && addr != 0;
    let prot = HostProt::from_bits(linux_prot as u32);

    let carve = fixed && proc.mem.contains(addr, len_up);
    if carve
        && proc.mem.containing(addr, len_up).map(|r| r.kind) == Some(crate::mem::MemKind::FileView)
    {
        // 覆盖文件视图区间无法重建（视图不可部分重映射），诚实拒绝
        return -(abi::ENOMEM as i64);
    }
    if fixed && !carve && proc.mem.overlaps(addr, len_up) {
        return -(abi::ENOMEM as i64);
    }

    // 真文件视图：offset 与（固定时）hint 都必须对齐分配粒度
    if !carve {
        let can_view =
            offset.is_multiple_of(MAP_VIEW_GRAN) && (!fixed || addr.is_multiple_of(MAP_VIEW_GRAN));
        if can_view {
            let hint = if fixed { addr as usize } else { 0 };
            match unsafe { host.map_file(f, offset, len_up as usize, hint, prot) } {
                Ok(base) if !fixed || base == addr as usize => {
                    proc.mem
                        .add(crate::mem::MemRange::view(base as u64, len_up));
                    return base as i64;
                }
                Ok(base) => {
                    // 宿主自选了别的基址：违背 MAP_FIXED，回滚走读入回退
                    let _ = unsafe { host.unmap_view(base) };
                }
                Err(_) => {}
            }
        }
    }

    // 阶段 1：文件内容读入本地缓冲（此后不再持有 fd 借用）。EOF 之后保持
    // 零填充（mmap 对文件尾之外的页保证读到 0）。
    let mut data = vec![0u8; len_up as usize];
    if let Err(e) = read_file_at(host, f, offset, &mut data) {
        return -(host_err_to_errno(&e) as i64);
    }

    // 阶段 2：进程状态变更
    if carve {
        // 预留区可能处于 PROT_NONE：先放开为 RW，写入后收敛到请求保护位
        let _ = unsafe {
            host.protect(
                addr as usize,
                len_up as usize,
                HostProt::READ | HostProt::WRITE,
            )
        };
        if let Err(e) = write_guest(proc, addr, &data) {
            return -(e as i64);
        }
        if prot.bits() != (HostProt::READ | HostProt::WRITE).bits() {
            let _ = unsafe { host.protect(addr as usize, len_up as usize, prot) };
        }
        return addr as i64;
    }
    let hint = if fixed { addr as usize } else { 0 };
    let got = match unsafe {
        host.map(
            hint,
            len_up as usize,
            HostProt::READ | HostProt::WRITE,
            true,
        )
    } {
        Ok(p) => p as u64,
        Err(e) => return -(host_err_to_errno(&e) as i64),
    };
    if fixed && got != addr {
        let _ = unsafe { host.unmap(got as usize, len_up as usize) };
        return -(abi::ENOMEM as i64);
    }
    proc.mem.add(crate::mem::MemRange::reserve(got, len_up));
    if let Err(e) = write_guest(proc, got, &data) {
        return -(e as i64);
    }
    if prot.bits() != (HostProt::READ | HostProt::WRITE).bits() {
        let _ = unsafe { host.protect(got as usize, len_up as usize, prot) };
    }
    got as i64
}

/// 把 fd 在 offset 处的内容读满 buf；EOF 尾部保持 buf 既有值（零填充）。
/// 读取前后保存/恢复该 fd 的游标（v0 单线程客户，短暂移动安全）。
fn read_file_at(
    host: &dyn Host,
    f: &HostFile,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), HostError> {
    let cur = host.seek(f, 0, 1)?;
    let mut filled = 0usize;
    let result = host.seek(f, offset as i64, 0).and_then(|_| {
        while filled < buf.len() {
            match host.read(f, &mut buf[filled..]) {
                Ok(0) => break, // EOF
                Ok(n) => filled += n,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });
    let _ = host.seek(f, cur as i64, 0);
    result
}

pub(super) fn sys_mprotect(
    proc: &mut GuestProcess,
    host: &dyn Host,
    addr: u64,
    len: u64,
    linux_prot: u64,
) -> i64 {
    if len == 0 {
        return 0;
    }
    // 文件视图上 VirtualProtect(RW) 会关闭 COW、把写入穿透到宿主文件——
    // MAP_PRIVATE 必须写私有，故对视图区间剥离 WRITE 位（W-only 变 no-op）。
    let view =
        proc.mem.containing(addr, len).map(|r| r.kind) == Some(crate::mem::MemKind::FileView);
    let prot = if view {
        HostProt::from_bits(linux_prot as u32 & !HostProt::WRITE.bits())
    } else {
        HostProt::from_bits(linux_prot as u32)
    };
    if !proc.mem.contains(addr, len) {
        return -(abi::ENOMEM as i64);
    }
    if view && prot.bits() == 0 {
        return 0;
    }
    match unsafe { host.protect(addr as usize, len as usize, prot) } {
        Ok(()) => {
            // T3.2 账本：记录客户请求的原值（不剥离 FileView WRITE 位——
            // fork 子进程的区间是 section 视图非 COW 文件映射，W 合法）
            proc.prot_ledger.push(crate::ProtOverride {
                start: addr,
                len,
                prot: linux_prot as u8,
            });
            0
        }
        Err(e) => -(host_err_to_errno(&e) as i64),
    }
}

pub(super) fn sys_munmap(
    proc: &mut GuestProcess,
    host: &dyn Host,
    addr_raw: u64,
    len_raw: u64,
) -> i64 {
    let addr = addr_raw & !(PAGE - 1);
    let len = (len_raw + PAGE - 1) & !(PAGE - 1);
    if len == 0 {
        return 0;
    }
    // v0：只移除完全被覆盖的登记项，释放 best-effort（规格 5.4）；
    // 登记项类型决定释放原语：文件视图走 UnmapViewOfFile（PLAN-0.0.4 T1.3）。
    // Island（0.1.0 T2.1）：客户 munmap 岛页无意义，仅解除登记不释放
    // （释放原语是 Windows 私有细节，语义上等同 Reserve 的诚实近似——
    // 但岛页地址空间极小且与映像同寿命，直接吞掉释放动作）。
    let removed = proc.mem.remove_fully_covered(addr, len);
    for r in &removed {
        let _ = match r.kind {
            crate::mem::MemKind::FileView => unsafe { host.unmap_view(r.start as usize) },
            crate::mem::MemKind::Reserve | crate::mem::MemKind::Island => unsafe {
                host.unmap(r.start as usize, r.len as usize)
            },
        };
    }
    0
}

/// msync(26)：vela 文件映射只有 MAP_PRIVATE（无回写语义），flush 恒为 no-op；
/// 仅做参数/区间校验，保持 Linux 错误语义。
pub(super) fn sys_msync(proc: &GuestProcess, addr_raw: u64, len: u64) -> i64 {
    if !addr_raw.is_multiple_of(PAGE) || len == 0 {
        return -(abi::EINVAL as i64);
    }
    if !proc.mem.contains(addr_raw, len) {
        return -(abi::ENOMEM as i64);
    }
    0
}

pub(super) fn sys_brk(proc: &mut GuestProcess, req: u64) -> i64 {
    // 堆为加载后预留的连续匿名块，brk 仅在块内移动断点（规格 5.4）
    let Some(heap) = proc.heap else {
        return -(abi::ENOMEM as i64);
    };
    if req == 0 || req < heap.start || req > heap.start + heap.len {
        // brk(0) 查询 / 越界：返回当前断点
        return proc.brk as i64;
    }
    proc.brk = req;
    proc.brk as i64
}
