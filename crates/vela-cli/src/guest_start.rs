//! 构造 Linux 进程初始栈（规格 4.2）。切入客户由 `HostTrap::enter_guest`
//! 承担（0.1.0 T1.1：汇编已迁入 vela-sys::windows）。

use vela_abi as abi;
use vela_runtime::mem::{LoadedImage, MemRange};
use vela_sys::{Host, HostError, HostProt};

/// 按 Linux ELF 启动约定建栈：rsp 指向 argc，之后 argv[]/NULL/envp[]/NULL/auxv。
/// ELF `_start` 时 rsp % 16 == 0（规格 4.2，注意不是 Win64 约定）。
pub fn build_stack(
    host: &dyn Host,
    img: &LoadedImage,
    argv: &[String],
    envp: &[String],
    stack_mb: u64,
) -> Result<(u64, MemRange), String> {
    // 16 对齐由「整块 MiB 级尺寸 + 64K 对齐基址」共同保证
    let stack_size = stack_mb * 1024 * 1024;
    if argv.is_empty() {
        return Err("guest argv is empty".to_string());
    }

    // SAFETY: host.map 契约保证零填充可写内存
    let base = unsafe {
        host.map(
            0,
            stack_size as usize,
            HostProt::READ | HostProt::WRITE,
            true,
        )
    }
    .map_err(|e: HostError| format!("map stack: {e}"))? as u64;
    let top = base + stack_size;

    // —— 自顶向下布局：
    //   [rsp(16对齐): argc|argv[]|NULL|envp[]|NULL|auxv]
    //   [对齐垫片]
    //   [argv/env 字符串]
    //   [AT_RANDOM 16 字节 @ top-16]

    let random_addr = top - 16;
    let mut string_bytes: Vec<(u64, Vec<u8>)> = Vec::with_capacity(argv.len() + envp.len());
    let mut str_ptrs: Vec<u64> = Vec::with_capacity(argv.len());
    let mut env_ptrs: Vec<u64> = Vec::with_capacity(envp.len());
    let mut cursor = random_addr;
    for s in argv.iter().chain(envp.iter()) {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        cursor -= b.len() as u64;
        // 先 argv 后 env：str_ptrs 收 argv，env_ptrs 收 env
        if str_ptrs.len() < argv.len() {
            str_ptrs.push(cursor);
        } else {
            env_ptrs.push(cursor);
        }
        string_bytes.push((cursor, b));
    }
    let strings_lo = cursor;
    let execfn_addr = str_ptrs[0];

    // AT_BASE：静态映像为自身 bias；动态映像为解释器 bias（Linux 内核 auxv
    // 约定：AT_PHDR/AT_ENTRY 指主程序，AT_BASE 指解释器，PLAN-0.0.4 T2.2）
    let at_base = img.interp.as_ref().map_or(img.bias, |i| i.bias);
    let auxv: Vec<(u64, u64)> = vec![
        (abi::AT_PHDR, img.phdr),
        (abi::AT_PHENT, img.phentsize as u64),
        (abi::AT_PHNUM, img.phnum as u64),
        (abi::AT_PAGESZ, 4096),
        (abi::AT_BASE, at_base),
        (abi::AT_ENTRY, img.entry),
        (abi::AT_UID, 1000),
        (abi::AT_EUID, 1000),
        (abi::AT_GID, 1000),
        (abi::AT_EGID, 1000),
        (abi::AT_HWCAP, 0),
        (abi::AT_CLKTCK, 100),
        (abi::AT_SECURE, 0),
        (abi::AT_RANDOM, random_addr),
        (abi::AT_EXECFN, execfn_addr),
        (abi::AT_NULL, 0),
    ];

    let mut words: Vec<u64> = Vec::new();
    words.push(argv.len() as u64); // argc
    words.extend(str_ptrs.iter().copied()); // argv[0..n]
    words.push(0); // argv 终止 NULL
    words.extend(env_ptrs.iter().copied()); // envp[0..m]
    words.push(0); // envp 终止 NULL
    for (t, v) in &auxv {
        words.push(*t);
        words.push(*v);
    }

    let words_bytes = words.len() * 8;
    let strings_bytes = (random_addr - strings_lo) as usize + 16;
    let total = (words_bytes + strings_bytes) as u64;
    let rsp = (top - total) & !15; // ELF _start：rsp%16==0 且 [rsp]=argc

    // 组装整块后一次性拷入
    let mut buf = vec![0u8; (top - rsp) as usize];
    for (i, w) in words.iter().enumerate() {
        buf[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    for (addr, b) in &string_bytes {
        let off = (addr - rsp) as usize;
        buf[off..off + b.len()].copy_from_slice(b);
    }
    let mut rnd = [0u8; 16];
    host.random(&mut rnd).map_err(|e| format!("random: {e}"))?;
    let roff = (random_addr - rsp) as usize;
    buf[roff..roff + 16].copy_from_slice(&rnd);

    // SAFETY: [rsp, top) 为刚映射的可写客户栈；写入范围不越界
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), rsp as *mut u8, buf.len());
    }

    Ok((rsp, MemRange::reserve(base, stack_size)))
}
