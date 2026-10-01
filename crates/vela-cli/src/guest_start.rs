//! 构造 Linux 进程初始栈（规格 4.2）。切入客户由 `HostTrap::enter_guest`
//! 承担（0.1.0 T1.1：汇编已迁入 vela-sys::windows）。

use vela_abi as abi;
use vela_runtime::mem::{LoadedImage, MemRange};
use vela_sys::{Host, HostError, HostProt};

pub(crate) const MAX_ARG_ENV_ENTRIES: usize = 4096;
pub(crate) const MAX_ARG_ENV_BYTES: usize = 8 * 1024 * 1024;

/// 按 Linux ELF 启动约定建栈：rsp 指向 argc，之后 argv[]/NULL/envp[]/NULL/auxv。
/// ELF `_start` 时 rsp % 16 == 0（规格 4.2，注意不是 Win64 约定）。
pub fn build_stack(
    host: &dyn Host,
    img: &LoadedImage,
    argv: &[String],
    envp: &[String],
    stack_mb: u64,
    uid: u32,
    gid: u32,
) -> Result<(u64, MemRange), String> {
    // 16 对齐由「整块 MiB 级尺寸 + 64K 对齐基址」共同保证
    let stack_size = stack_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| "stack size overflow (E2BIG)".to_string())?;
    if argv.is_empty() {
        return Err("guest argv is empty (E2BIG)".to_string());
    }
    if stack_size < 4096 {
        return Err("stack is too small (E2BIG)".to_string());
    }
    let entry_count = argv
        .len()
        .checked_add(envp.len())
        .ok_or_else(|| "too many argv/envp entries (E2BIG)".to_string())?;
    if entry_count > MAX_ARG_ENV_ENTRIES {
        return Err("too many argv/envp entries (E2BIG)".to_string());
    }
    let string_payload = argv
        .iter()
        .chain(envp.iter())
        .try_fold(0usize, |total, s| {
            total.checked_add(s.len().checked_add(1)?)
        })
        .ok_or_else(|| "argv/envp string size overflow (E2BIG)".to_string())?;
    if string_payload > MAX_ARG_ENV_BYTES {
        return Err("argv/envp strings exceed limit (E2BIG)".to_string());
    }
    let word_count = 1usize
        .checked_add(argv.len())
        .and_then(|v| v.checked_add(1))
        .and_then(|v| v.checked_add(envp.len()))
        .and_then(|v| v.checked_add(1))
        .and_then(|v| v.checked_add(16usize.checked_mul(2)?))
        .ok_or_else(|| "argv/envp metadata overflow (E2BIG)".to_string())?;
    let required = word_count
        .checked_mul(8)
        .and_then(|v| v.checked_add(string_payload))
        .and_then(|v| v.checked_add(16))
        .ok_or_else(|| "stack layout overflow (E2BIG)".to_string())?;
    let stack_size_usize = usize::try_from(stack_size)
        .map_err(|_| "stack size does not fit host (ENOMEM)".to_string())?;
    if required > stack_size_usize {
        return Err("argv/envp exceed stack capacity (E2BIG)".to_string());
    }

    // SAFETY: host.map 契约保证零填充可写内存
    let base = unsafe { host.map(0, stack_size_usize, HostProt::READ | HostProt::WRITE, true) }
        .map_err(|e: HostError| format!("map stack: {e}"))? as u64;
    let top = match base.checked_add(stack_size) {
        Some(top) => top,
        None => {
            let _ = unsafe { host.unmap(base as usize, stack_size_usize) };
            return Err("stack address overflow (ENOMEM)".to_string());
        }
    };

    // —— 自顶向下布局：
    //   [rsp(16对齐): argc|argv[]|NULL|envp[]|NULL|auxv]
    //   [对齐垫片]
    //   [argv/env 字符串]
    //   [AT_RANDOM 16 字节 @ top-16]

    let random_addr = top
        .checked_sub(16)
        .ok_or_else(|| "stack is too small (E2BIG)".to_string())?;
    let string_count = entry_count;
    let mut string_bytes: Vec<(u64, Vec<u8>)> = Vec::with_capacity(string_count);
    let mut str_ptrs: Vec<u64> = Vec::with_capacity(argv.len());
    let mut env_ptrs: Vec<u64> = Vec::with_capacity(envp.len());
    let mut cursor = random_addr;
    for s in argv.iter().chain(envp.iter()) {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        cursor = cursor
            .checked_sub(b.len() as u64)
            .ok_or_else(|| "argv/envp exceed stack capacity (E2BIG)".to_string())?;
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
        (abi::AT_UID, uid as u64),
        (abi::AT_EUID, uid as u64),
        (abi::AT_GID, gid as u64),
        (abi::AT_EGID, gid as u64),
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

    let words_bytes = words
        .len()
        .checked_mul(8)
        .ok_or_else(|| "argv/envp metadata overflow (E2BIG)".to_string())?;
    let strings_bytes = random_addr
        .checked_sub(strings_lo)
        .and_then(|v| v.checked_add(16))
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(|| "argv/envp string size overflow (E2BIG)".to_string())?;
    let total = words_bytes
        .checked_add(strings_bytes)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| "stack layout overflow (E2BIG)".to_string())?;
    if total > stack_size {
        return Err("argv/envp exceed stack capacity (E2BIG)".to_string());
    }
    let rsp = top
        .checked_sub(total)
        .ok_or_else(|| "argv/envp exceed stack capacity (E2BIG)".to_string())?
        & !15;

    // 组装整块后一次性拷入
    let buf_len = usize::try_from(
        top.checked_sub(rsp)
            .ok_or_else(|| "stack layout underflow (E2BIG)".to_string())?,
    )
    .map_err(|_| "stack layout too large (E2BIG)".to_string())?;
    let mut buf = vec![0u8; buf_len];
    for (i, w) in words.iter().enumerate() {
        let start = i
            .checked_mul(8)
            .ok_or_else(|| "argv/envp metadata overflow (E2BIG)".to_string())?;
        let end = start
            .checked_add(8)
            .ok_or_else(|| "argv/envp metadata overflow (E2BIG)".to_string())?;
        let dst = buf
            .get_mut(start..end)
            .ok_or_else(|| "argv/envp metadata exceeds stack (E2BIG)".to_string())?;
        dst.copy_from_slice(&w.to_le_bytes());
    }
    for (addr, b) in &string_bytes {
        let off = usize::try_from(
            addr.checked_sub(rsp)
                .ok_or_else(|| "argv/envp address underflow (E2BIG)".to_string())?,
        )
        .map_err(|_| "argv/envp offset too large (E2BIG)".to_string())?;
        let end = off
            .checked_add(b.len())
            .ok_or_else(|| "argv/envp string offset overflow (E2BIG)".to_string())?;
        let dst = buf
            .get_mut(off..end)
            .ok_or_else(|| "argv/envp strings exceed stack (E2BIG)".to_string())?;
        dst.copy_from_slice(b);
    }
    let mut rnd = [0u8; 16];
    if let Err(e) = host.random(&mut rnd) {
        let _ = unsafe { host.unmap(base as usize, stack_size_usize) };
        return Err(format!("random: {e}"));
    }
    let roff = usize::try_from(
        random_addr
            .checked_sub(rsp)
            .ok_or_else(|| "AT_RANDOM address underflow (E2BIG)".to_string())?,
    )
    .map_err(|_| "AT_RANDOM offset too large (E2BIG)".to_string())?;
    let rend = roff
        .checked_add(16)
        .ok_or_else(|| "AT_RANDOM offset overflow (E2BIG)".to_string())?;
    let dst = buf
        .get_mut(roff..rend)
        .ok_or_else(|| "AT_RANDOM exceeds stack (E2BIG)".to_string())?;
    dst.copy_from_slice(&rnd);

    // SAFETY: [rsp, top) 为刚映射的可写客户栈；写入范围不越界
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), rsp as *mut u8, buf.len());
    }

    Ok((rsp, MemRange::reserve(base, stack_size)))
}
