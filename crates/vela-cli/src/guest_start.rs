//! 构造 Linux 进程初始栈（规格 4.2）并切入客户（规格 6）。

use vela_abi as abi;
use vela_runtime::mem::{LoadedImage, MemRange};
use vela_sys::{Host, HostError, HostProt};

/// 切换到客户栈并跳入客户入口；不返回（exit_group 直接结束进程，规格 6）。
///
/// # Safety
/// entry/rsp 必须来自 loader 的映射结果；调用后本线程宿主栈作废。
pub unsafe fn enter_guest(entry: u64, rsp: u64) -> ! {
    unsafe { vela_enter_guest(entry, rsp) }
}

// Win64 ABI：参数在 rcx(entry)/rdx(rsp)。Vela 自身汇编边界用 Win64；客户内部用 SysV（规格 6）。
#[cfg(all(target_arch = "x86_64", windows))]
core::arch::global_asm!(
    ".globl vela_enter_guest",
    "vela_enter_guest:",
    "    mov rsp, rdx",
    "    xor ebp, ebp",
    "    xor ebx, ebx",
    "    jmp rcx",
);

// SysV ABI（linux dev 构建仅用于逻辑检查，不真正执行客户）
#[cfg(all(target_arch = "x86_64", not(windows)))]
core::arch::global_asm!(
    ".globl vela_enter_guest",
    "vela_enter_guest:",
    "    mov %rsi, %rsp",
    "    xor %rbp, %rbp",
    "    xor %rbx, %rbx",
    "    jmp *%rdi",
    options(att_syntax)
);

extern "C" {
    fn vela_enter_guest(entry: u64, rsp: u64) -> !;
}

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
    let base = unsafe { host.map(0, stack_size as usize, HostProt::READ | HostProt::WRITE, true) }
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

    let auxv: Vec<(u64, u64)> = vec![
        (abi::AT_PHDR, img.phdr),
        (abi::AT_PHENT, img.phentsize as u64),
        (abi::AT_PHNUM, img.phnum as u64),
        (abi::AT_PAGESZ, 4096),
        (abi::AT_BASE, img.bias),
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

    Ok((rsp, MemRange { start: base, len: stack_size }))
}
