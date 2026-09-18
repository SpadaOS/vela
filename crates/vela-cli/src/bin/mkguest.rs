//! vela-mkguest：生成综合压测 guest ELF（双 PT_LOAD：RX 代码段 + RW 数据段）。
//!
//! - `torture`：brk / mmap / uname / getrandom / writev 全链路真执行，
//!   输出 `Linuxmmap 1g1 ok\n`（任何机器可跑，不依赖 TLS）。
//! - `tls`：额外验证 arch_prctl(SET_FS) 后 FS 相对寻址真正生效，
//!   输出 `mmap 1t1 ok\n`（需要 FSGSBASE 支持，否则 fs 访问会崩溃）。
//!
//! 生成的机器码为手写 x64 编码，rip 相对位移由生成器自动回填。

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: vela-mkguest <torture|tls|bench> <output-file>");
        std::process::exit(2);
    }
    let elf = match args[1].as_str() {
        "torture" => build_torture(),
        "tls" => build_tls(),
        "bench" => build_bench(),
        other => {
            eprintln!("unknown kind: {other}");
            std::process::exit(2);
        }
    };
    if let Err(e) = std::fs::write(&args[2], &elf) {
        eprintln!("vela-mkguest: write {}: {e}", args[2]);
        std::process::exit(1);
    }
    println!("wrote {} ({} bytes)", args[2], elf.len());
}

// ---------------------------------------------------------------- ELF 框架

/// 代码段虚拟地址：64(ehdr) + 2*56(phdr) = 176 = 0xB0，p_offset==p_vaddr 平铺。
const CODE_VADDR: u64 = 0xB0;
/// 数据段（第二 PT_LOAD）基址。
const DATA_VADDR: u64 = 0x1000;

struct Code {
    buf: Vec<u8>,
    /// (disp32 在 buf 内的位置, 指令结束位置, 数据符号, 附加偏移)
    fix: Vec<(usize, usize, &'static str, i64)>,
}

impl Code {
    fn new() -> Self {
        Code {
            buf: Vec::new(),
            fix: Vec::new(),
        }
    }
    fn e(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    fn imm32(&mut self, v: i32) {
        self.e(&v.to_le_bytes());
    }
    fn push_fix(&mut self, sym: &'static str, addend: i64) {
        let at = self.buf.len();
        self.e(&[0, 0, 0, 0]);
        let end = self.buf.len();
        self.fix.push((at, end, sym, addend));
    }
    // ---- 指令封装（Intel 编码）
    fn mov_rax_i32(&mut self, v: i32) {
        self.e(&[0x48, 0xC7, 0xC0]);
        self.imm32(v);
    }
    fn mov_rdi_i32(&mut self, v: i32) {
        self.e(&[0x48, 0xC7, 0xC7]);
        self.imm32(v);
    }
    fn mov_rsi_i32(&mut self, v: i32) {
        self.e(&[0x48, 0xC7, 0xC6]);
        self.imm32(v);
    }
    fn mov_rdx_i32(&mut self, v: i32) {
        self.e(&[0x48, 0xC7, 0xC2]);
        self.imm32(v);
    }
    fn mov_r10_i32(&mut self, v: i32) {
        self.e(&[0x49, 0xC7, 0xC2]);
        self.imm32(v);
    }
    fn mov_r8_i32(&mut self, v: i32) {
        self.e(&[0x49, 0xC7, 0xC0]);
        self.imm32(v);
    }
    fn xor_rdi(&mut self) {
        self.e(&[0x48, 0x31, 0xFF]);
    }
    fn xor_rdx(&mut self) {
        self.e(&[0x48, 0x31, 0xD2]);
    }
    fn xor_rcx(&mut self) {
        self.e(&[0x48, 0x31, 0xC9]);
    }
    fn xor_r9(&mut self) {
        self.e(&[0x4D, 0x31, 0xC9]);
    }
    fn syscall(&mut self) {
        self.e(&[0x0F, 0x05]);
    }
    fn mov_rip_rax(&mut self, sym: &'static str) {
        self.e(&[0x48, 0x89, 0x05]); // mov [rip+d], rax
        self.push_fix(sym, 0);
    }
    fn mov_rip_rax_off(&mut self, sym: &'static str, off: i64) {
        self.e(&[0x48, 0x89, 0x05]); // mov [rip+d+off], rax
        self.push_fix(sym, off);
    }
    fn mov_rax_rip(&mut self, sym: &'static str) {
        self.e(&[0x48, 0x8B, 0x05]); // mov rax, [rip+d]
        self.push_fix(sym, 0);
    }
    fn lea_rip(&mut self, modrm: u8, sym: &'static str) {
        self.e(&[0x48, 0x8D, modrm]); // lea r64, [rip+d]
        self.push_fix(sym, 0);
    }
    fn mov_rip_cl(&mut self, sym: &'static str, off: i64) {
        self.e(&[0x88, 0x0D]); // mov [rip+d], cl
        self.push_fix(sym, off);
    }
    fn mov_dword_rax_i32(&mut self, v: u32) {
        self.e(&[0xC7, 0x00]); // mov dword [rax], imm32
        self.e(&v.to_le_bytes());
    }
    fn mov_dword_rip_i32(&mut self, sym: &'static str, off: i64, v: u32) {
        self.e(&[0xC7, 0x05]); // mov dword [rip+d], imm32
        let at = self.buf.len();
        self.e(&[0, 0, 0, 0]); // disp32 占位
                               // 注意：imm32 在 disp32 之后，rip 相对位移以整条指令结束处为基准
        let end = self.buf.len() + 4;
        self.e(&v.to_le_bytes());
        self.fix.push((at, end, sym, off));
    }
    fn mov_byte_rax4_i8(&mut self, v: u8) {
        self.e(&[0xC6, 0x40, 0x04, v]); // mov byte [rax+4], imm8
    }
    fn mov_rax_fs_off(&mut self, off: u32) {
        self.e(&[0x64, 0x48, 0x8B, 0x04, 0x25]); // mov rax, qword fs:[d32]
        self.imm32(off as i32);
    }
    fn test_rax(&mut self) {
        self.e(&[0x48, 0x85, 0xC0]);
    }
    fn cmp_rax_i32(&mut self, v: i32) {
        self.e(&[0x48, 0x3D]);
        self.imm32(v);
    }
    fn cmp_rax_rdx(&mut self) {
        self.e(&[0x48, 0x39, 0xD0]);
    }
    fn sete_cl(&mut self) {
        self.e(&[0x0F, 0x94, 0xC1]);
    }
    fn setne_cl(&mut self) {
        self.e(&[0x0F, 0x95, 0xC1]);
    }
    fn add_cl_0(&mut self) {
        self.e(&[0x80, 0xC1, 0x30]); // add cl, '0'
    }
}

struct Data {
    blob: Vec<u8>,
    syms: Vec<(&'static str, usize)>,
}

impl Data {
    fn new() -> Self {
        Data {
            blob: Vec::new(),
            syms: Vec::new(),
        }
    }
    fn sym(&mut self, name: &'static str, bytes: &[u8]) {
        let off = self.blob.len();
        self.blob.extend_from_slice(bytes);
        self.syms.push((name, off));
    }
    fn zero(&mut self, name: &'static str, n: usize) {
        self.sym(name, &vec![0u8; n]);
    }
    fn off(&self, name: &str) -> usize {
        self.syms
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, o)| *o)
            .expect("sym")
    }
    fn patch_u64(&mut self, name: &str, off: usize, v: u64) {
        let base = self.off(name);
        self.blob[base + off..base + off + 8].copy_from_slice(&v.to_le_bytes());
    }
}

/// 组装 ELF：PH1=RX 代码页，PH2=RW 数据段，回填 rip 相对位移。
fn frame(code: Code, data: Data) -> Vec<u8> {
    let code_end = CODE_VADDR as usize + code.buf.len();
    assert!(code_end <= DATA_VADDR as usize, "code overflow");
    let data_len = data.blob.len();
    let total = DATA_VADDR as usize + data_len;
    let mut f = vec![0u8; total];

    // ---- ELF header
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    f[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    f[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    f[20..24].copy_from_slice(&1u32.to_le_bytes());
    f[0x18..0x20].copy_from_slice(&CODE_VADDR.to_le_bytes()); // e_entry
    f[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
    f[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    f[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    f[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

    // ---- PH1: PT_LOAD R|X（头 + 代码，整页）
    let p1 = 0x40;
    f[p1..p1 + 4].copy_from_slice(&1u32.to_le_bytes());
    f[p1 + 4..p1 + 8].copy_from_slice(&5u32.to_le_bytes());
    // p_offset=0 / p_vaddr=0 / p_paddr=0
    f[p1 + 32..p1 + 40].copy_from_slice(&(DATA_VADDR).to_le_bytes()); // filesz
    f[p1 + 40..p1 + 48].copy_from_slice(&(DATA_VADDR).to_le_bytes()); // memsz
    f[p1 + 48..p1 + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    // ---- PH2: PT_LOAD R|W（数据）
    let p2 = 0x78;
    f[p2..p2 + 4].copy_from_slice(&1u32.to_le_bytes());
    f[p2 + 4..p2 + 8].copy_from_slice(&6u32.to_le_bytes());
    f[p2 + 8..p2 + 16].copy_from_slice(&DATA_VADDR.to_le_bytes()); // p_offset
    f[p2 + 16..p2 + 24].copy_from_slice(&DATA_VADDR.to_le_bytes()); // p_vaddr
    f[p2 + 32..p2 + 40].copy_from_slice(&(data_len as u64).to_le_bytes());
    f[p2 + 40..p2 + 48].copy_from_slice(&(data_len as u64).to_le_bytes());
    f[p2 + 48..p2 + 56].copy_from_slice(&0x1000u64.to_le_bytes());

    // ---- 内容
    f[CODE_VADDR as usize..code_end].copy_from_slice(&code.buf);
    f[DATA_VADDR as usize..total].copy_from_slice(&data.blob);

    // ---- rip 相对位移回填：disp = target - end_ip
    for (at, end, sym, add) in &code.fix {
        let target = DATA_VADDR as i64 + data.off(sym) as i64 + add;
        let end_ip = CODE_VADDR as i64 + *end as i64;
        let disp = (target - end_ip) as i32;
        let fp = CODE_VADDR as usize + at;
        f[fp..fp + 4].copy_from_slice(&disp.to_le_bytes());
    }
    f
}

/// 写 iov 结构：base 在 off+0，len 在 off+8。
fn mmap_and_fill(c: &mut Code, iov_sym: &'static str) {
    // mmap(0, 0x2000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    c.mov_rax_i32(9);
    c.xor_rdi();
    c.mov_rsi_i32(0x2000);
    c.mov_rdx_i32(3);
    c.mov_r10_i32(0x22);
    c.mov_r8_i32(-1); // fd = -1（sign-extended）
    c.xor_r9();
    c.syscall();
    // mmap_ptr = rax；把 "mmap " 写进新映射；iov[0].base = mmap addr
    c.mov_rip_rax("mmap_ptr");
    c.mov_dword_rax_i32(0x7061_6D6D); // "mmap"
    c.mov_byte_rax4_i8(0x20); // ' '
    c.mov_rip_rax(iov_sym);
}

/// "Linux"（uname sysname）+ "mmap ?g? ok\n"，? = brk/getrandom 自检。
fn build_torture() -> Vec<u8> {
    let mut d = Data::new();
    d.zero("iovA", 16); // (uname_buf, 5)——base 由 guest 运行时填
    d.zero("iovB", 32); // (mmap, 5) + (msg, 7)
    d.sym("msg", b"0g0 ok\n\0");
    d.zero("mmap_ptr", 8);
    d.zero("uname_buf", 390);
    d.zero("rnd_buf", 16);
    d.patch_u64("iovA", 8, 5);
    d.patch_u64("iovB", 8, 5);
    d.patch_u64("iovB", 24, 7);

    let mut c = Code::new();

    // 绝对指针一律运行时填写（合成 guest 无重定位处理）：
    // iovA[0].base = &uname_buf；iovB[1].base = &msg
    c.lea_rip(0x05, "uname_buf"); // lea rax, [rip+uname_buf]
    c.mov_rip_rax_off("iovA", 0);
    c.lea_rip(0x05, "msg");
    c.mov_rip_rax_off("iovB", 16);

    // brk(0) → rax = 当前断点（>0）
    c.mov_rax_i32(12);
    c.xor_rdi();
    c.syscall();
    c.xor_rcx();
    c.test_rax();
    c.setne_cl();
    c.add_cl_0();
    c.mov_rip_cl("msg", 2);

    // mmap + "mmap " + iovB[0].base
    mmap_and_fill(&mut c, "iovB");

    // uname(buf)
    c.mov_rax_i32(63);
    c.lea_rip(0x3D, "uname_buf"); // lea rdi
    c.syscall();

    // getrandom(rnd_buf, 16, 0) → 检查非零
    c.mov_rax_i32(318);
    c.lea_rip(0x3D, "rnd_buf");
    c.mov_rsi_i32(16);
    c.xor_rdx();
    c.syscall();
    c.mov_rax_rip("rnd_buf");
    c.xor_rcx();
    c.test_rax();
    c.setne_cl();
    c.add_cl_0();
    c.mov_rip_cl("msg", 0);

    // writev(1, iovA, 1) → "Linux"
    c.mov_rax_i32(20);
    c.mov_rdi_i32(1);
    c.lea_rip(0x35, "iovA"); // lea rsi
    c.mov_rdx_i32(1);
    c.syscall();

    // writev(1, iovB, 2) → "mmap ?g? ok\n"
    c.mov_rax_i32(20);
    c.mov_rdi_i32(1);
    c.lea_rip(0x35, "iovB");
    c.mov_rdx_i32(2);
    c.syscall();

    // exit_group(0)
    c.mov_rax_i32(231);
    c.xor_rdi();
    c.syscall();

    frame(c, d)
}

/// bench guest（PLAN-0.0.3 T1.1）：纯翻译 syscall 吞吐基准。
/// 循环 N 次 getpid(39)（无内存/路径/IO 参与，纯 VEH→dispatch→返回往返），
/// 后 exit_group(0)。host 侧用外部计时（进程含固定 ~10ms 启动开销）：
///   Measure-Command { vela run guest/bench }  →  ns/op ≈ (elapsed - 启动) / N
/// r12 做计数器（callee-saved，syscall 语义不触碰；VEH 只改 rax/rcx/rip/r11）。
fn build_bench() -> Vec<u8> {
    const N: i32 = 2_000_000;
    let mut d = Data::new();
    d.zero("pad", 16); // 双段框架要求非空数据段

    let mut c = Code::new();
    // mov r12, N
    c.e(&[0x49, 0xC7, 0xC4]);
    c.imm32(N);
    // loop_start:
    let loop_start = c.buf.len();
    // mov eax, 39 (getpid)
    c.e(&[0xB8]);
    c.imm32(39);
    // syscall
    c.syscall();
    // dec r12
    c.e(&[0x49, 0xFF, 0xCC]);
    // jnz loop_start（rel32 向后回填：rel = start - end）
    c.e(&[0x0F, 0x85]);
    let rel = loop_start as i32 - (c.buf.len() + 4) as i32;
    c.imm32(rel);

    // exit_group(0)
    c.mov_rax_i32(231);
    c.xor_rdi();
    c.syscall();

    frame(c, d)
}

/// "mmap ?t? ok\n"，?0 = fs:[0x40] 存取往返，?1 = GET_FS 回读 == tls_area。
/// 需要 FSGSBASE；不支持时 fs 基址为 0 → fs 写会崩溃（视为诚实的失败）。
fn build_tls() -> Vec<u8> {
    let mut d = Data::new();
    d.zero("iov", 32); // (mmap, 5) + (msg, 7)——iov[1].base 由 guest 运行时填
    d.sym("msg", b"0t0 ok\n\0");
    d.zero("mmap_ptr", 8);
    d.zero("fs_get_buf", 8);
    d.zero("tls_area", 64);
    d.patch_u64("iov", 8, 5);
    d.patch_u64("iov", 24, 7);

    let mut c = Code::new();

    // iov[1].base = &msg（运行时填）
    c.lea_rip(0x05, "msg");
    c.mov_rip_rax_off("iov", 16);

    // mmap + "mmap " + iov[0].base
    mmap_and_fill(&mut c, "iov");

    // arch_prctl(ARCH_SET_FS, tls_area)
    c.mov_rax_i32(158);
    c.mov_rdi_i32(0x1002);
    c.lea_rip(0x35, "tls_area"); // lea rsi
    c.syscall();

    // 检查A（决定性）：普通寻址往 tls_area+8 写 marker，再从 fs:[8] 读回。
    // 只有 fs 基址恰好等于 tls_area 时才会相等。
    c.mov_dword_rip_i32("tls_area", 8, 0x5A);
    c.mov_rax_fs_off(8); // mov rax, qword fs:[8]
    c.xor_rcx();
    c.cmp_rax_i32(0x5A);
    c.sete_cl();
    c.add_cl_0();
    c.mov_rip_cl("msg", 0);

    // 检查B：GET_FS 回读 == tls_area（验证 runtime 记账）
    // arch_prctl(ARCH_GET_FS, fs_get_buf)
    c.mov_rax_i32(158);
    c.mov_rdi_i32(0x1003);
    c.lea_rip(0x35, "fs_get_buf");
    c.syscall();
    c.mov_rax_rip("fs_get_buf");
    c.lea_rip(0x15, "tls_area"); // lea rdx
    c.xor_rcx();
    c.cmp_rax_rdx();
    c.sete_cl();
    c.add_cl_0();
    c.mov_rip_cl("msg", 2);

    // writev(1, iov, 2) → "mmap ?t? ok\n"
    c.mov_rax_i32(20);
    c.mov_rdi_i32(1);
    c.lea_rip(0x35, "iov");
    c.mov_rdx_i32(2);
    c.syscall();

    // exit_group(0)
    c.mov_rax_i32(231);
    c.xor_rdi();
    c.syscall();

    frame(c, d)
}
