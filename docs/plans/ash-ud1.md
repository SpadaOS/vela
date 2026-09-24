# ash `sh -c` UD1 陷阱 — 证据与复现（PLAN-0.1.0 T0.3）

> 状态：0.0.6 顺延项的冻结证据。M3（T3.1）开工的门槛材料。
> 结论未定：本文只固化「可复现的现象与数据」，定性见 PLAN-0.1.0 T3.1。

## 1. 现象

CI（windows-latest）上 `busybox sh -c 'echo hello | wc -c'` 在 **fork 之前**
死于非法指令异常；同一 busybox 的 `echo/nproc/true` 与 `fork-test` guest
全部通过。本机（无 msys2/zig musl 目标依赖）不可复现构建，证据全部来自
CI 现场。

## 2. 复现命令（CI 等价）

```powershell
cargo run -p vela-cli --bin vela -- run --soft-tls -v `
  guest/bin/busybox sh -c "echo hello | wc -c"
# 退出码 0xC000001D (STATUS_ILLEGAL_INSTRUCTION)
```

诊断 CI run：GitHub Actions run **35423396772**（commit c713e10，
2026-09-19，"diag(ci): strace busybox sh -c pipeline"）。该 run 在
`sh-trace.log` 尾部完整捕获以下输出（`|| true` 吞掉退出码只为打日志）。

## 3. busybox 构建指纹

| 项 | 值 |
|---|---|
| 版本 | busybox **1.36.1**（build-busybox.sh `BB_VER` 固定） |
| 配置 | allnoconfig + 白名单 applet（含 ASH，job control/历史关；SHELL_HUSH=N、ASH_RANDOM_SUPPORT=N） |
| 工具链 | **zig 0.13.0** `cc -target x86_64-linux-musl -fPIE -pie`（musl 静态） |
| 产物形态 | ELF 64-bit LSB **pie** executable, x86-64, static-pie, **not stripped**, with debug_info |
| 宿主 | windows-latest + msys2 (make/gcc/bzip2)；构建脚本 `tools/build-busybox.sh`（三项 zig/CI 修补见脚本注释） |

指纹稳定性：脚本固定版本与配置，CI 每次现编——字面重复此环境即复现。

## 4. strace 尾部（run 35423396772 原样，节选）

```
[vela] getpid(...)                        [nr=39,  rip=0x400a35f2]
[vela] rt_sigprocmask(0x1, ...)           [nr=14,  rip=0x400972d4]   ← SIG_BLOCK
[vela] rt_sigaction(0x11, ptr, 0x0, 0x8)  [nr=13,  rip=0x40097353]   ← SIGCHLD 装 handler
[vela] geteuid(...)                       [nr=107, rip=0x400a35d0]
[vela] getppid(...)                       [nr=110, rip=0x400a35fa]
[vela] getcwd(...)                        [nr=79,  rip=0x400a3575]
[vela] rt_sigaction(0x2, 0x0, ...)        [nr=13,  rip=0x40097353]   ← SIGINT  恢复默认
[vela] rt_sigaction(0x3, 0x0, ...)        [nr=13,  rip=0x40097353]   ← SIGQUIT 恢复默认
[vela] rt_sigaction(0xf, 0x0, ...)        [nr=13,  rip=0x40097353]   ← SIGPIPE 恢复默认
[vela] ILLEGAL_INSTRUCTION at rip=0x400722cc is NOT a patch point:
       bytes=["67","0f","b9","40","13","48","8b","45","d0",
              "48","89","45","e0","48","83","7d"]
       (execution ran off-script — check fork/execve rip restore)
error: process didn't exit successfully: ... (exit code: 0xc000001d,
STATUS_ILLEGAL_INSTRUCTION)
```

两条独立命令（带/不带 `-v`）均死在**同一固定地址** `0x400722cc`
（PIE + no-ASLR-by-vela，客户映像地址确定 → 地址可比对）。

## 5. 字节解读

```
67 0f b9 40 13   addr32 UD1 + ModRM(0x40, disp8=0x13)
48 8b 45 d0      mov rax, [rbp-0x30]
48 89 45 e0      mov [rbp-0x20], rax
48 83 7d ...     cmp qword [rbp-0x??], imm8
```

- `0f b9` = UD1（LLVM trap 常用 UD2；UD1+ModRM 形态罕见）
- **后续字节是规整的 rbp 帧代码**——要么这是一个真实的编译器陷阱
  指令（unreachable 分支），要么执行流**落进了一条指令的中间**
  （rip 被计算跳转/返回地址带偏）。两种假设都指向「执行流跑偏或
  编译器不可达分支」，不是 vela 主动注入的 UD2 patch 点
  （VEH 已判明 NOT a patch point）。
- 死亡点**在 fork 之前**：整条 trace 无 SYS_FORK/CLONE/sys_119。
  → PLAN-0.0.6 时期「fork 恢复 prot」类假设与证据矛盾，
    PLAN-0.1.0 T3.1 已降级为验证项。

## 6. M3 开工时的定性框架（T3.1，按证据重排）

假设排序（证据在手的优先验证）：

1. **ash/musl 走进编译器 unreachable 分支**（UD1 形态吻合）——
   触发条件可能是某个 stub syscall 返回值/寄存器约定被 ash 的
   断言（musl 的 `a_crash()`/`__unreachable`）捕获。重点核对
   rt_sigaction(0x11 SIGCHLD handler) 与 getppid 之后的执行路径。
2. **执行流落进指令中间**（返回地址/跳转表被带偏）——用 debug_info
   对 `0x400722cc` 反解所属函数即可一锤定音（需 CI 产物或本地
   重建 objdump；`not stripped, with debug_info` 是为此保的）。
3. ~~fork 恢复 prot 错~~ —— 与「死在 fork 前」矛盾，降级为验证项。

工具门槛：本地无法构建该 busybox（无 msys2 + zig musl 目标）；
定性工作需 (a) 在 CI 加产物上传（busybox ELF + sh-trace.log 全量），
或 (b) 本机补 msys2 环境。M3 T3.1 首个动作是前者。
