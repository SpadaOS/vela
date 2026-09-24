# ash `sh -c` UD1 陷阱 — 已解决（PLAN-0.1.0 T3.1 收口）

> 状态：**已定性并修复**（0.1.0 M3）。0.0.6 顺延项收口。
> 修复：tools/build-busybox.sh sed 注入 `jq != NULL` 守卫（e929af4）。

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

## 5. 字节解读（定性结论）

```
0000000000072220 <growjobtab>:        ← busybox ash job 表扩容
   7222b: movl 0x34837(%rip),%eax    ← eax = njobs（首次 = 0）
   72231: imulq $0x28,%rax           ← size = njobs * 40（= 0）
   72253: callq xrealloc             ← ckrealloc(NULL, 160)
   72264: subq %rcx,%rax             ← offset = jp - jq（jq==NULL，UB！）
   72270: je → offset==0 跳过        ← 首次 offset≠0 → 进入 relocation
   722a0: ud1l 0x13(%eax),%eax       ← 检查 (jq!=0)&&(jq+len!=0)&&(无溢出)
                                      全部失败 → unreachable → ud1
```

**根因（T3.1 定性）**：首次扩容时 `jobtab == NULL`，源码
`offset = (char *)jp - (char *)jq` 非零进入 relocation 块，
`(char *)jq + l` 为 **NULL 指针算术 = C UB**。zig cc/LLVM 利用 UB
把该路径标记 unreachable 并发射 `ud1`；gcc 不利用此 UB，故 Linux
构建从未触发。假设 3（fork prot）确认排除，假设 1 的机制成立但
责任在 busybox 源码 UB × LLVM 的组合，非 vela 侧缺陷。

**修复**：`tools/build-busybox.sh` sed 注入 `if (offset && jq != NULL)`
守卫——`jq == NULL` 时无指针可重定位，跳过 relocation 块（语义等价：
njobs == 0 时循环体零次）。grep 断言补丁生效。

## 6. 定性框架的验证记录
