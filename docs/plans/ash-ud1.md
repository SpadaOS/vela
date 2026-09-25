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

## 7. M3 终局（0.1.0）：UD1 之后的三处根因与收口

UD1 修复后 CI 的 ash 走得更远但仍崩，且呈两种形态。最终全部定性并修复
（诊断产物：CI artifact `ash-ud1` = busybox ELF + 全量 -v trace；
复算工具 = readelf/addr2line/objdump 直接作用于 CI 真实二进制）：

### 形态 A：guest AV rip=0x40055adf addr=0x40106ac8（三命令同址，与 fork 无关）

- CI binary 符号化：rip = `makestrspace`（ash.c:1798）；addr 在映像跨度
  之外（映像止于 ~0xa8000）。
- 反汇编真相：`48 8d 05 e9 0f 05 00` = `lea rax,[rip+0x50fe9]`，其
  **disp32 里嵌着 `0F 05`**。loader 的 syscall patch 是裸字节扫描，把
  disp32 的 `0F 05` 改写成 UD2 → disp 变 `e9 0f 0b 00`（+0x60000）→
  lea 目标 = `ash_ptr_to_globals_memstack`（0xa6ac8）+ 0x60000 =
  **0x40106ac8** —— 与现场 rax 逐位吻合。
- 结论：**不是 ash UB，是 vela patcher 损坏无辜指令**。0.0.6 规格里
  「误报概率极低，v0 接受」的欠账在 busybox ash 这类大代码体上必然引爆。
- 修复：`patch_syscalls` 改线性指令走查（内置最小 x86-64 长度解码器，
  SIB/disp/imm 与 0F 两字节表齐备，截断指令按不可解码处理）；只在指令
  起点上认 syscall。不可解码区诚实漏 patch，由陷阱后端对裸 `syscall`
  #UD 的兜底模拟自愈。回归测试锁定 lea disp32 现场。

### 形态 B：host AV addr=堆基址（`echo hello | wc -c`，首个 fork 中）

- -v trace：`mmap(0x181e4b30000, 0x1000, PROT=0, MAP_FIXED)` —— musl
  mallocng 的 donate 把**堆首一页**转为 NOACCESS；fork 快照对堆整块
  memcpy 读到 NOACCESS 页 → ntdll memmove AV。
- 修复：sys_mmap 的保护位收敛记入 mprotect 账本（T3.2）；fork 三处
  快照拷贝改 `copy_readable`——按账本跳过 PROT_NONE 洞（section 零页
  兜底），子进程由账本重放恢复 NOACCESS。

### 形态 C：第二个管道子进程静默退出 1（map_section_at EINVAL）

- `internal_fork_main` 诊断化后定位：fork #2 复用 imm 缓存时，fork #1
  收尾把父进程自己的缓存 section 句柄 close 了（且缓存命中路径从不
  set_inherit）→ 子进程拿死句柄。
- 修复：kind 3（imm 缓存）section 不随单次 fork 关闭；缓存命中路径
  set_inherit 幂等补齐。
- 同场加映：`--internal-fork` 分支 `cmd_run(&args[2..])` 没剥 `run`
  token，rest[0]="run" 落进位置参数分支吞掉全部选项——子进程 fs 表/
  soft_tls 配置静默丢失。修复为 do_fork 构造命令行时 skip(2)。
  此前 `echo $(echo ok)` 假绿纯因 echo 是 NOFORK applet 走进程内路径。

### busybox 侧配套

`FEATURE_PREFER_APPLETS` + `FEATURE_SH_STANDALONE` +
`BUSYBOX_EXEC_PATH="/bin/busybox"`：applet 经内建表解析（宿主 PATH 是
Windows 形态，guest 无 /bin 文件树）；CI 以 `--map /bin=guest/bin` 供给
重入文件。本地与 CI 等价验收命令见 `.github/workflows/ci.yml`
ash shell acceptance 步骤。

**收口**：4 条验收（管道 `wc -c`、命令替换、变量展开、`--root` 重定向
+ cat）本地全绿；UD1（§5）+ 上述三处根因构成本次 ash 闭环的完整缺陷链。
