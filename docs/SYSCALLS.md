# Vela syscall 兼容矩阵（0.0.6）

> 状态约定（效仿 Gramine 的诚实标注）：
> - ✅ 完整翻译
> - 🟨 部分实现（限制见备注）
> - ⭕ 诚实 stub（记录后返回固定值，行为可预期）
> - ❌ 未实现（返回 `-ENOSYS`；客户 libc 通常有降级路径）
>
> 未列出的 x86_64 syscall 一律 ❌。

## 已实现

| # | syscall | 状态 | 备注 |
|---|---|---|---|
| 0 | read | ✅ | 管道读端：空且写端开 → EAGAIN（无阻塞调度）、写端关 → EOF |
| 1 | write | ✅ | 管道写端：读端全关 → EPIPE |
| 2 | open | 🟨 | 绝对路径经映射表翻译；相对路径基于 cwd |
| 3 | close | ✅ | |
| 4 | stat | ✅ | ino 为路径哈希（同进程稳定，stat/getdents 一致） |
| 5 | fstat | ✅ | 目录 fd / FIFO（S_IFIFO）支持 |
| 6 | lstat | 🟨 | ≡ stat（无 symlink 语义） |
| 8 | lseek | ✅ | 目录 fd 返回 ESPIPE |
| 9 | mmap | 🟨 | MAP_PRIVATE 匿名 + **文件映射**（fd 背书，COW 语义）；MAP_FIXED 落在已登记 Reserve 内就地覆盖（musl donate 模式）；MAP_SHARED = ENOSYS。文件视图条件：offset/hint 64K 对齐，否则退化为匿名映射 + 读入（EOF 后零填充）。⚠ 旧 Reserve 块内的"就地覆盖"保留原页内容（Linux 为匿名零页）——musl 仅对未写入的 brk 尾页这样做 |
| 10 | mprotect | ✅ | 文件视图区间剥离 WRITE（VirtualProtect RW 会关闭 COW 穿透宿主文件） |
| 11 | munmap | 🟨 | 仅释放完全覆盖的整块（Windows 限制）；FileView 走 UnmapViewOfFile |
| 12 | brk | ✅ | 预映射堆块内移动 |
| 13 | rt_sigaction | ⭕ | 记录后返回 0；信号**投递**未实现（NONGOALS） |
| 14 | rt_sigprocmask | ⭕ | 同上 |
| 17 | pread64 | ✅ | seek→io→seek-back（单线程契约） |
| 18 | pwrite64 | ✅ | 同上 |
| 21 | access | 🟨 | W_OK 按宿主只读位；X_OK 语义简化 |
| 26 | msync | ⭕ | 参数校验后恒成功（MAP_PRIVATE 无回写语义） |
| 28 | madvise | ⭕ | no-op |
| 32 | dup | ✅ | 管道端复制共享缓冲 |
| 33 | dup2 | ✅ | |
| 59 | execve | 🟨 | **进程内重载**（CLI 层编排）：新映像装载成功后卸载旧地址空间、重建堆/栈/auxv；CLOEXEC fd 关闭，其余 fd 跨重载保留。⚠ Windows 上旧 Reserve 块解除登记但不 VirtualFree（含 musl donate NOACCESS 页的块会内核致死），泄漏至进程退出。失败路径返回 -errno，原映像继续 |
| 61 | wait4 | ✅ | **真实等待**（0.0.6）：WaitForSingleObject 阻塞 / WNOHANG 轮询；status 按 Linux 编码（退出码 <128 = WIFEXITED，≥128 = WIFSIGNALED）；孤儿无 init 收养 → -ECHILD；rusage 填零 |
| 74 | fsync | ✅ | stdio/伪设备 no-op |
| 75 | fdatasync | ✅ | |
| 76 | truncate | ❌ | 路径版未实现（ftruncate fd 版可用） |
| 77 | ftruncate | ✅ | File::set_len（截断/扩展） |
| 82 | rename | ✅ | |
| 83 | mkdir | ✅ | |
| 84 | rmdir | ✅ | |
| 87 | unlink | ✅ | |
| 89/267 | readlink/readlinkat | ⭕ | 恒 -ENOENT（vela 无 procfs、无 symlink） |
| 90/92 | chmod/fchmodat | ❌ | 路径版只读位近似未接（fchmod fd 版可用） |
| 91 | fchmod | 🟨 | Windows 只读位近似：mode & 0222 == 0 → 只读，其余位忽略 |
| 93/260 | fchown/fchownat | ⭕ | 校验 fd 后恒 0（Windows 无 per-file 属主） |
| 98 | getrusage | ⭕ | 填零结构（无记账） |
| 99 | sysinfo | 🟨 | uptime 真实（宿主时钟）；内存量固定近似；procs=1 |
| 16 | ioctl | 🟨 | 仅 TIOCGWINSZ（固定 80x25）；其余 ENOTTY（非终端语义） |
| 20 | writev | ✅ | 管道支持（容量内逐 iov 追加） |
| 39 | getpid | ✅ | 真实 Windows pid（0.0.6 起；fork 父子各自不同） |
| 60 | exit | ✅ | 退出前 flush stdio |
| 63 | uname | ✅ | Linux / vela / 6.6.0-vela |
| 72 | fcntl | 🟨 | F_GETFD/F_SETFD/F_GETFL/F_SETFL/F_DUPFD/F_DUPFD_CLOEXEC；其余 EINVAL |
| 79 | getcwd | ✅ | ERANGE 语义 |
| 80 | chdir | 🟨 | 记账式 cwd；宿主侧校验目录存在；`..` 拒绝 |
| 96 | gettimeofday | ✅ | |
| 102/104/107/108 | getuid/getgid/geteuid/getegid | ✅ | `--uid/--gid` 可配，默认 1000 |
| 110 | getppid | ✅ | fork 子进程 = 真实父 pid（0.0.6）；普通启动 = 宿主 pid 派生的稳定值 |
| 158 | arch_prctl | 🟨 | SET_FS 依赖 FSGSBASE；不支持时仅记录（`--soft-tls` 下 fs 访问由 VEH 软件模拟，见 DESIGN.md） |
| 160/161 | getrlimit/setrlimit | ⭕ | RLIM_INFINITY（与 prlimit64 一致） |
| 217 | getdents64 | ✅ | 快照式目录遍历（打开后不感知变化）；`..` 逃逸防护 |
| 218 | set_tid_address | ✅ | 单线程假 pid |
| 228 | clock_gettime | ✅ | REALTIME / MONOTONIC |
| 231 | exit_group | ✅ | |
| 257 | openat | 🟨 | dirfd 支持目录 fd 相对路径（`..` 拒绝）；O_EXCL/O_TRUNC/O_APPEND/O_CLOEXEC |
| 262 | newfstatat | 🟨 | AT_EMPTY_PATH；dirfd 相对路径同 openat |
| 273 | set_robust_list | ⭕ | 记录后返回 0（musl 启动路径） |
| 258 | mkdirat | ✅ | |
| 263 | unlinkat | ✅ | AT_REMOVEDIR 支持 |
| 264 | renameat | ✅ | |
| 269 | faccessat | 🟨 | 同 access |
| 292 | dup3 | ✅ | 仅接受 O_CLOEXEC flag |
| 293 | pipe2 | ✅ | **宿主匿名管道**（0.0.6 下沉）：真实阻塞读写、64 KiB 缓冲、fd 可跨 fork 继承；O_NONBLOCK 无效果（Linux 子集）；fstat = S_IFIFO\|0600 |
| 22 | pipe | ✅ | ≡ pipe2(flags=0)（musl pipe() 降级路径） |
| 56/57/58 | clone/fork/vfork | 🟨 | **用户态 fork**（0.0.6，0.1.0 减重）：仅接受 fork 语义（SIGCHLD / vfork / fork 号）——快照客户地址空间（区间级 inheritable section）+ CONTEXT 传递，子进程 MapViewOfFileEx 回原地址后从 fork 返回点继续；父返回子 pid、子返回 0。0.1.0 起：不可变区域（映像 X/R 段 + 解释器段 + 岛页）section 跨 fork 共享（kind-3），可变区域按 fork 拷贝；mprotect 运行时历史经账本（T3.2）在子进程重放，PROT_NONE 洞（mallocng donate）由拷贝侧跳过。⚠ 线程类 clone（CLONE_VM 等）诚实拒绝（单线程契约）；⚠ 性能非目标（-v 打印 copied/immutable KiB） |
| 280 | utimensat | 🟨 | **0.1.0 新增**：文件时间戳设置（AT_FDCWD 相对 / 绝对路径）；`SetFileTime` 落地。⚠ ctime 无 Windows 对应（不触碰）；`UTIME_NOW` 取当前时钟 |
| 62 | kill | 🟨 | 最小集（0.0.6）：SIGKILL/SIGTERM → TerminateProcess(128+sig)、sig 0 → 探测；其余信号 → ENOSYS（信号**投递**仍 NONGOALS，客户 handler 永不触发） |
| 109/121/111 | setpgid/getpgid/getpgrp | 🟨 | 诚实近似（0.0.6）：pgid=sid=pid（单进程无会话）；setpgid 校验后返回 0 |
| 112/124 | setsid/getsid | 🟨 | 同上：返回 pid |
| 302 | prlimit64 | ⭕ | 上报 RLIM_INFINITY（无资源限制语义） |
| 318 | getrandom | ✅ | 上限 64MiB 防呆 |
| 332 | statx | 🟨 | 128B 布局，mask=STATX_BASIC_STATS；btime 恒 0 |

## 动态链接（0.0.4 新增能力）

- `PT_INTERP` 不再拒载：解析解释器路径，**仅接受 musl**（basename 前缀
  `ld-musl`），其余诚实拒绝（`UnsupportedInterp`）。
- 双映像装载：客户 ELF 与 `ld-musl` 各自装载；`AT_BASE`=解释器 bias、
  `AT_PHDR/AT_ENTRY/AT_EXECFN`=客户侧（与 Linux 内核 auxv 约定一致），
  入口跳解释器 `_dlstart`；重定位全部由 ld-musl 自身完成。
- 验收：`guest/bin/hello-dyn`（zig cc 动态 musl）在 `--soft-tls` 下端到端
  输出问候并干净退出（见 docs/DESIGN.md「动态加载」节）。

## 已知不做（NONGOALS，见 docs/NONGOALS.md）

socket/epoll、clone/futex/线程、信号投递（rt_sigaction 等仅记账，handler
永不触发）、MAP_SHARED 文件映射、glibc 动态链接（非 musl interp 诚实拒绝）、
32 位 / 其他架构、Go 运行时。

## 陷阱与热路径（0.1.0）

- **island trampoline（`--trap=auto` 默认）**：通过校验的 syscall 站点用
  2 字节短跳进附近 RX 岛页，岛内保存现场、切宿主栈、直调 dispatch——
  绕过内核异常往返。校验不过的站点（迁移指令 >3 字节 / 分支目标 /
  rip 相对窗口冲突）整图回退 VEH（混合模式，`island/veh` 计数见 doctor）。
- **UD2 + VEH（后备/真实故障）**：异常处理全程宿主栈（T2.4 red zone
  纪律）；裸 `syscall`（0F 05）#UD 作为漏 patch 点的兜底自愈。
- loader patch 为线性指令走查（最小长度解码器）——0.1.0 前的裸字节
  扫描会误伤指令内部字节（busybox ash makestrspace 现场，
  docs/plans/ash-ud1.md §7）。

## 诊断

- `vela doctor`：FSGSBASE、映射约定、trap 后端、fork 快照/地址空间债说明、guest 产物状态
- `VELA_LOG=1` / `-v`：strace 风格逐 syscall 日志（含 rip，stderr）；
  fork 打印 `copied/immutable KiB`；execve 打印 reserve debt（T4.5/T4.6）
