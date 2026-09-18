# Vela syscall 兼容矩阵（0.0.2）

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
| 0 | read | ✅ | |
| 1 | write | ✅ | |
| 2 | open | 🟨 | 绝对路径经映射表翻译；相对路径基于 cwd |
| 3 | close | ✅ | |
| 4 | stat | ✅ | ino 为路径哈希（同进程稳定，stat/getdents 一致） |
| 5 | fstat | ✅ | 目录 fd 支持 |
| 6 | lstat | 🟨 | ≡ stat（无 symlink 语义） |
| 8 | lseek | ✅ | 目录 fd 返回 ESPIPE |
| 9 | mmap | 🟨 | 仅 MAP_PRIVATE\|ANONYMOUS；文件映射未实现 |
| 10 | mprotect | ✅ | |
| 11 | munmap | 🟨 | 仅释放完全覆盖的整块（Windows VirtualFree 限制） |
| 12 | brk | ✅ | 预映射堆块内移动 |
| 13 | rt_sigaction | ⭕ | 记录后返回 0；信号**投递**未实现（NONGOALS） |
| 14 | rt_sigprocmask | ⭕ | 同上 |
| 17 | pread64 | ✅ | seek→io→seek-back（单线程契约） |
| 18 | pwrite64 | ✅ | 同上 |
| 21 | access | 🟨 | W_OK 按宿主只读位；X_OK 语义简化 |
| 28 | madvise | ⭕ | no-op |
| 32 | dup | ✅ | |
| 33 | dup2 | ✅ | |
| 74 | fsync | ✅ | stdio/伪设备 no-op |
| 75 | fdatasync | ✅ | |
| 82 | rename | ✅ | |
| 83 | mkdir | ✅ | |
| 84 | rmdir | ✅ | |
| 87 | unlink | ✅ | |
| 98 | getrusage | ⭕ | 填零结构（无记账） |
| 16 | ioctl | 🟨 | 仅 TIOCGWINSZ（固定 80x25）；其余 ENOTTY（非终端语义） |
| 20 | writev | ✅ | |
| 39 | getpid | ✅ | 固定假 pid |
| 60 | exit | ✅ | 退出前 flush stdio |
| 63 | uname | ✅ | Linux / vela / 6.6.0-vela |
| 72 | fcntl | 🟨 | F_GETFD/F_SETFD/F_GETFL/F_SETFL/F_DUPFD/F_DUPFD_CLOEXEC；其余 EINVAL |
| 79 | getcwd | ✅ | ERANGE 语义 |
| 80 | chdir | 🟨 | 记账式 cwd；宿主侧校验目录存在；`..` 拒绝 |
| 96 | gettimeofday | ✅ | |
| 102/104/107/108 | getuid/getgid/geteuid/getegid | ✅ | `--uid/--gid` 可配，默认 1000 |
| 158 | arch_prctl | 🟨 | SET_FS 依赖 FSGSBASE；不支持时仅记录并返回 0（客户 TLS 不可用，见 DESIGN.md） |
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
| 302 | prlimit64 | ⭕ | 上报 RLIM_INFINITY（无资源限制语义） |
| 318 | getrandom | ✅ | 上限 64MiB 防呆 |
| 332 | statx | 🟨 | 128B 布局，mask=STATX_BASIC_STATS；btime 恒 0 |

## 已知不做（NONGOALS，见 docs/NONGOALS.md）

socket/epoll、clone/futex/线程、信号投递（rt_sigaction 等当前 ENOSYS）、execve/fork、
文件 mmap、动态链接支持（PT_INTERP 拒载）、32 位 / 其他架构、Go 运行时。

## 诊断

- `vela doctor`：报告 FSGSBASE、映射约定、guest 产物状态
- `VELA_LOG=1` / `-v`：strace 风格逐 syscall 日志（stderr）
