# 0.1.4 支持边界

Vela 当前只在 Windows x86_64 运行受支持的 Linux x86_64 PIE guest。以下能力不属于本版本承诺，未实现接口应明确返回错误。

- 非 Windows 可运行 Host、其他 CPU/32 位/x32；LinuxDev 只供逻辑测试，SpadaOS 仍为接口骨架。
- glibc 动态链接、完整 Linux 发行版、完整 /proc、Go/Python/Node 运行时兼容承诺、GUI/X11/Wayland/音频栈。
- 任意指令位置的异步信号抢占、Linux rt_sigframe/ucontext、SA_SIGINFO、realtime signal queue、signalfd、stop/continue/job control；stop/continue/realtime 操作返回 ENOSYS。handler 在 syscall 返回或受支持等待的安全点执行。
- SA_RESTART 仅覆盖无 socket 超时的 socket IO/accept 和 wait4；poll/select/epoll/futex 等返回 EINTR，不提供通用 restart_syscall。
- Ctrl+C 仍是原子控制台事件和子进程树清理近似，不实现 guest SIGINT handler。
- robust futex、线程取消、跨进程 futex、完整 pthread 语义；多线程 fork 返回 EAGAIN，worker 或其他线程存活时 exec 返回 ENOSYS。
- socket/socketpair/epoll fd 经 fork 的跨进程继承；任何此类 fd 存在时 fork/vfork/进程形态 clone 返回 ENOSYS。
- 完整 AF_UNIX 路径 socket、SCM_RIGHTS/ancillary data、未列出的 message flags/socket options、DNS/TLS 的兼容承诺。
- EPOLLET、EPOLLONESHOT、嵌套 epoll；仅 level-triggered，每实例最多 1024 watches。
- MAP_SHARED、fork 脏页增量跟踪；fork 使用不可变段共享和可变区快照，目录游标重置，孤儿无 init 收养。
- 完整 tty、termios、会话/进程组、资源限制、namespace/cgroup、io_uring、inotify、ptrace、mount。
- 安全沙箱和性能承诺。guest 与宿主共享进程权限和网络；只运行可信 ELF。
