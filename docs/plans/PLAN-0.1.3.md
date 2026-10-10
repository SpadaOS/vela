# Vela 0.1.3: 应用兼容层与网络运行时

本版本以已发布的 0.1.2 为基线，继续只支持 Windows x86_64。主线是让真实 Linux CLI 具备进程间通信能力：Winsock-backed TCP/UDP、AF_UNIX socketpair、socket-aware poll/select、level-triggered epoll，以及 trap 安全点上的基础信号状态。

已实现的边界包括 `socket`、`socketpair`、`bind`、`listen`、`accept`、`connect`、`sendto`、`recvfrom`、`sendmsg`、`recvmsg`、`shutdown`、socket options 和 epoll 1024-entry cap。LinuxDev/SpadaOS 保持 `Unimplemented`，guest-side crate 不依赖 Windows API。

信号路径支持常用 signal disposition、per-process pending mask、per-thread block mask、`kill`/`tkill`/`tgkill`、`rt_sigreturn` ABI 入口和 `sigaltstack` 验证入口。完整异步 handler frame、realtime signal queue、signalfd、job control 仍延期。

本版本不实现 MAP_SHARED、glibc、io_uring、SCM_RIGHTS、完整 realtime signal 或非 Windows host。默认网络访问使用宿主网络，Vela 不是安全沙箱；验收应使用 loopback。

收口门禁：fmt、workspace clippy、workspace tests、source gate、hello/musl/fork/pipe/poll/select/pthread 回归、signal/socket guest、BusyBox grep/find/tar/gzip/wget/nc 和 release ZIP smoke。发布 tag 由 CI 通过后另行创建。
