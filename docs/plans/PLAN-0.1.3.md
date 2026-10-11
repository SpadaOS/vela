# Vela 0.1.3: 应用兼容层与网络运行时

状态：**已发布**。`v0.1.3` 于 2026-10-11 04:35（Asia/Shanghai）发布，tag 对应提交 `56c84bca7e7e9d60e678014c0093566365dbdf94`。

- [GitHub Release](https://github.com/SpadaOS/vela/releases/tag/v0.1.3)：Windows x64 ZIP 与 SHA-256 校验文件已上传。
- [Release workflow 38083876976](https://github.com/SpadaOS/vela/actions/runs/38083876976)：build 与 publish 均通过。

本版本以已发布的 0.1.2 为基线，继续只支持 Windows x86_64。主线是让真实 Linux CLI 具备进程间通信能力：Winsock-backed TCP/UDP、AF_UNIX socketpair、socket-aware poll/select、level-triggered epoll，以及 trap 安全点上的基础信号状态。

已实现的边界包括 `socket`、`socketpair`、`bind`、`listen`、`accept`、`connect`、`sendto`、`recvfrom`、`sendmsg`、`recvmsg`、`shutdown`、socket options 和 epoll 1024-entry cap。LinuxDev/SpadaOS 保持 `Unimplemented`，guest-side crate 不依赖 Windows API。

信号路径支持常用 signal disposition、per-process pending mask、per-thread block mask、`kill`/`tkill`/`tgkill`、`rt_sigreturn` ABI 入口和 `sigaltstack` 验证入口。完整异步 handler frame、realtime signal queue、signalfd、job control 仍延期。

本版本不实现 MAP_SHARED、glibc、io_uring、SCM_RIGHTS、完整 realtime signal 或非 Windows host。默认网络访问使用宿主网络，Vela 不是安全沙箱；验收应使用 loopback。

已通过的发布门禁：fmt、workspace clippy、workspace tests、host source gate、guest 资产与 BusyBox 构建、`scripts/verify.ps1 -RequireBusybox -RequireThreads -RequireSignals -RequireNetwork`、release binary smoke、版本与 ZIP 资产清单检查，以及解压后的 hello/pthread/signal/socket guest smoke。

验收范围：signal guest 覆盖 handler、block/unblock 和 pending；socket guest 覆盖 AF_UNIX socketpair、IPv4 TCP/UDP loopback 和 epoll readiness，均重复运行三次。BusyBox root 验收覆盖 grep/find/tar/gzip；wget/nc 已加入构建白名单，当前脚本没有单独的网络 applet 端到端用例。此发布记录不代表完整 Linux 信号或网络兼容性。
