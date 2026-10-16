# Host 契约（0.1.4）

`vela-sys::Host` 是 runtime 与宿主之间的边界，由 HostMem、HostFileOps、HostTime、HostTls、HostTrap 和 HostProc 组成。Windows x86_64 是唯一可运行宿主；LinuxDev 用于逻辑测试，SpadaOS 保持 Unimplemented。runtime、loader、fs 不访问 Windows API。

## 状态与等待

`ProcessShared<GuestState>` 的一个 mutex guard 串行化地址空间、fd、信号 disposition 和子进程表变更。`GuestContext::enter` 在 guard 内绑定注册的 GuestThread，保存/恢复其 TLS、mask、signal frame 与 altstack。

HostSocket 创建时立即拥有原生 socket，始终使用 OS 非阻塞模式；逻辑 O_NONBLOCK、连接状态和超时由独立短锁保护。一次 syscall 只做有界尝试，CLI 在释放进程 guard 后等待再尝试。Linux flags 不临时修改共享的 OS blocking 模式。管道也使用非阻塞原生尝试；fork 元数据通道单独保持阻塞协议。

发送前复制有界 guest 数据；接收进入 owned buffer，再验证权限并写回。guest 切片不跨越锁释放或等待。映射和保护位变更由同一 guard 串行化；read/write 检查映射、溢出、ELF 段及最新 mmap/mprotect 权限。

## 契约组

| 组 | 责任 |
| --- | --- |
| HostMem | map/protect/unmap、私有文件视图、decommit；Windows reserve 仅整块释放 |
| HostFileOps | 文件/目录/stdio/pipe、终端探测、poll、socket 及 options |
| HostTime | 单调/实时时钟、随机字节 |
| HostTls/HostProc | guest tid、原生线程、clear-tid、futex、进程句柄和子进程生命周期 |
| HostTrap | 进入 guest、安装 trap、代码范围、TLS 模拟、FP 保存恢复、fork 上下文 |

## Windows 后端

- socket2 封装 Winsock socket，WSAPoll 使用显式 Linux/Winsock 位转换；连接失败补充 SO_ERROR 查询，WSA 错误转换为 Linux errno。
- socketpair 是 64 KiB 有界队列，两端分别维护 read/write shutdown；最后一个 Arc 引用关闭资源。dup 共享 open-file-description flags，CLOEXEC 独立。
- epoll 是 runtime 的 level-triggered watch 表，记录注册 fd 和稳定资源身份，最后别名关闭后清理 watch，轮转 maxevents。
- futex WAIT/WAKE 注册等待者并有界重试，支持定向信号中断，退出 clear-tid 唤醒；注册在返回时删除。Host 的 WaitOnAddress 接口仍保留。
- Native guest thread 使用 CreateThread/ExitThread；安全点轮询已结束线程句柄后释放每线程 trap scratch 与句柄。
- island/异常路径各线程独立保存寄存器、flags、512-byte FXSAVE 状态和宿主栈；clone 续接迁移 cell，fork 合成完整需要的控制/整数/浮点现场。
- SIGCHLD 在安全点轮询原生 child handle 时置 pending；handler 在 guest 安全点执行，wait4 回收句柄。Ctrl+C callback 只发布原子事件。

## 边界

普通磁盘文件和重载/快照工作仍在状态 guard 内执行；网络、pipe、poll/select/epoll、futex、wait4 等可等待路径采用有界尝试。标准输入的阻塞和控制台交互不提供完整 Linux tty/job-control 语义。

单线程 fork 支持既有文件/pipe 快照；包含任何 socket/socketpair/epoll fd 时，创建子进程前返回 ENOSYS。多线程 fork 返回 EAGAIN；exec 必须为唯一存活 guest 线程且由主线程发起。

发布包运行无需 Rust、Zig 或额外网络运行时；源码构建仍需要 Cargo 依赖。doctor 的实时计数只属于 doctor 自己，运行中的 guest 数据通过 `run -v` 观测；guest 资产先从可执行文件邻近目录查找，再查当前工作目录。
