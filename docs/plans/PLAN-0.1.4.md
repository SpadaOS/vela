# Vela 0.1.4：网络 CLI 与信号等待加固

状态：**实现已落地；本地完整质量门禁及源码目录外 ZIP 验收通过**。远程质量与合并状态以实现 PR #4 的检查记录为准。开发分支为 `codex/0.1.4`，workspace 版本为 `0.1.4`。0.1.4 尚未创建标签或公开发布；原始审计基线为 `f5a8378239a6ee5d2dcf6ba01d92c8dafdad17e2`（0.1.3）。

## 实施验收状态（2026-10-17）

| 里程碑 | 当前证据 |
| --- | --- |
| M0 | gzip/gunzip 字节比对、tar 提取、坏压缩流/失败 producer 检查，guest/server deadline 与输出留存 |
| M1 | ProcessShared 实际持有 trap 状态；GuestContext 绑定线程；owned IO 与权限验证；socket/pipe 背压及 fd 别名回归 |
| M2 | IPv6、connect/SO_ERROR、accept4、options/timeouts、UDP 消息/截断、EFAULT、SIGPIPE、exec/CLOEXEC guest |
| M3 | level-triggered epoll、稳定资源身份、公平性、并发 pipe ADD/DEL、非法 flags/targets 拒绝 |
| M4 | 定向信号、独立 mask/frame/altstack、FXSAVE/SSE 与 flags、临时 mask 等待、socket restart、wait4/SIGCHLD、fork/exec；island 汇编测试确实建岛 |
| M5 | 固定 Zig 0.13.0 重建；auto/VEH 重复 guest，wget/nc 实际 loopback 二进制传输和错误路径 |
| M6 | 共用 quality/build/acceptance/package 脚本，PR/main/manual/release 接线；ZIP/SHA-256 与目录外同套验收；PR CI 结果见 #4 |

本地报告见 `docs/validation/0.1.4.md`。当前实现使用一个进程状态 guard 配合线程上下文适配器；有界非阻塞尝试在 guard 内完成，等待在 guard 外完成。SIGCHLD 使用安全点轮询 child handle。信号 FP 现场覆盖 FXSAVE/x87/SSE；未验证更广泛的 XSAVE/AVX 扩展，不把该能力记为已支持。

以下保留原始审计与退出标准，历史基线结果不替代当前质量证据。

## 版本目标

让 0.1.3 已有的网络与信号能力形成真实 CLI 可依赖的闭环：BusyBox `wget` 能通过本机 HTTP 下载并校验文件，`nc` 能完成双向 TCP 传输和 EOF 退出，阻塞网络等待能够让其他 guest 线程继续运行，并在支持的信号到来后正确返回。

继续只支持 Windows x86_64，保留 soft-TLS、pthread/futex、单线程 fork/exec、root 路径映射和既有 BusyBox 能力。本版本的主线是修正已有契约、并发与验收缺口；新增 syscall 仅限这条主线确实需要的部分。

## 基线核查与优先级

以下是当前代码阅读和本地验收得到的规划依据，不表示每一项均已有独立运行时复现。

| 优先级 | 当前证据 | 影响与 0.1.4 要求 |
| --- | --- | --- |
| P0 | `scripts/verify.ps1:45` 只看 `cat \| gzip \| wc` 的最终退出码；本地运行 gzip 报错、wc 输出 `0`，脚本仍输出 `all checks passed` | 先修正验收假阳性，压缩、解压和 tar 必须校验实际内容；现有 CI 绿色不替代结果检查 |
| P0 | `crates/vela-runtime/src/syscalls/socket.rs:398` 从 `a[4]/a[5]` 读取 setsockopt 值/长度，Linux 参数位置应为 `a[3]/a[4]` | 常用 socket option 可能在 ABI 边界直接失败；增加参数布局与地址错误回归 |
| P0 | `crates/vela-cli/src/main.rs:1017` 附近的 socket/epoll 等等待仍持有 TRAP_SERIAL；被排除的 read/write 等路径继续使用同一可变 GuestState；`HostSocket` 多个读写函数在状态锁内执行阻塞 IO | 存在全局等待阻塞、可变状态并发访问与全双工锁竞争风险；先落实真实共享状态、句柄快照和锁释放协议 |
| P1 | `sys_accept` 未接收 guest sockaddr/addrlen；`recvfrom` 忽略写回错误；sendmsg/recvmsg 未完整处理地址、控制数据与输出字段 | 补齐地址、长度、错误与资源回滚，明确拒绝尚不支持的参数 |
| P1 | `crates/vela-sys/src/socket.rs` 的 readiness 使用 clone + nonblocking peek，流写就绪直接返回 POLLOUT；SO_ERROR 恒 0，超时 option 返回成功但不生效 | 需要宿主真实就绪、连接完成/失败状态与实际超时，不能以占位成功表示支持 |
| P1 | `crates/vela-cli/src/main.rs:1157` 只在 syscall 返回 0 时检查 pending；signal mask/frame 仍位于共享 GuestProcess；self SIGTERM 绕过 handler | 修正投递时机、线程定向、mask/frame 归属和不可屏蔽信号；保留 trap 安全点边界 |
| P1 | `crates/vela-cli/src/fork.rs:528` 的 fd 序列化跳过 socket 与 epoll | 本版本不实现网络 fd 跨 fork；必须在创建子进程前明确拒绝，禁止 fork 成功后悄悄丢 fd |
| P1 | signal guest 只测自发 SIGUSR1 与 mask；socket guest 只测简单 socketpair、IPv4 TCP/UDP、单个 epoll；wget/nc 没有 E2E | 增加反例、并发、关闭、超时、真实 applet 与包内验收 |

本地基线复核：fmt、workspace/all-targets Clippy 通过；`cargo test --workspace` 共 103 个测试通过；`verify.ps1 -RequireBusybox -RequireThreads -RequireSignals -RequireNetwork` 返回 0，pthread/signal/socket 均重复三次通过。BusyBox 复用现有本地产物，未在这次规划中重建；gzip 的漏检单独列为 P0，不能据此宣称所有 applet 行为通过。

## M0：先让验收能发现错误

- 修正 gzip 入口探测/参数或 pipe IO 的实际根因；不能只隐藏 stderr 或硬编码成功文本。
- gzip 必须产出非空且有效的 gzip 数据，解压结果与输入逐字节一致；tar 创建后再列出、提取并比对文件内容。
- shell 管道不得只依赖末端命令退出码：分别检查关键 applet 结果，并增加“中间命令失败”的门禁反例。
- 所有可能等待的 guest/宿主 server 设置进程级 deadline；超时终止本用例进程树，保留 stdout/stderr 与阶段标记，try/finally 清理临时目录和监听端口。
- 用动态端口和 server ready 握手启动 loopback 服务，禁止固定端口与固定 sleep 代替就绪确认。
- 在修正当前缺陷前加入会失败的 syscall/guest 用例，再由对应实现使其通过；超时、空输出、伪成功都必须失败。

完成标准：故意破坏 gzip、下载内容或 server 响应后门禁失败；恢复后得到可核验的正确字节。

## M1：把线程、fd 与阻塞 IO 接入真实共享模型

以现有 `ProcessShared`、`GuestThread`、`GuestContext` 为起点，将其接入实际 trap/dispatch，避免仅有类型定义而调用路径继续共享可变 GuestProcess。

- 进程共享：fd 表、映像/内存登记、cwd/fs、signal disposition、进程 pending 与线程注册表。
- 线程独立：guest tid、TLS、signal mask、定向 pending、signal frame 栈、alternate-stack 与当前等待状态。统一 main/worker 的 guest tid，不能混用 Windows 原生 tid 与 clone 返回的合成 tid。
- 不通过同一个裸指针向多个正在执行的线程构造重叠的 `&mut GuestState`；console callback 只发布事件，不遍历 RefCell 子进程表。
- 阻塞操作分为“查找并保活资源、释放共享锁、执行或等待、重新检查状态并写回”四步；禁止跨阻塞调用持有 fd/进程/epoll/socket 状态锁。
- socket 的数据通道与短期元数据锁分离，同一连接的读与写可以并行；一次 MSG_DONTWAIT 或 readiness 查询不修改共享的 O_NONBLOCK。
- fd 表项区分每个 descriptor 的 `FD_CLOEXEC` 和 open-file-description 共享的状态/资源标识。dup 后 O_NONBLOCK 一致；关闭一个别名不能关闭仍被引用的连接。
- 检查 guest 缓冲的生命周期与访问权限：不能在另一个线程可能 munmap/protect 的同时保留裸切片跨阻塞等待。发送采用有上限的 owned buffer；接收先取 owned buffer，再重新校验并写回，地址空间变更与短期复制同步。
- socketpair 使用有界队列和明确的读/写半关闭状态；容量满时按阻塞或 EAGAIN 路径处理，避免无限 VecDeque 增长；等待循环重查谓词，正确处理虚假唤醒、零长度 IO、最后引用释放与唤醒。
- 保持多线程 fork 返回 EAGAIN、worker exec 返回 ENOSYS；exec 不得在其他线程仍执行旧映像时释放地址空间。0.1.4 明确拒绝任何仍有其他 guest 线程存活的 exec。

完成标准：双向 socket IO、并行 accept/connect、fd close/dup 与等待、线程独立 signal mask 均在 bounded deadline 内结束；现有 pthread/futex/TLS 回归保持通过。

## M2：修正 socket ABI、状态机与错误语义

### 参数与输出

- 修正 setsockopt 参数索引，区分 integer 与 Linux x86_64 `timeval` option；校验 optlen、负值、溢出与 guest 地址。
- accept/accept4 写回 peer sockaddr 和实际 addrlen；支持 NULL 地址、不足容量截断与实际长度反馈；accepted socket 的 NONBLOCK/CLOEXEC 以 accept4 参数为准。
- recvfrom、getsockname/getpeername、getsockopt 的输出写回错误返回 EFAULT；先校验可写区域，避免无效输出地址消费数据或泄漏新 fd。
- sendmsg/recvmsg 支持有界 iovec、UDP msg_name、msg_namelen/msg_flags 输出；检查总长度溢出与分配上限。ancillary data 明确拒绝；不能忽略 SCM_RIGHTS 后仍返回成功。
- 最小 flags 集为 MSG_DONTWAIT、MSG_PEEK、MSG_NOSIGNAL，以及接收侧所需的 MSG_TRUNC；超出实现的 flags 明确返回错误。
- socketpair/accept/dup 分配后失败必须回滚；fd 用尽、坏地址、非法类型和 option 不得留下可观察资源泄漏。

### 真实 socket 状态

- socket 创建即持有宿主 socket；bind 与 listen 分离，connect 保留显式绑定的本地地址，backlog 按宿主能力落实。
- 非阻塞 connect 进入 Connecting，返回 EINPROGRESS；readiness 与 SO_ERROR 共同报告成功或失败；支持 EALREADY/EISCONN/ECONNREFUSED 等路径，失败后状态可解释。
- SO_ERROR 读取并清除真实 pending socket error；SO_REUSEADDR、TCP_NODELAY 在正确生命周期生效并可查询。
- SO_RCVTIMEO/SO_SNDTIMEO 实际影响对应 IO；0 为无限等待，非零值使用单调时钟 deadline，超时不伪装成 EOF。SO_SNDTIMEO 不作为 accept 或 poll/epoll 的超时。
- Windows WSA 错误集中转换为 Linux errno；不能直接把 WSA 数值透传给 guest。
- TCP、UDP 与 socketpair 的 shutdown、EOF、EPIPE/SIGPIPE、MSG_NOSIGNAL、零长度 datagram、短读短写均有独立用例。
- socket/epoll fd 跨 exec 保留非 CLOEXEC 资源，清理 CLOEXEC。对仍持有任何 socket/socketpair/epoll fd 的 fork/vfork/进程型 clone，在分配子进程和快照前返回 ENOSYS，并给出 -v 诊断；不静默跳过 fd。跨 fork 的真正共享继承单独设计到后续版本。

宿主策略：复用已存在的 socket2 依赖并限于 Windows socket 后端；Winsock 特有调用只进入 `vela-sys::windows`。不新增异步运行时；LinuxDev/SpadaOS 继续诚实返回未实现。

## M3：真实 readiness 与 level-triggered epoll

- Windows TCP/UDP 就绪采用 WSAPoll 等真实后端；移除通过 clone + 改 nonblocking + peek 推测就绪、或无条件报告 POLLOUT 的实现。
- poll/select/ppoll/pselect6/epoll_wait/epoll_pwait 共用 readiness 与 deadline 处理；混合普通文件、stdio、pipe、socketpair、socket 时保持已有约定，并记录 stdio 仍有的近似。
- 覆盖 listener 尚无连接、非阻塞连接成功/失败、接收缓冲数据、发送背压、半关闭、EOF、ERR/HUP 与无效 fd。
- 不直接把 Linux epoll bits 强转成宿主 poll bits；显式转换，ERR/HUP 按约定反馈，EPOLLRDHUP 需明确实现后才能声明支持。
- epoll watch 同时记录注册 fd 与稳定资源身份；dup/close/dup2 后按 open-file-description 生命周期处理，fd 号复用不能让旧 watch 指向新对象。
- 支持别名 fd 的独立 ADD、MOD/DEL、maxevents 截断与轮转公平性；支持同线程等待期间其他线程 ADD/DEL/close 的唤醒与重新取快照。
- 普通文件等不支持的 epoll target 返回明确错误；嵌套 epoll 本版本明确拒绝；避免忽略后返回成功。
- 保留 1024 watch 上限；EPOLLET/EPOLLONESHOT 继续 EINVAL。

完成标准：非阻塞连接失败不被误报为成功；readiness 查询不改变随后 IO 的阻塞模式；多个持续就绪 fd 在多次 wait 中不会长期饥饿。

## M4：trap 安全点信号与可中断等待

不引入任意 guest 指令位置的异步抢占，先把安全点和等待中的信号语义做正确。

- 每次准备返回 guest 时检查 pending，不再限定 syscall 返回值为 0；优先保留已经完成的 IO 字节数，再按契约投递 handler。
- process-directed pending 与 thread-directed pending 分开；tkill/tgkill 使用注册的 guest tid 查找目标，退出线程返回 ESRCH；kill(getpid(), SIGTERM) 可被捕获，SIGKILL 永不可捕获或屏蔽。
- 支持信号列表与默认动作做成明确表。未实现的 stop/continue、realtime 等行为必须拒绝或明确标注，不能以任意进程退出替代所有默认动作。
- handler 建栈保留 x86_64 red zone、满足栈对齐，验证 guest handler/restorer 与栈的权限；失败恢复原 mask 与 frame 状态，不吞掉 pending。
- sigreturn 恢复整数寄存器、flags、mask，以及信号 handler 可能破坏的浮点/SIMD 现场；Windows 上下文细节留在 HostTrap 边界，runtime 不依赖 CONTEXT。
- 实际落实 SA_ONSTACK 的每线程备用栈切换；对已支持的 SA_RESTORER/SA_NODEFER/SA_RESETHAND 做行为测试。SA_SIGINFO 与完整 Linux rt_sigframe/ucontext 布局不纳入本版本，不能静默接受后按一参数 handler 运行。
- ppoll/pselect6/epoll_pwait 的“发布等待 + 临时换 mask + 检查 pending”须有原子协议，等待结束恢复原 mask；以可复现的竞态用例验证不会丢唤醒。
- 本版本可中断等待限定为 socket accept/connect/recv/send、socketpair、poll/select/epoll、futex、wait4。未完成的操作返回 EINTR；已完成的部分 IO 返回字节数。等待时不持有共享状态锁。
- SA_RESTART 仅落实明确列出的阻塞 socket IO/accept 与 wait4；poll/select/epoll 等仍返回 EINTR。带 socket timeout 的等待不自动 restart；重试使用原 deadline；不承诺通用 restart_syscall。
- 子进程退出通知经 Host/CLI watcher 发布 SIGCHLD pending，wait4 回收与通知状态保持一致；handler 仍在安全点执行，不在 watcher 线程直接调用 guest。
- fork 继承 disposition 与调用线程 mask，子进程 pending 清空；exec 重置 caught handler、保留 ignored disposition/调用线程 mask 与尚未消费的 pending，清除备用栈和旧 frame。用独立 guest 覆盖这些生命周期。
- Windows Ctrl+C 暂保留既有进程树清理语义；callback 必须线程安全，但本版本不宣称控制台 SIGINT handler 或完整 job control。

完成标准：一个线程等待 socket/futex/epoll 时，另一个线程能定向发信号；目标 handler 恰好执行，mask 不串线程，返回后原 IO 结果、TLS、栈与寄存器保持正确。

## M5：真实 CLI 与反例验收

| 资产/用例 | 必须覆盖的结果 |
| --- | --- |
| 扩展 `guest/src/socket-test.c` | IPv4/IPv6 loopback、connect + SO_ERROR、accept4 地址/flags、UDP 地址与零长度消息、socket options/timeouts、MSG_PEEK/NOSIGNAL、shutdown/EOF、dup/exec、错误地址与泄漏 |
| 新增 `guest/src/network-concurrency-test.c` | pthread 双向 IO、满缓冲背压、并行 accept/connect、关闭别名/复用 fd、socketpair 容量与唤醒；阻塞期间另一个线程继续推进 |
| 新增 `guest/src/epoll-test.c` | socket/pipe/socketpair 混合、ADD/MOD/DEL、maxevents 公平性、dup/close/复用身份、其他线程变更与等待唤醒、无效 target/ET/ONESHOT 拒绝 |
| 扩展 `guest/src/signal-test.c` | 非零 syscall 返回时投递、SIGTERM handler、SIGKILL/mask、SIGPIPE/NOSIGNAL、red zone、SIMD/寄存器恢复、alternate-stack、fork/exec 继承/重置 |
| 新增 `guest/src/signal-wait-test.c` | 每线程 mask、tkill/tgkill 错误目标、poll/futex/socket/wait4 的 EINTR、选定 SA_RESTART、临时 mask 竞争与 SIGCHLD |
| BusyBox wget | 宿主临时 HTTP 服务；数字 loopback 地址；用 --root 将文件写入 guest `/data`；下载非空二进制并校验 SHA-256；404 和服务提前关闭必须失败 |
| BusyBox nc | 宿主临时 TCP 服务；数字 loopback 地址；二进制双向传输、对端 EOF 与进程退出；不以 nc 监听/执行子进程为验收目标 |
| BusyBox tar/gzip | 独立验证生成物、解包/解压与原文一致；刻意注入失败后门禁失败 |

新增 guest 使用固定 zig 0.13.0 + musl 在 CI 构建。核心 signal/socket/epoll 路径同时覆盖 `--trap=auto` 与 `--trap=veh`，Windows CI 使用 `--soft-tls`；有硬件 FS 能力时补做本地 smoke，不把单台机器结果当通用性能结论。

测试数据不依赖公网、DNS、TLS 或宿主发行版。IPv6 在 runner 上应可用；若环境确实不可用，必须输出明确原因并记为未完成，不能将跳过计入“IPv6 已通过”。每个并发用例使用握手而非睡眠猜测，按三次重复运行检查生命周期，压力用例为有界次数并设置总 deadline。

## M6：文档、CI 与发布

- 实施阶段统一 workspace/crate/CLI 版本为 0.1.4；Changelog 在顶部开 0.1.4 开发条目，不能在规划阶段宣称功能完成。
- README、SYSCALLS、HOST、DESIGN、NONGOALS、guest README 和本计划同步支持边界：网络 fd 跨 fork 拒绝、signal 安全点、支持的 flags、restart 范围和真实 applet 验收。
- 修正“零第三方依赖”表述与当前 socket2 的矛盾：区分用户无需安装额外运行时与源码已有依赖；不为更新文案移除必要后端。
- doctor 从运行位置/可执行文件邻近目录查找包内 guest，不再只依赖构建时 CARGO_MANIFEST_DIR；报告后端能力和诊断方法，独立 doctor 进程不伪称能读取另一个运行实例的实时计数。
- 将 CI 与 release 的必要质量步骤复用到统一脚本，提供可在分支上显式运行的完整 quality 入口；PR 和 main 必须执行相同核心门禁。
- guest/server harness 独立于源码路径，可对指定 vela.exe 与 guest 目录执行；CI 与 ZIP 解压后复用，确保测的是包内二进制而非 cargo 重新构建的源码版本。
- release workflow 校验 tag 与 workspace 版本，禁止硬编码 0.1.3；包含全部新增 guest、文档、ZIP 与 SHA-256。解压到源码目录外，执行 version/doctor、guest、BusyBox wget/nc 与 root 输出校验。
- 生成本地可检查的验证报告：commit、工具链、用例结果、重试/跳过、产物路径/大小/hash；网络 applet 缺测不得记为通过。

必须通过：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
.\scripts\verify.ps1 -RequireBusybox -RequireThreads -RequireSignals -RequireNetwork
```

此外，完整门禁必须要求所有新增 guest/真实网络 applet，包含 source gate、旧版 hello/torture/static+dynamic musl/file-io/fs-exec/fork/pipe/poll/select、pthread/TLS/futex、root 与解压包 smoke。若需要新增脚本开关，CI/release 必须显式启用，不能 optional skip 后依然发布。

本地 Rust 检查如缺 cl.exe/link.exe，先加载现有 VS2022 vcvars64.bat 或 vcvars32.bat，再诊断环境问题。

## 开发顺序与退出条件

1. M0：修正验收假阳性，建立最小失败用例。
2. M1：接通共享/线程状态和资源生命周期；并发与地址空间访问先于可中断信号。
3. M2、M3：修复 ABI 与后端、统一 readiness 和 epoll 身份。
4. M4：在已可唤醒的等待协议上完成 signal mask/pending、frame 与 restart。
5. M5：完成真实 applet、反例、竞态与三次重复验收；发现缺口回到对应实现。
6. M6：文档、完整 CI、本地产物和解压包验收收口；开单个实现 PR 到 main。

所有 P0、承诺的 P1 与发布硬门禁都是 0.1.4 退出条件。遇到架构阻碍应明确调整计划与文档，不能保留返回成功的 stub 或将缺测替换为绿色状态。实现 PR 的 CI 通过并合并后，再按用户当次发布授权推送 `v0.1.4`；不得在分支质量尚未通过时先 tag。

## 本版本不包含

MAP_SHARED、fork 脏页跟踪/性能优化、网络 fd/epoll 跨 fork 的真正共享继承、完整 Linux rt_sigframe/ucontext 与 SA_SIGINFO、任意指令异步抢占、realtime signal queue、signalfd、通用 restart_syscall、job control/控制台 SIGINT handler、robust futex/线程取消、EPOLLET/EPOLLONESHOT/嵌套 epoll、完整 AF_UNIX 路径 socket、SCM_RIGHTS、DNS/TLS 的兼容承诺、glibc/Go/Python/Node、GUI、非 Windows 宿主与其他架构。

## 实施时的接口核对来源

宿主和 guest 布局的行为回归以 Linux x86_64 ABI 与官方接口文档为准；下面的资料用于实施时逐项核对，不替代 Windows guest 实测。

- Linux man-pages：`accept(2)`、`setsockopt(2)`、`socket(7)`、`epoll(7)`、`signal(7)`、`sigaction(2)`、`sigaltstack(2)`、`poll(2)`、`select(2)`。
- Microsoft Learn：Winsock `WSAPoll`、`ioctlsocket/FIONBIO`、`getsockopt/SO_ERROR`、socket error codes。
- Rust 标准库：`TcpStream::try_clone` 的共享选项语义；socket2 已锁定版本的 socket 生命周期和选项 API。
