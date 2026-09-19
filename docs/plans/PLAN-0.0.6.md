# Vela 0.0.6 计划 — 多进程之门（用户态 fork + wait 族真实化 + busybox shell 解锁）

> 状态：草案 v1（2026-09-19）
> 前置：v0.0.5（tag v0.0.5）已交付 busybox 静态子集、abi 模块化、
> exec-range 原地重注册、宿主管道组合、syscall 广度 +9
> 用户目标：延续大版本节奏；0.0.6 攻克当前能力天花板的**根本约束**——
> 单进程模型

## 0. 版本主题与 Definition of Done

**主题：多进程之门。** 0.0.4 打开动态链接、0.0.5 跑起 busybox，但 Vela
仍是"一个 vela 进程 = 一个 Linux 进程"：客户永远拿不到第二个 pid。
这是当前生态适配的**根本天花板**——shell（ash）的管道与外部命令、
xargs、find -exec、make、一切 fork+exec 形态的软件，全部被它挡住。

0.0.6 在**纯用户态**实现 Linux `fork(2)`：vela spawn 自己的副本
（`vela --internal-fork` 隐藏入口），通过继承的 section 把客户内存
快照与执行上下文传给子进程，子进程重建现场后**从 fork 返回点继续**——
父返回子 pid、子返回 0，Linux 语义完整（不是 vfork 近似）。配套把
pipe2 从进程内环形缓冲**下沉为 Windows 匿名管道**（跨进程可继承的
前提，顺带获得真实阻塞语义），wait4 真实化（WaitForSingleObject），
busybox 解锁 ash shell 与 coreutils 扩容。

**为什么这可行（WSL1 不做的，我们在用户态做）：**

- Linux fork 的本质 = 地址空间副本 + 上下文副本 + fd 表副本。Vela 客户
  地址空间完全由 vela 进程持有且规模受控（映像 ≤ 数 MB + 栈/堆默认
  8+8 MiB），**全量快照 20-30 MB** 通过继承 section 传递毫秒级完成——
  不需要 COW 页表魔法，不需要内核。
- 子进程重建 = 一次"带现场的重载"，与 0.0.4 execve 进程内重载共用
  loader / 栈重建 / auxv / exec-range 重注册全部机制，新增工作集中在
  快照协议与 CONTEXT 注入。
- busybox ash 在无 job control（无 SIGCHLD 真实化、无 TTY 控制）时
  非交互模式（`sh -c`、管道、脚本）不触碰信号投递——与 0.0.5 的
  rt_sigaction 记账 stub 兼容。

**验收口径（全部满足才发版）：**

1. **fork 语义**：新 guest `fork-test`——fork → 子进程 write 管道
   `"child ok"` → 父 wait4 收到退出码 0 并读到消息；getpid 在子进程
   返回不同 pid，getppid 返回父 pid
2. **fork+exec 主路径**：新 guest `fork-exec`——fork → 子 execve 另一
   guest（fd 保留）→ 结果经管道回传父进程（shell 的标准工作形态）
3. **busybox shell**：`vela run guest/bin/busybox sh -c 'echo hello |
   wc -c'` 输出 `6`；`xargs`、`cp`/`mv`/`rm` 组合验收（CI 全部自动化）
4. **不回退**：0.0.5 全部验收（hello/torture/hello-dyn/fs-exec/pipe
   组合/busybox echo·nproc·true）保持全绿
5. **wait4 真实化**：阻塞等待、退出码传递（含 139 崩溃语义）、
   WNOHANG 轮询；孤儿进程诚实返回 -ECHILD
6. **syscall 广度 +N**：`getpgrp/setpgid/setsid/getsid`（ash/ps 类触碰），
   诚实近似逐条标注
7. 常规：测试全绿、fmt/clippy -D warnings、SYSCALLS/DESIGN/NONGOALS/
   README/CHANGELOG 更新、**Release 挂 vela.exe 产物**、tag v0.0.6

## 1. M1 — 进程地基（用户态 fork）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T1.1 | **pipe2 下沉为 Windows 匿名管道** | `GuestFd::PipeRead/PipeWrite` 的进程内环形缓冲换成 `CreatePipe` 句柄（inheritable）；read/write 走 file_ops 真实阻塞 IO；同进程 execve 重载语义不变（句柄仍在 fd 表）。**语义变化**：空管道 read 从"EAGAIN（假非阻塞）"变为真实阻塞——fs-exec/pipe 对回归验证 | fs-exec、pipe-a/pipe-b、hello-dyn 全部回归通过；新单测：跨"模拟 fork"的 pipe 句柄继承 |
| T1.2 | **spawn-self 协议** | CLI trap 层拦截 `SYS_clone`（flags==SIGCHLD，即 fork；线程类 flags 维持拒绝）：构造快照 section（客户映像+堆+栈全量）+ 元数据管道，`CreateProcessW(vela.exe, "--internal-fork …", inheritHandles=TRUE)`；`--internal-fork` 为隐藏入口（--help 不显示，doctor 说明） | 单进程内单测 + 手动 spawn 冒烟；子进程能拿到继承句柄并回连 |
| T1.3 | **快照与元数据协议** | section 内容：映像页（含已写数据段）+ 堆 + 栈全量拷贝；元数据（经继承管道 JSON-免依赖定长结构传递）：CONTEXT 全寄存器、客户 TLS 基址、brk 位置、fd 表（句柄值+类型+offset+flags）、cwd、envp、auxv 关键值、soft-tls 开关。同步屏障：快照写完 → 管道发 ready 帧 | 协议结构体单测（字节布局稳定）；快照往返 round-trip 测试 |
| T1.4 | **子进程重建** | `--internal-fork` 入口：等元数据 → 打开 section → loader 装载同一 ELF 后用快照**覆写**映像页 → 恢复堆/栈 → 重注册 exec-ranges → 按 fd 表重建 GuestFd（继承句柄值不变，直接用）→ arch_prctl 恢复 TLS（FSGSBASE 或 soft-tls 模式与父一致）→ 注入 CONTEXT（Rip=客户 syscall 下一条、Rax=0）→ NtContinue 进客户代码 | fork-test guest：子从 fork 返回点继续执行并输出（不是从 main 重跑） |
| T1.5 | **pid 语义诚实化** | `getpid` = GetCurrentProcessId（0.0.5 是派生假值）；`getppid` = 元数据传递的父 pid；父 fork 返回值 = 子 Windows pid | fork-test 断言：子 getpid ≠ 父 getpid、子 getppid == 父 getpid |

## 2. M2 — wait 族真实化

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T2.1 | **wait4 阻塞等待** | 父进程持有子句柄表（pid → handle 映射，快照元数据同款协议维护）；`WaitForSingleObject` 无限等待；`WNOHANG` 用 0 超时轮询；`WUNTRACED` 诚实忽略 | fork-test：父 wait4 拿到子退出码 0；多子进程逐个回收 |
| T2.2 | **退出码语义** | 客户 `exit(n)` → vela 进程退出码 n（已有）→ `WEXITSTATUS`；崩溃 139 语义保持；`WIFEXITED/WIFSIGNALED` 按 exit code 范围判定 | 单测 + e2e：正常退出/主动崩溃两形态 |
| T2.3 | **孤儿与 rusage** | 孤儿子进程：wait4 诚实 -ECHILD（无 init 收养，文档标注）；rusage 结构填零维持 | 文档 + SYSCALLS 标注更新 |
| T2.4 | **SIGCHLD 记账** | 维持 0.0.5 stub（记录返回 0）；ash 以 job control off 模式运行时不依赖 | busybox sh 验收通过即证明 |

## 3. M3 — 信号最小集（诚实近似）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T3.1 | **kill(2) 有限版** | `kill(pid, SIGKILL/SIGTERM)` → OpenProcess + TerminateProcess（退出码编码信号号）；其余信号 → 诚实 ENOSYS；对自己 pid 的 kill(0) 探测返回 0 | 单测：杀子进程后 wait4 返回 WIFSIGNALED |
| T3.2 | **Ctrl+C 传播** | vela 主进程 SetConsoleCtrlHandler：CTRL_C_EVENT → 转发 TerminateProcess 全部子进程（ctrl 进程组语义近似）；自身仍可被客户 handler？——**不支持**（信号投递仍 NONGOALS），文档写明 | CI 不测（交互）；手动验收记录于 DESIGN |
| T3.3 | **边界文档化** | rt_sigaction 仍记账 stub；客户注册的 handler 永远不会被调用——NONGOALS 与 SYSCALLS 重申；ash 依赖矩阵核对（SIGINT handler 在交互模式才装） | 文档落地 |

## 4. M4 — busybox 解锁（shell + coreutils 扩容）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T4.1 | **构建配置扩容** | 白名单追加：`ASH`（关 job control/历史，NOMMU 特性全关——musl 是 MMU，ash 走 fork 路径）、`CP/MV/RM/MKDIR/RMDIR/HEAD/TAIL/WC/GREP/SLEEP/SEQ/XARGS/TEST/EXPR/SORT/UNIQ/DD/DF/DU/PS`（按 allnoconfig 实际可选集微调）；构建脚本同步更新 | busybox 体积报告；`sh -c` 冒烟通过 |
| T4.2 | **启动缺口排查** | ash 启动 strace：预期新增触碰 `getpgrp`、`ioctl(TCGETS→ENOTTY 已有)`、`fcntl(F_DUPFD_CLOEXEC 已有)`；逐个闭环，诚实 ENOSYS 优先 | `sh -c 'echo hi'` 零致命缺口 |
| T4.3 | **shell 语义验收** | 管道（ash 内部 pipe2+fork+exec+dup2）、重定向（`>`/`>>`/`<`，open 系已有）、变量展开、退出码 `$?`、`&&`/`||` | `sh -c 'echo hello | wc -c'` → `6`；`sh -c 'a=b; echo $a'` → `b`；重定向产物与真实 Linux 一致 |
| T4.4 | **coreutils 组合验收** | `ls /mnt/c/Windows | head -3`、`cp`+`cmp`（busybox cmp 需启用）回读一致、`xargs` 管道、`ps` 最小输出（/proc 缺失下诚实降级——若 ps 不可用则从白名单移除，记录决策） | CI 自动化验收链 ≥6 条 |
| T4.5 | **CI 集成** | busybox 验收步骤扩容（沿用 zig cc 构建通道，注意 0.0.5 的三项修补维持）；新增验收走 `--soft-tls`（CI runner 无 FSGSBASE） | CI 全绿 |

## 5. M5 — syscall 广度 +N（ash 触碰驱动）

| # | syscall | 状态 | 要点 |
|---|---|---|---|
| 111/112 | setpgid/getpgid | 🟨 | 记账式：进程组表（进程树内存态），fork 继承，语义最小化 |
| 110 系 | setsid/getsid | 🟨 | getsid=self pid（无会话概念，诚实近似）；setsid 记账 |
| 96 系 | fcntl 增量 | 🟨 | F_GETOWN/F_SETOWN（返回 0/记账）、F_GETPIPE_SZ/F_SETPIPE_SZ（固定 64K） |
| 66/73 | fstatat64 等 | — | 按实际 strace 补 |
| 334 | rseq | ⭕ | 记账 no-op（glibc/新 musl 启动路径可能触碰） |

最终清单以 T4.2 strace 为准，逐条诚实标注进 SYSCALLS.md。

## 6. M6 — 发布工程与文档

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T6.1 | **Release 挂产物** | 新增 release workflow：tag 触发 release 构建 → 上传 `vela.exe`（release profile，附 SHA256）到 GitHub Release；不含 PDB | Release 页可直接下载运行 hello |
| T6.2 | **bench 基线更新** | guest/bench 补 0.0.5/0.0.6 取样（getpid 纯往返 + fork 往返新基准项）；结论节更新 | docs/bench.md 三版本对照表 |
| T6.3 | **文档五件套** | SYSCALLS（clone/fork/wait4/kill/getpgrp 全量改写）、DESIGN（「用户态 fork」新节：快照协议图）、NONGOALS（信号投递/fork 语义边界重写）、README（能力矩阵+路线+快速开始加 sh -c 示例）、CHANGELOG 0.0.6 | 与代码事实逐条对齐 |
| T6.4 | **版本与发版** | Cargo.toml 0.0.6、tag v0.0.6、Release（验收输出 + vela.exe） | tag+Release 页上线 |

## 7. 决策点与降级路径

1. **快照协议失败**（CI 上 section 大块传递/句柄继承不稳）：降级为
   **vfork-only**——快照仅 CONTEXT+fd 表，子进程限定"只能 execve/_exit"
   （越界 abort 并诚实报错）；此时 ash 不可解锁，M4 降级为纯 coreutils
   扩容（fork-free applet），fork 标注实验特性，版本主题改为
   "shell 之门"照常发版。
2. **ash 启动缺口过深**（strace 出现无法诚实近似的依赖）：降级 hush
   （更小、路径更少）；再不行回到纯 coreutils。
3. **快照性能**（>100ms/次影响体验）：v0.0.6 接受（正确性优先），
   脏页跟踪优化顺延 0.0.7 候选；fork 往返进 bench 观察。
4. **ps/df 等依赖 /proc 的 applet**：不可诚实实现 → 移出白名单，
   决策记录（vela 无 procfs 是既定边界）。

## 8. 诚实边界（发版时写进 NONGOALS/SYSCALLS）

- fork 是**用户态快照**：快照瞬间的内存一致视图，不含并发线程
  （线程类 clone 仍拒绝，单线程契约不变）
- 信号投递仍未实现：kill 仅 SIGKILL/SIGTERM 立即终止；客户注册的
  handler 永不触发；SIGCHLD 记账 stub
- 孤儿进程无 init 收养：wait4 诚实 -ECHILD
- 管道改为真实阻塞：`O_NONBLOCK` 在管道上无效果（Linux 语义子集，
  musl/ash 默认阻塞读写不受影响）
- fork 快照是全量拷贝（20-30 MB/次），性能非目标

## 9. 风险表

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| Windows 句柄继承 + section 协议在 CI 不稳 | 中 | 高（M1 整体） | 决策点 1 降级路径；协议结构体字节布局单测先行 |
| ash 隐藏依赖（信号/终端）超出最小集 | 中 | 中（M4） | T4.2 strace 先行；hush 降级；job control 编译期关闭 |
| 快照竞态（父在子重建前退出） | 低 | 中 | 元数据管道 ready 帧同步屏障（T1.3） |
| pipe2 下沉破坏既有 fs-exec 验收 | 低 | 中 | T1.1 回归先行于一切 fork 工作 |
| CI 时长膨胀（busybox 扩容 + 新 guest） | 低 | 低 | -j1 已必要；白名单按需微调 |
