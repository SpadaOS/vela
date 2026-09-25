# NONGOALS（v0 明确不做，规格 2.2）

0.1.0 起 ash `sh -c` 闭环、岛页热路径、fork 只读段共享、utimensat、
SIGCHLD 记账落地——从本清单移除或收窄；本清单是 "v0 承诺不追求"的
边界，随版本诚实修订。

- **任何非 Windows 宿主上运行客户**（0.1.0 唯一可运行宿主 = Windows
  x86_64；SpadaOS/macOS 只有契约桩，不进验收、不进发布矩阵）
- SpadaOS Host 的真实实现（`spadaos` 只是编译通过的空壳；填实前
  不为它设计 map 语义、不写假时钟/假文件）
- GUI / X11 / Wayland / PulseAudio
- glibc 动态链接（仅 `ld-musl*` 解释器在白名单内；glibc 诚实拒绝）
- **信号投递**：rt_sigaction/rt_sigprocmask 记账后放行，但信号不会真的
  送达，客户注册的 handler 永不触发；kill 仅 SIGKILL/SIGTERM（进程终止）
  与 sig 0 探测；SIGCHLD 仅记账（wait4 完成后置位，不投递 handler）
- Ctrl+C 是控制台进程组近似（杀客户子进程树后默认终止），不是
  SIGINT handler 语义
- **线程**：clone 仅接受 fork 语义（SIGCHLD），CLONE_VM 等线程 flags
  诚实拒绝（单线程契约）
- fork 的快照语义边界：不可变区 section 共享 + 可变区整块拷贝（无脏页
  跟踪）、mprotect 运行时历史按账本重放、HostDir 游标重置、孤儿无 init
  收养（wait4 诚实 -ECHILD）
- MAP_SHARED 文件映射（共享匿名仅服务 fork 快照；`mmap` SHARED 诚实
  ENOSYS）
- Go 程序（运行时自己发 `syscall`，且可能 JIT）
- socket / epoll / inotify / ptrace / mount / cgroup / namespace
- 32 位、x32、i386、ARM、RISC-V
- 完整 `/proc` 或假 Linux 发行版（readlink 恒 -ENOENT 是诚实行为而非缺陷）
- 指令模拟器 / 完整用户态 CPU emulator（可作未来后门，v0 禁止当主路径）
- 性能承诺（性能非目标；岛页热路径与 VEH 往返的实测数字见 docs/bench.md）
- 把 Linux ABI 做进任何内核（包括 SpadaOS 内核）
