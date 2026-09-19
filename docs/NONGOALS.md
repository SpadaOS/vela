# NONGOALS（v0 明确不做，规格 2.2）

v0.0.6 起用户态 fork、wait4、kill 最小集落地——从本清单移除；本清单是
"v0 承诺不追求"的边界，随版本诚实修订。

- SpadaOS Host 的真实实现（`spadaos` 只是编译通过的空壳）
- GUI / X11 / Wayland / PulseAudio
- glibc 动态链接（仅 `ld-musl*` 解释器在白名单内；glibc 诚实拒绝）
- **信号投递**：rt_sigaction/rt_sigprocmask 记账后放行，但信号不会真的
  送达，客户注册的 handler 永不触发；kill 仅 SIGKILL/SIGTERM（进程终止）
  与 sig 0 探测；无 SIGCHLD 投递（ash 以 job control off 模式运行）
- **线程**：clone 仅接受 fork 语义（SIGCHLD），CLONE_VM 等线程 flags
  诚实拒绝（单线程契约）
- fork 的快照语义边界：全量拷贝、mprotect 运行时历史不传递、HostDir
  游标重置、孤儿无 init 收养（wait4 诚实 -ECHILD）
- Go 程序（运行时自己发 `syscall`，且可能 JIT）
- socket / epoll / inotify / ptrace / mount / cgroup / namespace
- 32 位、x32、i386、ARM、RISC-V
- 完整 `/proc` 或假 Linux 发行版（readlink 恒 -ENOENT 是诚实行为而非缺陷）
- 指令模拟器 / 完整用户态 CPU emulator（可作未来后门，v0 禁止当主路径）
- 性能优化（README 写明性能非目标；~2 µs/syscall 的 VEH 往返见 docs/bench.md）
- 把 Linux ABI 做进任何内核（包括 SpadaOS 内核）
