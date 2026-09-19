# NONGOALS（v0 明确不做，规格 2.2）

v0.0.5 起动态链接（ld-musl）、execve 进程内重载、pipe2 已落地——从本清单
移除；本清单是"v0 承诺不追求"的边界，随版本诚实修订。

- SpadaOS Host 的真实实现（`spadaos` 只是编译通过的空壳）
- GUI / X11 / Wayland / PulseAudio
- glibc 动态链接（仅 `ld-musl*` 解释器在白名单内；glibc 诚实拒绝）
- **信号投递**（rt_sigaction/rt_sigprocmask 记账后放行，但信号不会真的送达）
- 完整 `fork` / `clone`（非线程）；`execve` 仅支持**进程内重载**形态
  （无独立子进程，wait4 恒 -ECHILD）
- Go 程序（运行时自己发 `syscall`，且可能 JIT）
- socket / epoll / inotify / ptrace / mount / cgroup / namespace
- 32 位、x32、i386、ARM、RISC-V
- 完整 `/proc` 或假 Linux 发行版（readlink 恒 -ENOENT 是诚实行为而非缺陷）
- 指令模拟器 / 完整用户态 CPU emulator（可作未来后门，v0 禁止当主路径）
- 性能优化（README 写明性能非目标；~2 µs/syscall 的 VEH 往返见 docs/bench.md）
- 把 Linux ABI 做进任何内核（包括 SpadaOS 内核）
