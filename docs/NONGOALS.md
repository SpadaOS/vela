# NONGOALS（v0 明确不做，规格 2.2）

- SpadaOS Host 的真实实现（`spadaos` 只是编译通过的空壳）
- GUI / X11 / Wayland / PulseAudio
- 动态链接（`ld-musl` / glibc / `PT_INTERP`）
- 完整 `fork`、`clone`（非线程）、`execve`
- Go 程序（运行时自己发 `syscall`，且可能 JIT）
- socket / epoll / inotify / ptrace / mount / cgroup / namespace
- 32 位、x32、i386、ARM、RISC-V
- 完整 `/proc` 或假 Linux 发行版
- 指令模拟器 / 完整用户态 CPU emulator（可作未来后门，v0 禁止当主路径）
- 性能优化（README 写明性能非目标）
- 把 Linux ABI 做进任何内核（包括 SpadaOS 内核）
