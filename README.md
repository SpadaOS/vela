# Vela

在 Windows x86_64 用户态运行 Linux x86_64 PIE ELF。Vela 装载 ELF、改写 syscall 站点，并通过宿主接口翻译受支持的 Linux ABI。

当前已发布版本为 **0.1.3**；本分支开发 **0.1.4**，尚未创建发布标签。实施和验收范围见 [0.1.4 计划](docs/plans/PLAN-0.1.4.md)。

Vela 直接在宿主进程和网络中运行 guest，**不是安全沙箱**。仅运行可信程序，安全边界见 [SECURITY.md](SECURITY.md)。

## 运行

Windows x64 发布包包含单个 `vela.exe`、guest 示例和验收脚本。运行 Vela 无需安装 Rust、Zig 或额外网络运行时。

```powershell
.\vela.exe --version
.\vela.exe doctor
.\vela.exe run guest/bin/hello
.\vela.exe run --soft-tls guest/bin/hello-musl
.\vela.exe run --soft-tls guest/bin/busybox echo hello
```

硬件 FSGSBASE 可用时可以运行使用 FS 的 guest；云 VM、VBS 等环境可用 `--soft-tls` 诊断和验收，该模式没有性能承诺。

```powershell
.\vela.exe run --soft-tls --root C:/vela-root guest/bin/busybox sh -c 'echo hello > /data/hello && cat /data/hello'
.\vela.exe run --soft-tls --root C:/vela-root guest/bin/busybox wget -O /data/file http://127.0.0.1:8080/file
.\vela.exe run --soft-tls guest/bin/busybox nc 127.0.0.1 9000
```

先创建 root 中的 `/data`。无 `--root` 时保留 `/mnt/c` 到 `C:\` 的兼容映射；提供 root 时只访问 root，除非通过 `--map` 增加映射。root 是路径映射约定，不提供安全隔离。参数详见 `vela --help`。

## 0.1.4 范围

| 能力 | 支持范围 |
| --- | --- |
| 装载 | 静态 PIE、musl 动态 PIE；包含解释器示例；拒绝 glibc 解释器 |
| 文件和进程 | 文件、目录、pipe、poll/select、单线程快照 fork、exec、wait4、root 路径映射 |
| 线程 | pthread 形态 clone、guest tid、每线程 TLS、futex WAIT/WAKE；等待时释放共享状态锁 |
| 网络 | Windows socket2/Winsock IPv4/IPv6 TCP/UDP；有界本地 socketpair；非阻塞 connect、SO_ERROR、超时、半关闭 |
| 消息 | accept4 地址/flags、sendmsg/recvmsg 的有界 iovec 和 UDP 地址；PEEK/DONTWAIT/NOSIGNAL/TRUNC 子集 |
| epoll | level-triggered、每实例 1024 watches、dup/close/fd 复用身份、maxevents 轮转；拒绝 ET/ONESHOT/嵌套 |
| 信号 | trap 安全点、每线程 mask/frame/altstack、tkill/tgkill、SIMD/flags 恢复、等待中 EINTR、有限 SA_RESTART、SIGCHLD |
| CLI 验收 | BusyBox gzip 解压逐字节校验、tar 提取、wget 实际 HTTP/hash/错误响应、nc 双向 TCP/EOF |

任何 socket/socketpair/epoll fd 存在时，fork 返回 ENOSYS；多线程 fork 返回 EAGAIN。worker exec 或其他 guest 线程仍存活时 exec 返回 ENOSYS。信号不在任意 guest 指令位置抢占，SIGINFO/realtime/job control 等限制见 [NONGOALS](docs/NONGOALS.md) 和 [SYSCALLS](docs/SYSCALLS.md)。

## 构建与质量门禁

构建 Vela 需要 Rust stable 和 Windows MSVC 工具链；Cargo 获取锁定依赖，其中 socket2 提供原生 socket 接口。构建 guest/BusyBox 另需固定 **Zig 0.13.0** 和 MSYS2 的 make/gcc/bzip2/diffutils/curl。

```powershell
cargo build --workspace
.\scripts\quality.ps1 -BuildBusybox -Package
```

`quality.ps1` 统一执行 fmt、Clippy、workspace 测试（含宿主源码隔离门禁）、release 构建、guest 重建、完整验收和可选 ZIP。PR、main、分支手动 CI 与 release 使用相同入口。

```powershell
# 指定现有二进制和 guest 目录；不通过 cargo 替换待测程序。
python scripts/acceptance.py --exe target/release/vela.exe --guests guest/bin --busybox --threads --signals --network
```

每个 guest 有进程级 deadline，原始 stdout/stderr、命令、退出码和二进制 hash 保存到 `release/validation`。`scripts/package.py` 打包 ZIP 与 SHA-256，解压到源码目录之外，用包内程序执行同一完整验收；证据在 `release/package-validation` 和 `release/package.json`。

## 文档

- [宿主接口](docs/HOST.md)、[设计](docs/DESIGN.md)、[syscall 矩阵](docs/SYSCALLS.md)
- [guest 构建与验收](guest/README.md)、[版本记录](CHANGELOG.md)、[贡献](CONTRIBUTING.md)
- [支持边界](docs/NONGOALS.md)、[性能观测](docs/bench.md)、[许可证](LICENSE)
