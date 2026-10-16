# Guest 资产与验收（0.1.4）

`guest/src` 是 Linux x86_64 PIE 测试源码。使用固定 Zig 0.13.0；不把本机较新 Zig 编译成功当作固定工具链验证。

```powershell
cargo build --workspace --release
.\scripts\build-guests.ps1
```

脚本生成 hello/torture/tls/bench，并编译静态 musl、文件/pipe/fork/exec、pthread、signal、socket/epoll 和并发 guest。`hello-dyn` 与 `ld-musl-x86_64.so.1` 是仓库提供的动态程序和 musl 1.2.5 loader fixture，不由该脚本重建。构建及验收都核对二者 SHA-256 和程序的 `PT_INTERP`；固定 Zig 0.13.0 的内置 musl 即使传入 `-dynamic` 仍会生成静态 PIE，不能代替动态测试。验收在 auto/VEH/island 三种模式中核对动态加载日志和输出。

BusyBox 1.36.1 源码 SHA-256 固定在 `tools/build-busybox.sh`。构建要求 MSYS2 make/gcc/bzip2/diffutils/curl，脚本核对 Zig 0.13.0，修复 ash NULL 指针运算及 gzip/解压的未对齐访问，保留 sanitizer。

```powershell
bash tools/build-busybox.sh
.\scripts\quality.ps1 -BuildBusybox -Package
```

## 关键 guest

| 文件 | 验收 |
| --- | --- |
| pthread-test | 多线程 TLS/futex/clear-tid |
| network-concurrency-test | 1 MiB socketpair/原生 pipe 背压、双向回复、阻塞 accept、dup 与 fork 边界 |
| socket-edge-test | IPv6、connect/SO_ERROR、accept4、timeouts/options、UDP sendmsg/recvmsg/TRUNC、坏地址不消费数据、SIGPIPE/NOSIGNAL、CLOEXEC |
| epoll-test | 公平性、dup/close/fd 复用、并发 ADD/DEL、pipe、拒绝不支持的 flags/targets |
| signal-wait-test | 每线程 mask、tkill/tgkill、非零 syscall、altstack、SIMD、ppoll/pselect/epoll/futex/socket 中断、socket SA_RESTART |
| signal-lifecycle-test | fork dispositions/mask/pending、wait4 EINTR、回收前 SIGCHLD、exec reset/mask/pending |
| island-test | 必须实际安装 island；寄存器/flags/SIMD/red zone、fork、并发 clone 迁移 cell |

## 同一二进制验收入口

```powershell
python scripts/acceptance.py --exe target/release/vela.exe --guests guest/bin --busybox --threads --signals --network
```

脚本只依赖 Python 标准库。网络服务使用 loopback 动态端口，guest/server 有 deadline 和清理；原始输出和 JSON/hash 保存到报告目录。线程/信号/网络 guest 在 auto 与 VEH 各重复三次；island-test 还检查实际安装的 island 数量，防止静默回退被当作 island 通过。

gzip 压缩/解压逐字节校验、tar 真正提取、损坏输入/失败 producer 必须失败；wget 实际下载二进制并核对 SHA-256，404/截断响应必须失败；nc 核对双向二进制和 EOF。软 TLS 是诊断/CI 路径，无硬件 FS 性能结论。

`scripts/package.py` 复制这些 guest 和验收脚本到发布 ZIP，在源码目录之外解压，再执行同一套验收；不调用 cargo 重建替换包内二进制。
