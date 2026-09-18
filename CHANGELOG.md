# Changelog

本项目的所有显著变更记录于此（Keep a Changelog 格式）。

## [0.0.3] - 2026-09-19

主题：性能、广度、SpadaOS 就绪（计划见 docs/plans/PLAN-0.0.3.md）。

### Added

- **syscall 矩阵扩容（+16 号，共 ~50）**：
  - 文件写路径：`mkdir`/`mkdirat`/`rmdir`/`unlink`/`unlinkat`/`rename`/`renameat`
  - `access`/`faccessat`（W_OK 按宿主只读位）
  - 定位读写 `pread64`/`pwrite64`（单线程 seek→io→seek-back 契约）+ `fsync`/`fdatasync`
  - fd 复制：`dup`/`dup2`/`dup3` + fcntl `F_DUPFD`/`F_DUPFD_CLOEXEC`（Host::dup_file）
  - `statx`（128B 完整布局，STATX_BASIC_STATS）
  - musl/busybox 启动兜底：`rt_sigaction`/`rt_sigprocmask`/`madvise`/`getrusage`/`prlimit64` 诚实 stub
  - `clock_gettime` 支持 CLOCK_MONOTONIC_RAW / BOOTTIME
- **性能基准设施**：`vela-mkguest bench` 变体（2M 次纯翻译 getpid 循环）+
  `docs/bench.md` 数据档案
- **SpadaOS 就绪**：`Host` 按内核能力拆为五组 supertrait
  （`HostMem`/`HostFileOps`/`HostTime`/`HostTls` + thread/futex 生命周期），
  SpadaOS 实现者可逐组填实；HOST.md 重写为五组契约与能力映射表
- **专业度**：workspace lints 统一（`missing_safety_doc` 按 HOST.md 组级
  SAFETY 约定放行）；CI 前置 `cargo fmt --check` 与 `clippy -D warnings`
  （全仓已清零）；crate 全部挂 `[lints] workspace = true`
- guest 预编译产物归位 `guest/bin/`（源码与产物分离）

### Changed

- **性能结论（bench 驱动，docs/bench.md）**：纯翻译 syscall 往返 ~2 µs，
  瓶颈在 VEH 内核异常往返的固有成本；exec_ranges 提前退出与热路径去分配
  的收益在噪音内如实记录，dispatch 函数表因"不可测量"按计划规则放弃
- getdents64 每条 dirent 从堆分配改为 280B 栈缓冲；FsMap::translate 常规
  路径零中间分配
- CI 生成 guest 增加 bench 变体

### Fixed

- `FsMap::translate` 对反斜杠开头的 Windows 风格路径误拒（归一顺序）

## [0.0.2] - 2026-09-19

主题：从 demo 到可用的运行时 —— 真实 musl C 程序 + 文件 IO 成为
一等公民，路径映射通用化，工程地基打牢（计划见 docs/plans/PLAN-0.0.2.md）。

### Added

- **文件 syscall 全链路**：`stat`/`fstat`/`lstat`/`newfstatat`（Linux struct
  stat 144B 布局）、`getdents64`（快照式目录遍历）、`getcwd`/`chdir`、
  `getuid`/`geteuid`/`getgid`/`getegid`
- **路径映射表**：`vela-fs` 从硬编码 `/mnt/c → C:\` 升级为最长前缀匹配的
  `FsMap`；新 CLI 选项 `--root <dir>`（挂任意宿主目录为客户根）与可重复的
  `--map guest=host`；默认保留 legacy 映射
- **进程环境**：envp 默认继承宿主环境（`--env K=V` 覆盖 / `K=` 删除）；
  `openat` 支持目录 fd 相对路径；`O_EXCL`/`O_TRUNC`/`O_APPEND`/`O_CLOEXEC`
  语义补全；`fcntl` 最小集（F_GETFD/F_SETFD/F_GETFL/F_SETFL）
- **ioctl stub**：`TIOCGWINSZ` 返回固定 80x25（终端探测用），其余保持诚实
  ENOTTY
- **CLI**：`vela doctor` 环境自检（FSGSBASE / 路径映射 / guest 产物）；
  `--uid/--gid`、`--stack-mb/--heap-mb`（护栏 1-512 / 1-1024）
- **可观测性**：`VELA_LOG=1` 输出 strace 风格 `name(args...) = ret` 日志
- **验收 guest**：`guest/file-io`（musl C，open/write/lseek/read/fstat/stat/
  fcntl/getdents64/getcwd 全链路，zig cc 交叉编译）
- `docs/SYSCALLS.md` 兼容性矩阵（效仿 Gramine 按条诚实标注）
- CI 现场用 `vela-mkhello`/`vela-mkguest` 生成 guest，移除对预编译产物的依赖

### Changed

- `HostError::Other` 载荷约定为 Linux errno：Windows 原始码经
  `os_to_errno` 翻译，`GetLastError` 在 VEH/random 失败处捕获——错误码
  不再丢失（原 `Other(0)`）
- `MemRegistry` 从线性扫描升级为 `BTreeMap` 区间账本（O(log n)）；
  exec-range 表满时响亮警告而非静默丢弃
- 客户段内 AV：完整诊断后以 `128+SIGSEGV=139` 规范化退出（替代不可控的
  second-chance 原始崩溃码）
- `read_cstr` 按页分块扫描替代逐字节 trap 检查
- 堆初始化失败从 warn-继续改为 fatal

### Fixed

- stable 工具链缺 cargo/rustc 组件时 rustup shim 误报的问题（重装修复；
  并发 rustup 操作同一工具链会损坏清单——教训记入项目记忆）

### 已知限制（沿 NONGOALS）

- TLS 依赖程序（musl/glibc）仍需 CPU+OS 的 FSGSBASE；缺失环境（典型
  Hyper-V/云 VM）下集成测试自动跳过
- 线程/futex/socket/信号投递/动态链接/文件 mmap 维持不做（见
  docs/NONGOALS.md）

## [0.0.1] - 初始版本

- 静态 PIE ELF 加载 + syscall patch（0F 05 → 0F 0B）+ VEH 翻译
- TLS trampoline（wrfsbase，需 FSGSBASE）
- guest：hello（汇编）/ torture / tls / hello-musl
- Windows 主宿主完整实现；linux_dev 逻辑测试壳；SpadaOS 空壳
