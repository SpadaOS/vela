# Changelog

本项目的所有显著变更记录于此（Keep a Changelog 格式）。

## [0.1.0] - unreleased

主题：Windows 一等运行时（计划见 docs/plans/PLAN-0.1.0.md）。

- 岛页 syscall 热路径（VEH 降为后备）、陷阱走宿主栈、red zone 纪律
- fork：映像只读段共享、快照体积/地址空间债可观测、mprotect 账本恢复
- **ash 最小 `sh -c` 闭环达成**（CI 硬门禁）：`echo hello | wc -c` /
  `echo $(echo ok)` / `a=b; echo $a` / `--root` 下重定向 + cat 全部通过。
  过程中三处根因修复：
  1. loader syscall patch 裸字节扫描 → 线性指令走查（最小 x86-64 长度
     解码器）。裸扫描把 `lea` rel32 位移里的 `0F 05` 误 patch 成 UD2，
     破坏 ash `makestrspace` 的全局指针装载（CI 0x40055adf/0x40106ac8
     精确复算）；漏 patch 点由裸 `syscall` #UD 异常兜底自愈
  2. fork 快照拷贝跳过 mprotect 账本中 PROT_NONE 子区间（musl mallocng
     的 donate 把堆首页转 NOACCESS，整块 memcpy 读到即宿主 AV）；
     sys_mmap 的保护位收敛入账本
  3. fork 子进程命令行重放剥掉 `run` token（此前吞掉全部选项，
     子进程 fs 表/软 TLS 配置静默丢失）；imm 缓存 section 不随
     单次 fork 关闭（跨 fork 复用句柄）；`internal_fork_main` 静默
     失败点全部补诊断日志
- busybox 构建：`FEATURE_PREFER_APPLETS`/`FEATURE_SH_STANDALONE` +
  `BUSYBOX_EXEC_PATH=/bin/busybox`（CI `--map /bin` 供给），applet 经
  内建表解析，不依赖宿主 PATH
- `utimensat`；SIGCHLD 记账（不投递）
- Host 增 Trap/Proc 桩；Windows 为唯一实现；runtime 去 Windows API
- dispatch 拆分、doctor 2.0、Ctrl+C 进程树
- 唯一支持宿主：Windows。SpadaOS/macOS 仅预留

## [0.0.6] - 2026-09-19

主题：多进程之门 —— 用户态 fork + wait 族真实化 + busybox shell 解锁
（计划见 docs/plans/PLAN-0.0.6.md）。

### Added

- **用户态 fork（M1）**：`fork(2)` 完整语义——拦截 `SYS_FORK/CLONE
  (SIGCHLD)` 后 spawn vela 自身（`--internal-fork` 隐藏入口），按客户地址
  区间建 inheritable section 快照，子进程 `MapViewOfFileEx` 回**原地址**
  （指针一致性），CONTEXT 注入后从 fork 返回点继续；父返回子 pid、
  子返回 0。快照协议免依赖定长编码，CONTEXT 全量（0x4D0）传递
- **wait4 真实化（M2）**：`WaitForSingleObject` 阻塞 / WNOHANG 轮询；
  Linux status 编码（WIFEXITED/WIFSIGNALED）；孤儿诚实 -ECHILD
- **kill 最小集（M3）**：SIGKILL/SIGTERM → TerminateProcess(128+sig)、
  sig 0 探测；其余信号诚实 ENOSYS（投递仍 NONGOALS）
- **busybox 白名单扩容（M4）**：ash + coreutils 全家族（cp/mv/rm/grep/
  xargs/sort 等 20+ applet）入构建白名单；⚠ ash 的 `sh -c` 在 CI 发现
  执行流跑到编译器 UD1 陷阱（fork 路径深层问题，strace 证据存档），
  **实验性**，验收顺延 0.0.7
- **进程组/会话近似（M5）**：getpgrp/getpgid/setsid/getsid（pgid=sid=pid）、
  setpgid；utimensat 诚实 ENOSYS
- **发布工程（M6）**：release workflow——tag 触发 release 构建并上传
  `vela.exe`（zip + SHA256）到 GitHub Release

### Changed

- **pipe2 下沉为 Windows 匿名管道**：fd 可跨 fork 继承（子进程同值句柄）；
  真实阻塞读写取代进程内环形缓冲的假 EAGAIN；EOF（写端全关）/
  EPIPE（读端全关）由 OS 语义维持；fstat = S_IFIFO|0600
- **getpid/getppid 诚实化**：getpid = 真实 Windows pid（fork 父子不同）；
  getppid = fork 传递的父 pid（普通启动维持派生值）
- pipe(22) 补齐（musl pipe() 降级到 pipe2）

### Fixed

- fork 子进程执行页 DEP 执行 AV——section 需 PAGE_EXECUTE_READWRITE 且
  MapViewOfFileEx desiredAccess 含 FILE_MAP_EXECUTE
- NtContinue 注入失败返回——CONTEXT 需 16 字节对齐（repr(align(16))）
  且 context_flags 必须显式置 CONTEXT_ALL（VEH 传入的 flags 带异常请求位）

## [0.0.5] - 2026-09-19

主题：真实软件之门 —— busybox 静态子集压力测试 + 工程地基加固
（计划见 docs/plans/PLAN-0.0.5.md）。

### Added

- **busybox 静态子集（M3）**：`tools/build-busybox.sh`（msys2 make +
  zig cc musl 静态 PIE），applet 白名单 echo/ls/cat/true/false/nproc/
  env/printf；CI 现场构建并验收 echo/nproc/true
- **管道组合（M2）**：`pipe-a`/`pipe-b` 验收 guest——
  `vela run pipe-a | vela run pipe-b`（PowerShell 宿主管道）端到端
  输出 `pipe-b ok: 29 bytes, 3 lines`；stdin 直通验证（GuestFd::StdIn
  经 file_ops 真实读取）
- **syscall 广度（M4，+9）**：
  - `fchmod`（Windows 只读位近似：mode & 0222 == 0 → 只读）
  - `ftruncate`（File::set_len，截断/扩展）
  - `fchown`/`fchownat`（校验 fd 后 0——无 per-file 属主）
  - `readlink`/`readlinkat`（恒 -ENOENT：无 procfs、无 symlink）
  - `sysinfo`（uptime 真实、内存固定近似、procs=1）
  - `getrlimit`/`setrlimit`（RLIM_INFINITY）
- **soft-tls 形态回归资产（M5）**：decode_fs_mov 表驱动测试
  （REX.W/R/B × 8b/89 × mod 0/1/2 × SIB × disp 宽度，10 组合向量 + 负例）

### Changed

- **exec-range 原地重注册（M1 T1.1）**：`replace_guest_exec_ranges`
  前缀覆盖 + 尾部清零，execve 重载不再受 32 静态槽累积限制
- **abi 模块化（M1 T1.2）**：vela-abi 拆 10 个子模块，`pub use` 全量
  重导出保持 API 兼容
- **mmap carve 清零（M1 T1.4）**：Reserve 内 MAP_FIXED 覆盖显式清零，
  对齐 Linux "替换 = 匿名零页" 语义
- **syscall 名表完备性测试（M1 T1.3）**：dispatch 全部号必须有可读名字

### Fixed

- CI `version_and_help` 硬编码版本号在 0.0.4 升版后失败——改为
  `CARGO_PKG_VERSION` 动态断言

## [0.0.4] - 2026-09-19

主题：动态程序之门 —— 文件映射 mmap、动态链接、execve 重载、软 TLS
（计划见 docs/plans/PLAN-0.0.4.md）。

### Added

- **mmap 文件映射（M1）**：`HostMem::map_file/unmap_view`（Windows 用
  `CreateFileMappingW` + `MapViewOfFileEx`，可写视图走 `PAGE_WRITECOPY`
  COW，写入永不回写宿主文件）；`mmap(9)` 支持 MAP_PRIVATE + fd，MAP_FIXED
  落在已登记 Reserve 内就地覆盖（musl ldso 的 PROT_NONE 预留 carve 模式），
  非对齐/非固定地址退化为匿名映射 + 读入（EOF 后零填充）；`MemRegistry`
  登记项带类型（Reserve/FileView），`munmap` 按类型选释放原语；
  `mprotect` 对文件视图剥离 WRITE 位（防止 VirtualProtect 关闭 COW）；
  `msync(26)` 校验后 no-op（MAP_PRIVATE 无回写）
- **动态链接（M2）**：loader 解锁 `PT_INTERP`（白名单 `ld-musl*`，其余
  诚实拒绝）；双映像装载（客户 ELF + 解释器），`AT_BASE`=解释器 bias、
  `AT_PHDR/AT_ENTRY/AT_EXECFN`=客户侧（Linux 内核 auxv 约定），入口跳
  `_dlstart`，重定位全部交给 ld-musl；CLI `--interp` 选项 + 解析链
  （显式 > fs 翻译 > guest ELF 同目录回退）；验收 guest
  `guest/bin/hello-dyn`（zig cc 动态 musl）+ `ld-musl-x86_64.so.1`
  （musl 1.2.5 源码构建，见 guest/README.md）
- **execve 进程内重载（M3）**：`execve(59)` 由 CLI 层编排——新映像装载
  成功后卸载旧地址空间、重建堆/栈/auxv、重注册 exec ranges、改写
  rip/rsp；失败返回 -errno 原映像继续；路径解析支持 POSIX 绝对/cwd 相对/
  宿主风格 argv[0]；解释器解析复用运行时链
- **pipe2(293) + fd 跨 execve**：进程内环形缓冲 fd 对（64 KiB）；读端
  EOF/EAGAIN、写端 EPIPE；`fstat` = S_IFIFO；dup 共享缓冲；
  `close_cloexec` 按 FD_CLOEXEC 记账关闭，其余 fd 跨重载保留
- **wait 族（M3）**：`wait4(61)` 恒 -ECHILD（无 fork，诚实）；
  `getppid(110)` 返回宿主 pid 派生的稳定值
- **软 TLS（M4，实验）**：`--soft-tls` 开关——FSGSBASE 缺失环境下 VEH
  对客户段内 fs 前缀 mov 做软件模拟（ModRM/SIB 解码覆盖 musl 发射的
  全部形态：fs:0 SIB 绝对、RIP 相对、base+idx+disp、读写双向）；重入
  防护 + 一次性慢速警告；未覆盖形态保持致命路径并输出指令字节；
  VEH 对客户段内特权指令（#GP）也输出 rip/字节诊断
- **诊断**：strace 日志增加 rip；`vela doctor` 增补 guest 清单

### Changed

- `mmap` 兼容矩阵升级：MAP_PRIVATE 文件映射、Reserve 内 MAP_FIXED 覆盖
  （内容语义差异记录于 SYSCALLS.md）
- CI 生成 guest 增加 fs-exec；验收运行增加动态 musl 与 execve 链路
- 已知限制（如实记录）：execve 重载时旧 Reserve 块解除登记但不
  VirtualFree（含 donate NOACCESS 页的块会内核致死且不经 VEH），地址
  空间保留至进程退出

### 验收口径达成（PLAN-0.0.4 §0）

1. MAP_PRIVATE 文件映射读一致、COW 不回写宿主文件（Windows 宿主测试）
2. `vela run --soft-tls guest/bin/hello-dyn` 输出问候并干净退出
3. execve 重载语义 + CLOEXEC 关闭 + fd 保留（fs-exec 端到端）
4. pipe2 随 execve 落地且使 fd 继承有意义
5. `--soft-tls` 让 FSGSBASE 缺失环境（本机/云 VM）从"跳过"变"软跑通"
6. 82 测试全绿、fmt/clippy -D warnings 干净

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
