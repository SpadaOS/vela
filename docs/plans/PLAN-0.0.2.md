# Vela 0.0.2 计划 — 从 demo 到可用的运行时

> 状态：草案 v1（2026-09-18）
> 前置：v0.0.1（`b43abf4`）已交付：静态 PIE 加载 + UD2/VEH syscall 翻译 + TLS trampoline + 4 个 guest 验收
> 本计划的现状调研基于 0.0.1 全量代码走读（详见附录 A）

## 0. 版本主题与 Definition of Done

**主题：让"真实的 musl C 程序 + 文件 IO"跑起来，并把工程地基打牢。**

0.0.1 的本质是一个能跑无 libc 汇编程序的 demo；0.0.2 要让静态 musl 程序（含文件读写、目录遍历）成为一等公民。

**验收口径（全部满足才发版）：**

1. FSGSBASE 机器上：`hello-musl` 稳定运行（300 次零失败，对齐 DESIGN.md 的既有标准）
2. 新增 `guest/file-io`（musl C 源码）端到端通过：open/read/write/stat/getdents64/getcwd 全链路
3. `vela run --root <dir>` 可将任意宿主目录挂为客户根，无硬编码 `/mnt/c`
4. `cargo test --workspace` 全绿；文件类 syscall 有专项集成测试
5. CI（windows-latest）完整跑通构建 + 测试 + guest 验收，且 guest 由 `vela-mkhello`/`vela-mkguest` 现场生成
6. CHANGELOG.md + tag v0.0.2 + GitHub Release

## 1. 背景判断：为什么是这三条主线

README 路线图对 v0.x 的承诺是"补全 musl 常用 syscall（fstat/stat）、busybox 静态子集"。musl 静态程序从 `_start` 到 `printf` 输出，实际触碰的 syscall 集合（参考 Docker 默认 seccomp 白名单、Gramine 的实现矩阵、arceos-runlinuxapp 的 musl 启动集）核心是：

```
set_tid_address, arch_prctl, brk, mmap, mprotect, munmap,      ← 0.0.1 已覆盖
ioctl(TIOCGWINSZ stub), fcntl, fstat/stat/newfstatat,           ← 0.0.2 必补
writev, exit_group, getrandom, clock_gettime,                   ← 0.0.1 已覆盖
getdents64, getcwd, chdir, access, readlink, uname              ← 0.0.2 补齐（ls/cd 需要）
```

其中 **stat 家族是 musl stdio 初始化与一切文件操作的硬前提**（0.0.1 返回 -ENOSYS 只是恰好没被 hello 触发）。同行项目的共识做法：

- **Gramine**（~170/360 syscalls）：按 syscall 逐条维护兼容性矩阵文档，诚实标注部分实现 —— Vela 的 README/syscalls 表应效仿
- **blink**（jart）：`-f host:guest` 挂载语法 + `-s` syscall 日志 —— 对应本计划的 `--map` 与 strace 风格日志
- **musl 语义**：stat 的 `st_ino/st_dev` 只需"同进程内稳定一致"，不需要真实 inode —— 这把 Windows 句柄映射的实现风险大幅降低

## 2. 里程碑与任务分解

### M1 — 文件系统内核面：stat 家族与文件操作（最大块，先行）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T1.1 | **Host trait 加文件元数据能力** | `stat_path` 已存在但返回什么需重设计：新增 `HostFileMeta { dev, ino, mode, nlink, uid, gid, size, atime/mtime/ctime, blksize, blocks }`；Windows 实现用 `GetFileInformationByHandle`（`dwVolumeSerialNumber`→dev 哈希、`nFileIndexHigh/Low`→ino）；`mode` 从属性推导（目录位/只读位），权限位固定 `0644/0755` 风格 | 单元测试锁定 `struct stat` 偏移（vela-abi 已有布局，加 const 断言） |
| T1.2 | **stat(4) / fstat(5) / lstat(6) / newfstatat(262)** | dispatch 落地四个分支；`newfstatat` 支持 `AT_EMPTY_PATH`+`AT_SYMLINK_NOFOLLOW` 标志位；全部经 vela-fs 翻译 | musl hello 在 FSGSBASE 机启动不再 ENOSYS；每个 syscall 至少 2 条单测（成功/ENOENT） |
| T1.3 | **getdents64(217)** | Host 新增 `list_dir`（Windows `FindFirstFileExW`/`FindNextFileW`）；runtime 组装 `linux_dirent64 { d_ino, d_off, d_reclen, d_type, d_name }`，缓冲区按 Linux 语义逐条填满即停（返回已填字节数） | 新 guest `file-io` 中 `ls`-式遍历通过；与 stat 的 ino 一致性测试 |
| T1.4 | **fcntl(72) 最小集** | `F_GETFD/F_SETFD/F_GETFL/F_SETFL` 在 fd 表内记账（O_APPEND/O_NONBLOCK 记录但可 no-op 返回 0）；其余 cmd 返回 `-EINVAL` | fd 标志往返测试 |
| T1.5 | **ioctl(16) 终端 stub** | `TIOCGWINSZ`→返回 80x25；`TCGETS/TCSETS`→安全默认或 `-ENOTTY`；musl stdio 探测即通过 | musl hello 的 isatty 探测路径稳定 |
| T1.6 | **open/openat 语义补全** | openat(257) 支持 dirfd（fd 表内目录句柄，先支持目录 fd + 相对路径）；`O_CLOEXEC/O_TRUNC/O_APPEND` 语义记账；错误码映射 `ENOENT/EACCES/EISDIR/EEXIST/EINVAL` | 错误路径专项测试（当前为 0 覆盖） |

**M1 出口**：`guest/file-io`（新 musl C guest，做 open/write/read/stat/mkdir/getdents64/close）端到端绿。

### M2 — 进程环境：路径通用化 + envp/auxv

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T2.1 | **vela-fs 重写：映射表** | `Vec<Map { guest_prefix, host_dir }>` 替代硬编码 `/mnt/c → C:\`；默认单条目 = `--root <dir>`（缺省取宿主 cwd）；`--map guest=host` 追加多条（借鉴 blink `-f host:guest`）；翻译函数纯函数化并单测 | 路径翻译单测矩阵（绝对/相对/越界/`..` 仍拒绝/重复前缀） |
| T2.2 | **getcwd(79) / chdir(80)** | runtime 记账式 cwd（不真改宿主进程目录）；客户 cwd 初始值 = 宿主 cwd 经映射反推的客户路径；chdir 校验存在性（Host `stat_path`） | `file-io` guest 内 `getcwd`+`chdir` 往返测试 |
| T2.3 | **envp 传递** | 默认继承宿主环境变量（透传，含 PATH）；`--env K=V` 覆盖、`--env K=` 删除；argv[0] 规则文档化 | guest 打印 envp 与预期一致 |
| T2.4 | **auxv 补全** | 现状检查后补 `AT_RANDOM`（16 字节 getrandom）、`AT_EXECFN`、`AT_HWCAP=0`、`AT_CLKTCK=100`、`AT_PAGESZ` 已有则确认 | musl 启动零 auxv 相关异常；auxv 布局单测 |
| T2.5 | **uid/gid 可配** | 默认 1000 保持，`--uid/--gid` 覆盖（写进 auxv 与 `getuid` 系） | 参数生效测试 |

### M3 — 运行时健壮性（去 demo 感，穿插进行）

| # | 任务 | 要点 |
|---|---|---|
| T3.1 | **错误码真实传播** | `HostError::Other(0)` 消灭：Windows `GetLastError()`/NTSTATUS → Linux errno 映射表（约 20 个高频码），Host 层携带原始码 |
| T3.2 | **退出路径清理** | `process_exit` 前 flush stdio、关闭 Host 文件句柄；客户 AV/非法指令时输出完整 rip/映射段归属并以 `128+sig` 规范化退出码 |
| T3.3 | **数据结构升级** | `MemRegistry` 线性扫描 → `BTreeMap<u64, Region>` 区间账本；`exec_ranges` 上限 32 → 动态 Vec |
| T3.4 | **栈/堆可配** | `--stack-mb/--heap-mb`（默认 8/8），上限护栏；堆初始化失败从 warn-继续改为 fatal |
| T3.5 | **syscall 日志 strace 化** | `VELA_LOG=1` 输出 `nr 名字(参数...) = ret` 格式（对齐 blink `-s`），方便 musl 兼容性排障 |
| T3.6 | **patch 加固** | patch 只落在 loader 登记的可执行段内（现状已扫 exec 段，但需把"被 patch 地址表"传给 VEH 校验，防数据段 0F 05 误报与外星 UD2） |
| T3.7 | **read_cstr 优化** | 4096 上限保留，但改为按页安全读取 + 长度 O(n)，不再逐字节 trap 检查 |

### M4 — 测试 / CI / 发布

| # | 任务 | 要点 |
|---|---|---|
| T4.1 | **文件 syscall 集成测试** | temp 目录内：open/write/read 回读、stat 尺寸与类型、getdents64 遍历、lseek 语义、ENOENT/EACCES 路径 —— 补上当前文件链路 0 测试的窟窿 |
| T4.2 | **CI 现场生成 guest** | `ci.yml` 用 `vela-mkhello`/`vela-mkguest` 生成 `guest/hello`、`torture`，`hello-musl` 因 FSGSBASE 依赖走条件门（现状已 gate） |
| T4.3 | **vela doctor** | 子命令：报告 CPU FSGSBASE、版本、杀软提示（README 已述风险）、Host 能力矩阵 —— 排障入口 |
| T4.4 | **发布流水线** | CHANGELOG.md（Keep a Changelog 格式）、版本号 0.0.2、tag `v0.0.2`、GitHub Release 附 `vela.exe` 产物（gh CLI 流程） |
| T4.5 | **兼容性矩阵文档** | `docs/SYSCALLS.md`：全表列 已实现/部分实现/ENOSYS 三态 + 备注（效仿 Gramine），README 链接 |

### M5 — 拉伸目标（可选，M1 完成后评估）

- **busybox 静态裁剪版**（`CONFIG_STATIC=y`，仅 echo/ls/cat/true/false 五个 applet）作为 0.0.2 的真实压力测试；若时间不够则顺延 0.0.3 —— busybox 启动还会触碰 `rt_sigaction/rt_sigprocmask`（0.0.2 可用"记录并返回成功"的诚实 stub，与 0.0.1 对 set_robust_list 的处理一致）
- mmap 文件映射（`MAP_PRIVATE` 文件 backed）—— musl loader 场景需要，量力放 0.0.3

## 3. 明确不做（0.0.2 维持 NONGOALS）

线程/clone/futex、socket/epoll、信号投递（rt_sigaction 诚实 stub 除外）、动态链接、fork/execve、GUI、Go 程序、32 位 —— 全部沿 `docs/NONGOALS.md`。**不把兼容面摊大饼，先把单线程文件型 musl 程序做扎实。**

## 4. 依赖关系与建议顺序

```
T1.1 (Host 文件元数据)
  └→ T1.2 stat 家族 ─→ T1.3 getdents64 ─→ [M1 出口: file-io guest]
T1.4 fcntl / T1.5 ioctl / T1.6 openat 语义 ─→（与上并行）
T2.1 vela-fs 映射表 ─→ T2.2 cwd ─→ T2.3 envp / T2.4 auxv / T2.5 uid
T3.x 与 T4.1/T4.2 穿插；T4.3 doctor 收尾；T4.4 发版最后
```

建议提交节奏（Conventional Commits）：每个 T 编号一个或一组 commit，M1 出口打 `v0.0.2-alpha.1` 自测 tag。

## 5. 风险与对策

| 风险 | 等级 | 对策 |
|---|---|---|
| **本机 FSGSBASE 不可用**（已实测），musl 全链路无法本机验收 | 高 | CI（windows-latest）作为 musl 验收主战场（需先验证 runner CPU 特性，T4.2 顺带确认）；本机用无 TLS guest 回归 |
| Windows 文件元数据语义映射（ino 稳定性、mode） | 中 | 收窄目标：ino 只保证"同进程稳定+stat/getdents 一致"（musl 语义足够）；const 断言锁结构体布局 |
| `struct stat`/`dirent64` 布局手写出错 | 中 | vela-abi 加布局 const 断言 + musl 侧交叉验证 guest（打印 offsetof） |
| VEH red zone 风险（0.0.1 遗留） | 低 | 维持已知风险记录；file-io guest 压测观察；不阻塞 0.0.2 |
| 范围蔓延（busybox 诱惑） | 中 | busybox 定位 M5 拉伸目标，不阻塞发版 |

## 6. 需要拍板的决策点

1. `--root` 默认值：宿主 cwd（推荐，类 blink）还是保留 `/mnt/c` 兼容旧 guest？
2. envp 默认透传宿主全部环境（推荐）还是最小白名单（PATH/TEMP）？
3. busybox 是否进 0.0.2（影响发版时间）？
4. 发版产物：只发 `vela.exe` 单文件，还是 zip（含 docs）？

---

## 附录 A — 0.0.1 代码走读结论（计划依据）

- 代码量：vela-abi 213 行 / vela-sys ~1020 / vela-loader ~300 / vela-runtime ~940 / vela-fs 62 / vela-cli ~1140
- 已实现 24 个 syscall 号；stat/fstat/newfstatat/getdents64 无分支直接落 ENOSYS；fcntl 显式 ENOSYS（`syscalls.rs:34`）
- `HostError::Other(0)` 丢真实错误码（`windows.rs:147,546`）；堆初始化失败仅 warn（`main.rs:137-139`）
- 路径硬编码：`/mnt/c→C:\`（`fs/lib.rs:22-23`）、cwd 默认 `/mnt/c`（`runtime/lib.rs:102`）、uid=1000（`runtime/lib.rs:92`）
- envp 恒空（`guest_start.rs:102`）；栈 8MiB/堆 8MiB 硬编码
- 文件 open/read/lseek/close **零测试**；无错误路径测试；CI 依赖预编译 guest 产物
- 全库无 TODO/FIXME；mem registry 线性扫描、exec_ranges 上限 32

## 附录 B — 参考资料

- Docker 默认 seccomp 白名单（musl/C 程序 syscall 实用集）
- Gramine features 矩阵（https://gramine.readthedocs.io/en/v1.6/devel/features.html）
- blink（jart/blink）：`-f host:guest` 挂载与 `-s` syscall 日志设计
- arceos-runlinuxapp：musl 启动最小 syscall 集（SET_TID_ADDRESS/ioctl stub/writev/arch_prctl）
- x86_64 syscall 号表（https://cigix.me/syscalls，对齐 linux syscall_64.tbl）
