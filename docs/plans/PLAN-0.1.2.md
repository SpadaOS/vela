# Vela 0.1.2：线程与并发运行时

## 版本定位

以已合并的 `v0.1.1` 为基线，继续只支持 Windows x86_64。0.1.2 的唯一主线是实现真实并行的 pthread 基线，让更多 musl CLI 工具具备运行基础。

本阶段先提交计划；代码、workspace 版本、CI 和发行包在计划确认后再实施。最终目标是完成 PR 和 GitHub Actions 收口，不打 tag、不发布 Release。

## 范围与边界

- 默认启用线程支持，保持 0.1.1 的静态 PIE、动态 musl、文件 IO、fork/exec、pipe、poll/select 和 BusyBox 验收兼容。
- 目标是 pthread 基线：真实 Windows 并行线程、线程 TLS、基础 futex、线程退出与 join 所需语义。
- 目标软件以 musl pthread guest 和 BusyBox `grep`、`find`、`tar`、`gzip` 为硬验收；静态 musl git 不纳入本版本门槛。
- socket、epoll、glibc、完整信号投递、robust futex、线程取消、MAP_SHARED、32 位、ARM、非 Windows 宿主和 SpadaOS/LinuxDev 真正实现继续不在范围内。
- 多线程进程调用 fork 返回 `EAGAIN`；非主线程调用 execve 返回 `ENOSYS`；单线程进程保留现有 fork/exec 语义。

## 实现计划

### 1. 进程与线程状态

- 将当前单线程 `GuestProcess` 拆为进程共享状态与 `GuestThread` 状态。
- 进程共享状态包括 ELF 映像、`MemRegistry`、fd 表、cwd、路径映射、uid/gid、子进程表和进程级资源。
- 线程状态包括 tid、FS/GS 基址、soft-TLS 基址、`clear_tid`、robust-list 指针、线程栈和退出状态。
- 使用 `Arc`、`Mutex`、`RwLock` 和原子类型保护共享状态；poll、pipe、futex 等阻塞调用不得持有进程共享锁。

### 2. clone、线程退出和身份

在 `vela-abi` 增加 `SYS_GETTID=186`、`SYS_FUTEX=202`、线程 clone flags 和 futex 操作常量。

支持以下线程 flags：

`CLONE_VM`、`CLONE_FS`、`CLONE_FILES`、`CLONE_SIGHAND`、`CLONE_THREAD`、`CLONE_SYSVSEM`、`CLONE_SETTLS`、`CLONE_PARENT_SETTID`、`CLONE_CHILD_CLEARTID`；`CLONE_DETACHED` 作为兼容性 no-op 掩码，不改变线程生命周期。

- 父线程获得新 tid；子线程从 clone 返回点继续执行，返回值为 0，并使用 `newsp` 和 `tls`。
- 未支持或组合错误的 flags 返回明确的 `EINVAL` 或 `ENOSYS`。
- `SYS_EXIT` 只退出当前线程；`SYS_EXIT_GROUP` 终止整个进程。
- 线程退出时写入 `clear_tid` 并唤醒等待者；`getpid` 返回进程 pid，`gettid` 返回线程 tid。
- 扩展 `HostProc` 为平台无关的 guest-thread 启动、等待和退出接口；Windows 使用原生线程和 CONTEXT 恢复，LinuxDev/SpadaOS 保持 `Unimplemented`。

### 3. 每线程 TLS 与 trap 并发安全

- `arch_prctl(ARCH_SET_FS/GET_FS)` 改为线程级状态。
- soft-TLS 基址改为 Windows TLS/FLS 或等价 thread-local 存储，移除单一全局 soft-TLS 基址。
- VEH、island 的保存区、异常栈和 RSP 保存值改为每线程 `TrapScratch`。
- trap 回调按当前 Windows 线程取得对应 `GuestThread`；执行区间表和 syscall 回调保持原子/只读共享。
- `--soft-tls` 作为 CI 首选路径；硬 TLS 保持兼容。`doctor` 报告线程后端、futex 后端、TLS 模式和活动 tid。

### 4. Windows futex

在 Host 契约实现 `futex_wait(addr, expected, timeout)` 和 `futex_wake(addr, count)`。Windows 使用 `WaitOnAddress`、`WakeByAddressSingle`、`WakeByAddressAll`：

- 当前值不等于 expected 返回 `EAGAIN`。
- 无 timeout 表示无限等待；等待超时返回 `ETIMEDOUT`，不能与正常 wake 返回值混淆。
- 非法地址、未对齐地址和非法 timespec 返回明确错误。
- runtime 实现 `FUTEX_WAIT`、`FUTEX_WAKE` 和 private flag；PI、requeue、robust futex 等继续返回 `ENOSYS`。Host API 必须保留 timeout/wake 的区别，让 runtime 映射为 `ETIMEDOUT` 或成功唤醒。
- LinuxDev/SpadaOS 默认继续返回 `Unimplemented`，guest-side crate 不泄漏 Windows API。

### 5. guest 与 BusyBox

- 新增 `guest/src/pthread-test.c` 和 `guest/bin/pthread-test`，覆盖 8 至 16 个线程创建/join、每线程 TLS、原子计数、共享内存、futex wait/wake、tid 唯一性和稳定的 getpid。
- BusyBox 白名单增加 `FIND`、`TAR`、`GZIP`，保留现有 grep、cp、mv、rm、wc、sort、ash 等 applet。
- BusyBox 验收在 root 隔离目录中覆盖 grep/find/tar/gzip；重复运行 pthread guest，避免偶然通过。

## 文档、版本和 CI

- 计划确认后将 workspace 和所有 crate 版本统一为 `0.1.2`。
- 更新 `CHANGELOG.md`、README、`guest/README.md`、`docs/DESIGN.md`、`docs/HOST.md`、`docs/SYSCALLS.md`、`docs/NONGOALS.md`。
- `scripts/verify.ps1` 增加线程 guest 入口，发布流程要求 BusyBox 和 pthread guest。
- release workflow 更新版本检查、计划文档和 `pthread-test` 资产；本版本不创建 tag。
- CI 增加线程 guest 构建、soft-TLS 验收、BusyBox 新 applet 验收和并发重复测试。
- 本地缺少 `cl.exe` 或 `link.exe` 时加载：`%comspec% /k "D:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"`。

## 验收门禁

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- 既有 Windows guest acceptance 全部回归
- `scripts/verify.ps1 -RequireBusybox -RequireThreads`
- pthread guest 的 soft-TLS 并行测试
- futex timeout、EAGAIN、wake count、clear-tid 回归
- unsupported clone flags、线程 fork、worker exec 的错误语义测试
- BusyBox grep/find/tar/gzip root 隔离测试
- release ZIP 解压后的 version、doctor、pthread、musl、fork/exec/pipe/poll/select 和 BusyBox 验收
- 工作区无未提交源码改动和未跟踪构建产物
