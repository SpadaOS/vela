# Vela 0.0.4 计划 — 动态程序之门（大版本适配）

> 状态：草案 v1（2026-09-19）
> 前置：v0.0.3（`b9590dc`）已交付五组 Host supertrait、~50 syscall、bench 设施
> 用户目标：大规模更新、大版本、较多的新适配

## 0. 版本主题与 Definition of Done

**主题：打开"动态程序之门"——文件映射 mmap、动态链接加载、execve 重载、
TLS 软回退。0.0.4 之后，Vela 能跑的不再只是"静态 musl 单文件"，而是
真实 Linux 软件的两大主流形态（静态 + musl 动态）。**

**验收口径（全部满足才发版）：**

1. **mmap 文件映射**：`MAP_PRIVATE` 文件 backed 映射可用，读一致、COW 语义正确
2. **动态链接**：`PT_INTERP` 不再拒载；`vela run --interp <ld-musl> <动态elf>`
   （或默认探测 `/lib/ld-musl-x86_64.so.1`）跑通动态 musl hello，输出标准问候
3. **execve**：进程内重载语义实现；`execve` 后 CLOEXEC fd 正确关闭、
   映像/堆/栈全部重建；新 guest `fs-exec`（musl C）端到端验收
4. **pipe2**：随 execve 语义一起落地（fd 继承记账使其有意义）
5. **TLS 软回退**：`--soft-tls` 实验开关——FSGSBASE 缺失环境下用 VEH 软件模拟
   fs 段访问，让 musl 程序在云 VM 上"能跑（慢）"；诊断模式输出明确性能警告
6. 常规：65+ 测试全绿、SYSCALLS.md/CHANGELOG 更新、tag v0.0.4 + Release

## 1. M1 — mmap 文件映射（动态链接的地基）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T1.1 | **Host 内存组扩展** | `HostMem` 增加 `map_file(file, offset, len, prot) -> addr`：Windows 用 `CreateFileMappingW` + `MapViewOfFileEx` FFI（零依赖手写，风格同现有）；`protect` 对映射区走 `VirtualProtect` | 单元测试：映射宿主文件→客户读到正确内容 |
| T1.2 | **mmap(9) 语义升级** | `MAP_PRIVATE` + fd（非匿名）走文件映射；`MAP_ANONYMOUS` 保持现状；`MAP_SHARED` 文件映射延后（记录 ENOSYS） | musl 动态 loader 依赖的映射形态全覆盖 |
| T1.3 | **munmap/msync 适配** | `unmap` 区分 unmap-view 与 free-reserve 两种句柄；MemRegistry 登记项标记类型 | 混合映射/释放序列无泄漏（诊断验证） |

**风险**：MapViewOfFileEx 的地址提示受 64K 对齐限制——loader 的 hint 逻辑需适配。

## 2. M2 — 动态链接加载（最大适配项）

musl 的动态执行不依赖 Vela 做重定位——`ld-musl-x86_64.so.1` 自身是完整的
ELF 加载器。Vela 只需：**把动态 ELF 当静态映像装载其 PT_INTERP 指向的
interpreter，构造正确的 auxv，从 interpreter 入口进入**。

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T2.1 | **loader 解锁 PT_INTERP** | 接受含 `PT_INTERP` 的 ET_DYN；解析 interp 路径字符串；拒绝非 musl interp（白名单前缀 `ld-musl`，其余诚实拒绝） | loader 单测矩阵 |
| T2.2 | **双映像加载** | 客户 ELF 与 interpreter 分别装载（各自 span/bias）；`AT_BASE`=interpreter bias、`AT_PHDR/AT_ENTRY`=客户 ELF 的、`AT_EXECFN`=路径 | auxv 布局单测 |
| T2.3 | **entry 语义** | 入口跳 interpreter entry（`e_entry`），ld-musl 自行装载客户段（依赖 T1 文件映射）| 动态 musl hello 端到端 |
| T2.4 | **验收 guest** | `guest/bin/hello-dyn`（zig cc 不加 `-static`，默认动态 musl）+ CI 条件跑 | CI 绿 |

**风险（高）**：ld-musl 启动路径可能触碰未实现 syscall（如 `mprotect` 特定
模式、`set_tid_address` 已有）；需要 strace 日志逐个补。预留"实验分支缓冲"：
若 2 周内跑不通，降级为"PT_INTERP 解锁 + 文档说明"，动态验收顺延 0.0.5。

## 3. M3 — execve 重载 + pipe2 + wait 族

| # | 任务 | 要点 |
|---|---|---|
| T3.1 | **execve(59) 进程内重载** | 同一 vela 进程内：flush/关闭旧 fd（CLOEXEC 生效）→ unmap 全部客户内存 → 重新 loader::load → 重建堆/栈/auxv → 重新进入。`exec_ranges` 槽位重置。argv/envp 全新传入 |
| T3.2 | **pipe2(293) + fd 继承** | 进程内环形缓冲 fd 对；execve 时非 CLOEXEC fd 保留（跨重载存活，支撑 `a | b` 的 velar 侧组合与未来 forkserver） |
| T3.3 | **wait4(61) 记账** | 单进程无子进程：诚实返回 `-ECHILD`（等待存在前的占位语义）；`getppid(110)` 返回宿主 pid 哈希 |
| T3.4 | **验收 guest** | `guest/bin/fs-exec`：musl C 程序 forkfree 地 execve 自身脚本式重载 + pipe 读写自测 |

## 4. M4 — TLS 软回退（--soft-tls，实验）

| # | 任务 | 要点 |
|---|---|---|
| T4.1 | **VEH fs 模拟** | FSGSBASE 缺失 + `--soft-tls` 时：客户段内 fs 前缀指令（0x64）触发的 AV 不再崩溃，改为解释执行该条 mov（读/写 tls_area 映射页），Rip 前进。仅覆盖 musl 实际发射的 `mov rax, fs:0` 等有限形态 |
| T4.2 | **诚实性能边界** | 命中软路径即置慢速标志并 stderr 警告一次；文档明确"诊断/CI 可用，生产性能不承诺"。unhandled 形态仍崩溃并报告模式 |

**风险（中）**：指令形态覆盖不全 → 崩溃信息必须列出 rip/字节便于扩表。
价值：CI（Hyper-V runner）与云 VM 的 musl 验收从"跳过"变"软跑通"，
0.0.2 以来的最大可用性解锁。

## 5. M5 — 收尾

- SYSCALLS.md 增补（execve/pipe2/wait4/getppid/statx 已有…）
- file-io guest 保留；新增 hello-dyn / fs-exec
- CHANGELOG（bench 表延续）+ 版本 0.0.4 + tag + Release
- docs/DESIGN.md 增补「动态加载」「execve 重载」「软 TLS」三节

## 6. 依赖与顺序

```
T1.x mmap 文件映射 ──→ T2.x 动态链接（依赖文件映射）
T3.1 execve 重载 ──→ T3.2 pipe2 / T3.4 guest
T4.x 软 TLS 独立轨（可并行）
M5 收尾（动态链接若降级，发版口径相应调整并明示）
```

## 7. 决策点（按推荐执行，除非另有指示）

1. **动态链接进 0.0.4 主线**（推荐）：这是"较多新适配"的最大单项；接受降级缓冲
2. **execve 语义**：进程内重载（推荐）——vela 架构无 fork，重载是唯一诚实路径
3. **软 TLS**：实验开关形态（默认关），不承诺性能
4. **busybox**：顺延 0.0.5（execve + 动态链接就位后才有意义）

## 8. 风险

| 风险 | 等级 | 对策 |
|---|---|---|
| ld-musl 启动路径触碰未知 syscall/语义 | 高 | strace 日志逐个补；预留降级缓冲（见 M2） |
| MapViewOfFileEx 地址对齐/提示失败 | 中 | 64K 对齐 + 失败回退系统自选地址再校验 |
| execve 重载的状态清理遗漏（VEH 槽/FS 基址） | 中 | 重载清单化（checklist 函数）+ 集成测试覆盖二次进入 |
| 软 TLS 指令形态覆盖不全 | 中 | 崩溃即报模式字节，快速扩表；实验开关定位 |
| 范围失控（四条主线并列） | 中 | M2 降级缓冲 + M4 独立开关化，任一受阻不阻塞其余里程碑 |
