# Vela 0.0.5 计划 — 真实软件之门（busybox + 工程地基加固）

> 状态：草案 v1（2026-09-19）
> 前置：v0.0.4（`feecf1c`）已交付文件映射 mmap、动态链接（musl）、
> execve 进程内重载、pipe2、--soft-tls 实验开关
> 用户目标：延续"较多的新适配"，本版以**真实软件（busybox）**为压力测试
> 主轴，同时清偿 0.0.4 留下的工程债

## 0. 版本主题与 Definition of Done

**主题：真实软件之门。** 0.0.4 打开了动态链接，但验收 guest 都是
"hello 级"小程序。0.0.5 把 **busybox 多调用（multi-call）二进制**作为
核心压力测试——它一次触碰几十个 syscall 路径（启动期 envp 遍历、
applet 表分发、文件系统批量遍历、终端探测），是"vela 能不能跑真实
Linux 软件"的第一个可信回答。工程侧同步完成 0.0.4 遗留的三笔技术债
（exec-range 静态表、abi 单文件、syscall 广度缺口），并补齐宿主管道
组合的最后一块拼图（stdin 直通），让 `vela run a | vela run b` 成为
一等用法。

**验收口径（全部满足才发版）：**

1. **busybox multicall**：`vela run guest/bin/busybox echo hello`、
   `... ls /mnt/c/Windows/Temp`、`... cat <文件>`、`... true/false/nproc`
   五个 applet 真实运行，输出与语义正确（构建方案见 M3，含 CI 可复现）
2. **宿主管道组合**：`vela run --soft-tls guest/bin/A | vela run --soft-tls
   guest/bin/B`（A 写 / B 读）在 PowerShell 下端到端工作——stdin 直通
   实现并有测试
3. **exec-range 原地重注册**：连续 10 次 execve（fs-exec 循环化）
   不触发 range 表满警告，无新分配、无锁
4. **abi 模块化**：vela-abi 拆分为子模块，纯重排零语义变化，
   `pub use` 保持 API 兼容，所有 crate 无需修改
5. **syscall 广度（+7 号）**：`fchmod/fchown/utimensat/ftruncate/
   readlinkat/sysinfo/getrlimit`，全部诚实近似并逐条标注
6. **soft-tls 回归资产**：形态覆盖表固化为测试向量（含 REX 全组合、
   mod=1/2 变址形态），bench guest 增加 soft-tls 模式对照数据
7. 常规：测试全绿（≥90）、fmt/clippy -D warnings、SYSCALLS/CHANGELOG
   更新、tag v0.0.5 + Release

## 1. M1 — 工程地基（清偿 0.0.4 技术债）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T1.1 | **exec-range 原地重注册** | 32 槽静态表保持无锁；GuestState 记录 `ranges_in_use: usize`；execve 重注册时**前缀覆盖**：新范围数 ≤ 上次数则逐槽覆盖（SeqCst store），多余槽清 0；不足则追加分配新槽。`clear_guest_exec_ranges` 退役 | dispatch 单测：模拟 10 轮 execve 的注册/清空循环，槽位计数恒 ≤ 32、无警告；fs-exec 串联 3 次重载 e2e |
| T1.2 | **abi 模块化** | `vela-abi/src/lib.rs`（~700 行）拆为 `syscalls.rs`（号+名表）、`errno.rs`、`auxv.rs`、`stat.rs`（Stat/S_IF*）、`mmap.rs`（PROT/MAP）、`fcntl.rs`（O_*/F_*/FD_*）、`mod.rs`。纯移动 + `pub use` 重导出，**不新增/修改任何常量** | 全仓 `cargo build/test` 零改动通过；`grep -r "abi::" | wc -l` 前后一致 |
| T1.3 | **syscall 名表完备性测试** | 新增测试：遍历 dispatch 已处理的所有号，断言 `syscall_name(nr) != "unknown"`——杜绝 0.0.4 曾出现的 "unknown(nr=293)" 排障体验 | 测试落地且通过 |
| T1.4 | **mmap carve 内容语义收敛（小项）** | Reserve 内 MAP_FIXED 匿名覆盖时，把覆盖区间**显式清零**（protect RW → fill 0 → 收敛 prot），对齐 Linux "替换=匿名零页" 语义；消除 0.0.4 的内容差异标注 | SYSCALLS.md mmap 行限制删除；musl donate 场景回归（hello-dyn/fs-exec 照常） |

## 2. M2 — 宿主管道组合（stdin 直通）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T2.1 | **stdin 直通** | 确认/修复 `GuestFd::StdIn` 读取链路（file_ops::read → std::io::stdin 已有真实实现，需 e2e 验证；MockHost 的 `Ok(0)` 保持测试语义）。必要时处理 PowerShell 管道的字节流模式（SetConsoleMode 关闭行缓冲对管道无影响，仅需验证） | 新 guest `guest/src/pipe-b.c`：`read(0,...)` 读到数据并回显 `cat` 语义 |
| T2.2 | **组合验收 guest 对** | `guest/src/pipe-a.c`（写 3 行到 stdout，含二进制安全边界行）+ `pipe-b.c`（stdin 逐块读、统计字节/行数输出）；两者均为静态 musl | `vela run guest/bin/pipe-a | vela run guest/bin/pipe-b` 输出行/字节统计正确 |
| T2.3 | **退出码与错误传播验证** | 管道中段 vela 崩溃（139）时宿主 shell 的 `$LASTEXITCODE` 行为记录；vela `--soft-tls` 等选项在管道两侧各自生效 | 文档化于 README「组合」节；e2e 脚本化 |
| T2.4 | **（评估）velar 迷你组合器** | 若 T2.1-T2.3 发现有 shell 无法表达的需求（如两侧不同选项模板、fail-fast 语义），再实现 `velar`（~200 行，Job 对象 + 匿名管道）；**默认不做**——pwsh `|` 已覆盖 | 决策记录于本文件决策点 3 |

## 3. M3 — busybox 静态子集（主轴）

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T3.1 | **构建通道** | busybox 1.36.x 源码（不入库，同 musl 惯例）；`make defconfig` 后 sed 裁剪：`CONFIG_STATIC=y`、仅启用 echo/ls/cat/true/false/nproc/env/printf（关 httpd/tc 等）；`CC="zig cc -target x86_64-linux-musl"`。本机无 make → 提供两通道：(a) CI 用 `msys2`/choco make 构建；(b) 本机 PowerShell 版 `tools/build-busybox.ps1` 手动驱动（obj 列表由 `make -n` 一次性导出后固化） | `guest/bin/busybox` 产出（ET_DYN 静态 PIE，`-fPIE -pie`）；构建脚本入库 `tools/` |
| T3.2 | **启动缺口排查** | busybox `_start` → `main` → applet 分发表（只读数据）→ `busybox_main`。预期触碰：`readv?`、`ioctl(TIOCGWINSZ/TCGETS)`、`getcwd`、`mmap` 大块、`execve`?（applet 直调不需要）、`stat` 批量。用 `-v` strace 逐个补齐缺口，诚实 ENOSYS 优先（观察 libc 降级路径） | echo/true/false/nproc 零缺口直通；ls 需要的缺口全部闭环 |
| T3.3 | **ls 的文件系统语义** | `ls` 走 `opendir/getdents64/stat/lstat`——vela 已有但从未被真实软件压测。重点核对：d_type 传播、`d_off` 单调性、大目录分页（count 不足→EINVAL→musl 降级 getdents64 循环）、隐藏文件语义 | `ls /mnt/c/Windows/Temp` 与真实目录内容一致（条目集合相同） |
| T3.4 | **cat 的 IO 语义** | 大文件分块读（vela read 上限内的循环）、stdin 直通（`cat` 无参数 = echo）、`cat 缺失文件` 的 stderr + 退出码 1 | `cat` 回读 file-io 验收产物逐字节一致 |
| T3.5 | **CI 集成** | busybox 产物（~1-2MB）是否入库遵循既有惯例（guest/bin 入库）；CI 增加构建通道（msys2 make）或跳过构建直接用入库产物+文档化复现——按决策点 2 | CI 验收含 `busybox echo/ls/cat` 三连 |

## 4. M4 — syscall 广度 +7（诚实近似）

| # | syscall | 状态 | 要点 |
|---|---|---|---|
| 91/94 | fchmod / fchmodat | 🟨 | Windows 仅只读位：mode & 0222 → 只读属性翻转；其余位忽略并文档化 |
| 260/207 | fchown(260)/fchownat | ⭕ | 记录后返回 0（Windows 无 per-file uid/gid；诚实 no-op） |
| 253 | futex **不变** | — | 维持 NONGOALS |
| 88/89/90 | symlink/readlink 系 | 🟨 | readlinkat 对 `/proc/self/exe` 诚实 ENOENT（vela 无 procfs）；其余 ENOSYS |
| 179 | sysinfo | ⭕ | 固定结构：uptime=宿主运行时长、totalram=GlobalMemoryStatusEx、mem_unit=1 |
| 160/161 | getrlimit/setrlimit | ⭕ | RLIM_INFINITY（与 prlimit64 一致） |
| 252 | execveat | ❌ | 维持 ENOSYS（空 path+AT_EMPTY_PATH 场景无需求） |

最终清单在实现时按 busybox 实际触碰微调（T3.2 的 strace 是输入）。

## 5. M5 — soft-tls 增强 + 性能对照

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T5.1 | **形态回归资产** | `tests/soft_tls_forms.rs`：把 decode_fs_mov 的解码矩阵固化为表驱动测试（前缀/REX.W/R/B × 8b/89 × mod=0/1/2 × SIB 有无 × disp 宽度），全部形态向量入测 | ≥40 组合向量，含负例（32 位、lea、reg-reg、截断） |
| T5.2 | **bench 对照** | bench guest 增加 `--soft-tls` 模式（TLS 读循环，模拟 musl 常见密度），产出"硬 TLS vs 软 TLS vs 无 TLS"三列对照入 docs/bench.md | 数据落档；软路径单次成本数量级明确（预期 ~µs 级=VEH 往返） |
| T5.3 | **（评估）写形态白名单** | soft-tls 当前禁写（load only）？——0.0.4 已支持 store；评估 store 到 NOACCESS/只读页时的诊断质量 | 决策记录；诊断输出含目标地址 |

## 6. M6 — 收尾

- SYSCALLS.md 增补（+7 号 + busybox 相关语义注记）
- CHANGELOG（bench 表延续 busybox 启动耗时对照）
- docs/DESIGN.md 增补「busybox 与 multicall」「宿主组合」两节
- 版本 0.0.5 + tag + Release（附 busybox 验收输出）

## 7. 依赖与顺序

```
M1 工程地基 ──→ M3 busybox（strace 排障依赖 T1.3 名表完备）
M2 管道组合（独立轨，可并行）
M4 广度 +7 ←─ T3.2 缺口清单驱动（busybox 需要什么先做什么）
M5 soft-tls（独立轨）
M6 收尾
```

节奏建议：M1 → M2 → M4（随 T3.2 滚动）→ M3（主轴，留最大时间片）→
M5/M6。每 M 一个 commit 推送 origin main。

## 8. 决策点（按推荐执行，除非另有指示）

1. **busybox vs toybox vs 自研 multicall**：推荐 **busybox**——它是"真实
   Linux 软件"的最强背书，构建重但一次投入永久复用；toybox 构建轻但
   说服力弱；自研无意义。构建通道失败时降级顺序：msys2 make →
   手动固化 obj 列表 → 本版顺延 busybox（M3 其余任务独立成立）
2. **busybox 产物入库**：推荐**入库**（与 hello-dyn/ld-musl 惯例一致，
   CI 不依赖构建通道也能验收）；复现脚本入库 tools/
3. **velar 迷你组合器**：推荐 **默认不做**——pwsh `|` 已覆盖组合语义，
   velar 仅在 T2.3 发现不可表达需求时升级
4. **MAP_SHARED 匿名/跨进程**：推荐 **本版不做**——vela 单进程 +
   宿主组合器场景下无真实需求；跨进程共享内存（句柄继承/命名对象）
   复杂度与收益不成比例，放 0.0.6 评估
5. **execve 旧 Reserve 泄漏**：推荐 **维持现状**——内核路径致死未解，
   泄漏量（每重载 ~16MB+）在单 guest 生命周期内可接受；0.0.6 立项
   "Windows 内存策略研究"（MEM_RESET / 分区式堆 / fork-server 前置研究）

## 9. 风险

| 风险 | 等级 | 对策 |
|---|---|---|
| busybox 构建链在 Windows 上不可行（make/config 深依赖） | 高 | 三级降级（决策点 1）；`make -n` 固化 obj 列表为兜底；CI msys2 为正道 |
| busybox syscall 面失控（一个 applet 拖出一串缺口） | 高 | applet 白名单裁剪到最小集；诚实 ENOSYS 优先；缺口清单入 M4 滚动消化；单 applet 不可达则从白名单移除 |
| busybox 触碰信号（busybox 启动装 handler） | 中 | rt_sigaction/procmask 已是诚实 stub；确认 musl 层降级路径（sigaction 失败 → busybox 忽略？）实测决定 |
| ls/cat 的目录/IO 边界问题集中爆发 | 中 | T3.3/T3.4 拆小验收；getdents64 分页语义已实现，重点在真实目录压力 |
| stdin 直通与 v0 "StdIn 读返回 0" 历史语义冲突 | 低 | 仅 MockHost 保留测试语义；WindowsHost 走真 stdin；e2e 定验收 |
| abi 模块化纯机械但量大 | 低 | 纯移动无语义变更；一个 commit 完成，diff 逐块核对 |
| 范围失控（busybox 主轴 + 4 条支线） | 中 | M3 为主轴；M2/M5 独立轨可整体顺延；决策点均有"不做"出口 |
