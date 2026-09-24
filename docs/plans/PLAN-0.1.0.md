# Vela 0.1.0 计划 — Windows 一等运行时

> 状态：草案 v1（2026-09-24）
> 前置：v0.0.6（tag v0.0.6）已交付用户态 fork + wait4 + kill 最小集 +
> busybox 白名单扩容 + release 产物
> 定位：**唯一可运行宿主：Windows x86_64**。SpadaOS / macOS 只预留契约
> 默认桩，不进验收、不进 Release 矩阵、不承诺 hello。
>
> 大规模更新动的是 Windows 产品本身 + 把 Windows 专用机制从「碰巧能
> 抽象」收成「以后能换」——不是去实现另一个 OS。

## 0. 现状锚点与欠债

已闭环（0.1 必须不回退）：静态 PIE hello、torture mmap、动态 musl
（ld-musl* + --soft-tls）、execve 进程内重载、pipe2 真 Windows 管道、
用户态 fork + wait4、busybox echo/nproc/true。Host 五组形状已有；
runtime 禁 cfg(target_os) 纪律在；零第三方依赖。

欠债（0.0.6 自己写进 Release/CHANGELOG 的）：

- ash `sh -c`：CI 跑到编译器 **UD1 陷阱**（rip=0x400722cc 固定，
  `67 0f b9 40 13` = UD1，strace 显示**死在 fork 之前**——最后 syscall
  是 rt_sigaction(0xf)，无 fork syscall）
- fork 全量 ~24MB 快照；execve 旧 Reserve 不 VirtualFree
- VEH 处理帧跑在**客户栈**上（红区被踩风险；0.0.6 的 fork 在 VEH 里
  跑 CreateProcessW 就是站在这个地雷上）
- 热路径每 syscall ≈ 一次内核异常往返（bench ~2µs；0.0.6 本机取样
  噪音 ±25%，需方法论修正）
- `syscalls.rs` ~56KB / `windows.rs` ~58KB / `fork.rs` ~31KB；
  `HostFileKind::Disk` 直接抱 `std::fs::File`
- `SpadaOsHost` 全 Unimplemented；无 macOS 模块

## 1. Definition of Done

全部满足才打 `v0.1.0`：

1. 0.0.6 验收全集不回退（hello / torture / hello-dyn / fs-exec /
   fork-test / busybox echo·nproc·true），guest 输出字节级一致。
2. **ash 最小闭环**：`busybox sh -c 'echo hello | wc -c'` 在 CI
   `--soft-tls` 下稳定输出并退出 0。做不到 → 降级二选一（决策点 1），
   **不许第三种「实验性且 CI 绿着装没看见」**。
3. 陷阱处理走**宿主栈**（VEH 与岛页两条路径都不得用客户栈 / 红区）。
4. 岛页跳板：**实现并给出 VEH vs 岛页两列 bench**；默认后端由稳定性
   决定（`--trap=veh|island|auto`，doctor 打印实际后端）。岛页没快一个
   数量级也发版，但数据必须测到、写进 `docs/bench.md`。
5. fork：映像只读段共享（不 memcpy）落地；快照体积可观测
   （doctor：copied_kib）；**HostDir 游标不再重置**；execve 地址空间债
   可见（doctor：reserve leak）。
6. `Host` 增加 `HostTrap` / `HostProc`（带默认 `Unimplemented` 桩）；
   Windows 填满；**vela-runtime / vela-loader / vela-fs 中不再出现
   VEH / NtContinue / CreateProcessW**；`SpadaOsHost` 空壳能编译。
7. dispatch 按子系统拆文件；`utimensat` 落地（SetFileTime）；
   `vela doctor` 报陷阱后端、TLS 模式、地址空间债、island/veh 计数。
8. 文档五件套 + `PLAN-0.1.0.md` 与代码一致；README 写明
   「唯一支持宿主：Windows」。

## 2. 里程碑

### M0 — 冻结与基线

| # | 任务 | 要点 |
|---|---|---|
| T0.1 | `docs/plans/PLAN-0.1.0.md` 入库 + CHANGELOG 开 `## [0.1.0] - unreleased` | 本文即基线 |
| T0.2 | 基线 bench 方法论入库 | **固定 CPU 亲和（start /AFFINITY）+ 5 次取样取中位数**；本机 ±25% 噪音的教训（0.0.6 取样 8.9s/11.1s）写进 bench.md 头注 |
| T0.3 | ash UD1 证据可复现化 | 固定 busybox 构建指纹（CI 产物 hash）+ `-v` strace 片段 + UD1 字节/地址 → `docs/plans/ash-ud1.md`。**没有 strace 复现就不开始 M3** |

### M1 — 契约收口（行为与 0.0.6 完全一致，Windows 机制进 vela-sys）

| # | 任务 | 要点 |
|---|---|---|
| T1.1 | `HostTrap` trait | `install` / `enter_guest` / `resume` / `on_guest_fault`；Windows 实现 = 现有 VEH + UD2 + NtContinue + `vela_enter_guest` 汇编。**注意**：dispatch 签名 `(nr, args, rip, &mut Context)` 依赖 VEH CONTEXT——HostTrap 化时一并重构为寄存器视图（M2 岛页路径没有 VEH 上下文，这是前置） |
| T1.2 | `HostProc` trait | `spawn_self` / `shared_section` / `map_section_at` / `wait` / `kill` / `set_inherit`；把 `fork.rs` 的 `CreateProcessW`、section、CONTEXT 对齐/flags 细节全部下沉 `windows.rs`。**连锁**：fork 的 fd 序列化依赖 `HostFileKind::Disk{path,handle}`——与 T1.3 同步改造 |
| T1.3 | `HostFile` 不透明化 | `Disk { file: std::fs::File }` 改为 sys 私有存储；runtime 只见 token。`file_ops.rs` 保留给 Windows 宿主内部用；对外新增 `raw_handle` / `disk_path` 供 fork 协议序列化 |
| T1.4 | 编译闸门 | CI grep：`vela-runtime` / `vela-loader` / `vela-fs` 源码禁止 `windows`、`NtContinue`、`VEH`、`CreateProcessW` 字样（crate 结构 + CI 脚本双保险） |
| T1.5 | `SpadaOsHost` | 新 trait 方法全部走默认桩（`Unimplemented`），**不写假实现**；macOS 模块不建 |

验收：0.0.6 guest 字节级输出不变。**这是 M2/M3/M4 的地基——跳过会把
岛页和脏页继续焊死在 cli。**

### M2 — Windows 热路径（岛页跳板 + 宿主栈）

| # | 任务 | 要点 |
|---|---|---|
| T2.1 | patch 点账本 + 岛页分配器 | **账本先行**：每个被 patch 的 syscall 点登记（地址、原字节、岛地址）。岛 = `VirtualAlloc` 在映像 ±2GB 内的 RX 页（`jmp rel32` 可达）；**不做 jmp rel8**（musl 页内 cave 配不齐每个 syscall 点 ±128 的洞——0.0.6 评审结论）。patch = 5 字节 `jmp rel32`，**必须校验被覆盖的 3 字节不是任何跳转目标**（最小指令解码 + 线性扫描跳转范围；vela 已有 ModRM 解码器底子）。校验不过的点 → 留 UD2+VEH（混合模式，计数进 doctor：`island_sites / veh_sites`） |
| T2.2 | 岛内序列 | 覆盖字节无需搬移（syscall = 调用即返回语义，dispatch 后写回 `rip+2`）。岛内：保存 caller-saved + 参数寄存器 → **切宿主栈** → `call dispatch`（重构后的寄存器视图签名）→ 写回 rax → 用户态 `jmp` 回 `rip+2`。**不碰 NtContinue** |
| T2.3 | VEH 降级 | 只处理：非岛来源的 UD2（VEH-site）、真实 #UD、soft-tls 的 fs AV、客户段缺页。**与 T1.1 的 HostTrap 统一为同一份代码** |
| T2.4 | 红区纪律 | VEH 处理函数与 soft-tls 模拟**先切宿主栈再干活**——VEH 回调栈帧落在异常时 rsp（客户栈）上，客户红区（rsp-128）会被踩；0.0.6 的 fork 在 VEH 里跑 CreateProcessW 就站在这个地雷上。两条陷阱路径统一「进入即切宿主栈」 |
| T2.5 | fs heal 降频（**保守**） | ⚠ 0.0.4 的 fs 自愈是**正确性修复**（CI 必现内核还原陈旧 FS 基址 → 客户 TLS 崩），不是纯优化。0.1 只允许「降频」（arch_prctl 后 N 次校验 / 或诊断计数）——**先在 CI 连续 20 次 hello-dyn/hello-musl 验证内核行为已消失，才允许删**；删不干净就保留全量 heal，不挡发版 |
| T2.6 | `--trap=veh\|island\|auto` | 默认 `auto`：岛页全部校验通过 → island；任一点失败 → 该点 VEH（混合）。doctor 打印实际后端与 site 计数 |
| T2.7 | **岛页 × fork 联动（评审补充，必做）** | 岛页不在 MemRegistry——fork 快照后子进程的 `jmp` 指向不存在的岛 → 秒崩。修法：子进程恢复时按 T2.1 账本**重建岛并重写 patch 点**（patch 点账本是 T2.1 的直接产出）；或岛页 section 化随快照传递。二选一，实现于 fork 恢复路径 |

验收：hello-dyn / fork-test / file-io / busybox 三件套在 island 模式全绿；
bench 两列（VEH / island）入 `docs/bench.md`（T0.2 方法论）。

### M3 — ash 与「真实软件」债

| # | 任务 | 要点 |
|---|---|---|
| T3.1 | UD1 定性（假设按证据重排） | **证据**：死在 fork 之前（无 fork syscall）+ UD1 = 编译器 unreachable 陷阱 → 假设排序：① ash/musl 走到 `__builtin_unreachable` 分支（fork 返回值/寄存器断言被破坏）② ash 自己的 inline asm 或 zig 生成代码踩 patch 点邻域 ③ ~~fork 恢复 prot 错~~（prot 影响在 fork 后才显现，与「死在 fork 前」矛盾，**降级为验证项而非主假设**）。方法：`-v` strace + 在 UD1 诊断里补寄存器快照 |
| T3.2 | mprotect 账本（服务 fork 恢复） | 运行期 mprotect 记账（地址段 → prot），fork 恢复按「映像段 + 账本」收敛——与 M4 共享段直接相关。**即使它不是 UD1 根因也要做**（快照语义正确性） |
| T3.3 | `sh -c 'echo hello | wc -c'` 入 CI | 失败即红 |
| T3.4 | 再加 3 条脚本 | `sh -c 'echo $?'`、`a=b; echo $a`、`echo x > t && cat t`（`--root` 临时目录） |
| T3.5 | `utimensat` | Windows `SetFileTime`（atime/mtime；ctime 无对应——诚实标注） |
| T3.6 | SIGCHLD 记账 | wait 回收后置位；不投递 handler；ash job control off 够用 |
| T3.7 | `poll`/`select` 仅 pipe+stdin | 可选；做不完标实验不挡发版 |

决策点 1（二选一，PLAN-0.0.6 的降级承诺在此收口）：ash 修好（T3.3 绿）
**或** 正式砍 interactive/ash——NONGOALS 写明「shell 不在支持矩阵，
applet + fork-test 仍是承诺」。不许第三种。

### M4 — fork / execve 减重

| # | 任务 | 要点 |
|---|---|---|
| T4.1 | 映像只读段共享 | RX 段装载后未被写 → fork 不 memcpy，直接共享同一 section；数据段/堆/栈照旧拷贝（先求正确） |
| T4.2 | 堆栈拷贝保持 | 同 T4.1 |
| T4.3 | 脏页（目标） | **`GetWriteWatch`**（Windows 现成 API，MEM_WRITE_WATCH）——比手写写监视便宜一个量级；只拷写过的堆/文件视图页；doctor 打 `copied_kib` |
| T4.4 | HostDir 游标 | 走已有 `clone_remaining`，禁止重置（0.0.6 已实现，验收锁定） |
| T4.5 | execve 债可见 | `decommit` + 延迟 unmap；不能 Free 的 Reserve 计入 doctor「reserve leak」字节 |
| T4.6 | fork bench | 全量 vs 共享映像两列（T0.2 方法论） |

降级：T4.3 做不完仍可发 0.1；T4.1 + T4.4 + T4.5 建议当 DoD 硬项。

### M5 — 产品与工程

| # | 任务 | 要点 |
|---|---|---|
| T5.1 | dispatch 拆分 | `syscalls/{file,mem,proc,time,stub}.rs`；`every_dispatched_syscall_has_a_name` 测试保留 |
| T5.2 | doctor 2.0 | 宿主=Windows；陷阱后端（island/veh + site 计数）；FSGSBASE / soft-tls 生效状态；guest 清单；杀毒提示；reserve leak；copied_kib |
| T5.3 | Ctrl+C | 确认控制台默认传播 + kill 遗留子进程树；**不假装 SIGINT handler** |
| T5.4 | 路径边界 | 长路径 `\\?\`、非 ASCII `--root` 各一条手工清单（CI 可选） |
| T5.5 | guest 减重 | 大 ELF（ld-musl）评估 CI 生成 vs 入库；README 用 mkhello/mkguest |
| T5.6 | Release | 仍只出 Windows zip + sha256；notes 用 DoD 清单 |
| T5.7 | SECURITY | 「不是沙箱」+ 分发/SmartScreen/杀软排除目录指引 |

CI 继续只跑 Windows。**不为「大规模」加 macos job 编译空壳。**

### M6 — 预留（刻意做小）

| # | 任务 | 要点 |
|---|---|---|
| T6.1 | HOST.md | Trap/Proc 方法表；注明「目前唯一实现：windows」 |
| T6.2 | NONGOALS / README | 「SpadaOS Host 真实现 / macOS / 第二宿主跑 guest」列预留，不列 0.1 成功标准 |
| T6.3 | 禁止 | 不为尚未存在的内核设计 map 语义；不填 SpadaOsHost 假时钟/假文件 |

## 3. 开工顺序

```
M0 基线 → M1 契约收口 → M2 岛页+宿主栈
                ↘ M3 ash（依赖 M1；prot 账本依赖 M3.2）
                ↘ M4 fork 减重（T4.1 依赖 M1；可与 M2 后半并行）
         → M5 拆分/doctor/发布 → M6 文档预留
```

优先级共识：M1 → M3 优先（对叙事收益最大）；M2 是最大技术风险，允许
按 DoD 4 降级为实验 flag；M4 体验项。不要先加 20 个 syscall。

## 4. 决策点

1. **ash**：修好（T3.3 绿）或正式砍（NONGOALS 声明）。二选一，无第三态。
2. **岛页默认化**：CI 全绿 + bench 数据到手后，由「混合模式下 veh_site
   占比」决定——>20% 点位配不上岛则默认仍 veh，island 仅 flag。
3. **fs heal**：CI 连续 20 次动态 musl 无内核还原证据 → 降频；否则全量
   保留（正确性 > 性能）。

## 5. 诚实边界（发版写进 NONGOALS/SYSCALLS）

- 唯一支持宿主：Windows x86_64。SpadaOS/macOS 仅契约预留
- 信号投递仍不做：kill = 终止语义；SIGCHLD 仅记账
- fork：映像只读共享 + 堆栈全拷（脏页若落地则按 GetWriteWatch）；
  mprotect 账本恢复；HostDir 游标保持
- MAP_SHARED 文件仍 ENOSYS（匿名共享仅服务 fork 内部）
- 岛页模式下 VEH 仍是后备路径（混合模式是预期形态，不是降级）

## 6. 风险表

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| 岛页 patch 的指令安全校验漏跳转目标 → 偶发执行流错乱 | 中 | 高 | T2.1 线性扫描全部跳转范围 + 混合模式兜底（校验不过留 VEH）+ `--trap=veh` 一键回退 |
| 岛页 × fork 联动漏做 → 子进程秒崩 | 中 | 高 | T2.7 列为 M2 必做；fork-test 是现成回归闸 |
| fs heal 删除引发 TLS 偶发崩（0.0.4 历史问题回归） | 中 | 高 | T2.5 保守降频 + 连续 20 次验证门槛 |
| ash UD1 为 musl/编译器层问题，vela 侧不可修 | 低 | 中 | 决策点 1 正式砍 ash（NONGOALS），applet + fork-test 仍是承诺 |
| GetWriteWatch 在某些内存形态不可用 | 低 | 低 | 退回全量拷贝（T4.2 本来就是正确性基线） |
| dispatch 接口重构破坏 VEH 现有语义 | 低 | 中 | M1 验收「字节级输出不变」+ 全量测试先行 |
