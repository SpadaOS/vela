# Vela 0.0.3 计划 — 性能、广度、SpadaOS 就绪

> 状态：草案 v1（2026-09-19）
> 前置：v0.0.2（`052bade`）已交付 musl 文件 IO 全链路、路径映射表、健壮性三件套
> 用户目标：① 项目更专业、目录架构优化、为接入 SpadaOS 铺路 ② Windows 上 syscall 覆盖再扩大 ③ 算法/函数优化，跑得更快

## 0. 版本主题与 Definition of Done

**主题：让 Vela 从"能用"走向"专业"——数据驱动的性能优化、syscall 广度翻倍、Host 抽象按组治理。**

**验收口径（全部满足才发版）：**

1. **性能有数字**：新增 bench guest，发布 CHANGELOG 附 0.0.2 基线 vs 0.0.3 对比表；纯翻译类 syscall（getpid）单次往返进入 **≤ 1.5 µs** 区间（VEH 架构固有成本主导，先测基线再定死目标）
2. **syscall 矩阵扩容**：新增 ≥ 15 个号（文件写路径 / access / pread/pwrite / dup 系 / statx / musl 启动兜底 stub），全部有 dispatch 单测
3. **SpadaOS 就绪**：`Host` 按 [HOST.md](../HOST.md) 的 map/file/time/thread/futex 五组拆分为 supertrait；`spadaos.rs` 每组有 TODO 骨架与内核能力映射文档
4. **专业度**：`cargo clippy --workspace -D warnings` 与 `cargo fmt --check` 进 CI 且全绿；crate 元数据齐备；abi crate 模块化
5. 常规：61+ 测试全绿、CHANGELOG、tag v0.0.3 + GitHub Release

## 1. M1 — 性能工程（基准先行，数据驱动）

> 背景：Vela 的 syscall 路径 = 客户 UD2 → 内核异常分发 → VEH → dispatch → NtContinue 返回。
> 内核往返是架构固有成本（µs 级），WSL1 走内核 pico provider 也无法免除翻译成本。
> 我们能优化的是 **用户态 dispatch 热路径** 的每一次分支、每一笔分配。

| # | 任务 | 要点 | 验收 |
|---|---|---|---|
| T1.1 | **bench guest + 基线** | `vela-mkguest` 新增 `bench` 变体：clock_gettime 围绕 `N=100万` 次 getpid（纯翻译）与 write→Null（含 IO）循环，客户侧输出 ns/op；`vela run guest/bench` 直接读数。**先跑 0.0.2 基线存档** | 基线数字进 CHANGELOG 与 docs/bench.md |
| T1.2 | **dispatch 分发表** | 现状 dispatch 是 300+ 行稀疏 match（LLVM 编译为二分+跳转混合）。改为 `static DISPATCH: [Handler; 512]`（编译期初始化函数指针表，高频号 O(1) 直调），>512 号回退 match 尾部 | bench 对比：getpid 路径可测收益 |
| T1.3 | **VEH exec_ranges 查找** | 32 槽 AtomicU64 对每对 load+比较。改：start 有序登记 + 找到即停（现状是全扫）+ 常用段前置（loader 按地址排序注入） | bench 对比；汇编检查热循环 |
| T1.4 | **热路径去分配** | ① getdents64 每条 `vec![0u8; reclen]` → 复用栈上缓冲 ② `FsMap::translate` 每次 `split` 产生 Vec<String> → 改零分配组件迭代（PathBuf 输出仍需一次分配，可接受）③ build_envp/路径拼接无回归 | bench：文件类 syscall 路径改善 |
| T1.5 | **fs 自愈成本复核** | 每次 syscall 返回的 rdfsbase 自愈校验是 FSGSBASE 机器上的固定 3 指令；确认无退化，写进 bench 备注即可 | 文档记录 |

**出口**：docs/bench.md 前后对比表；优化项全部"bench 驱动"——无数字收益的改动不合并（防止为优化而优化）。

## 2. M2 — syscall 广度（Windows 上全部可做）

| # | 任务 | 号 | 要点 |
|---|---|---|---|
| T2.1 | **文件写路径** | mkdir(83) rmdir(84) unlink(87) unlinkat(263) rename(82) renameat(264) | std::fs 一一对应（create_dir/remove_file/rename）；v0.2 的 file-io guest 只能创建不能删，此组补齐生命周期 |
| T2.2 | **access 族** | access(21) faccessat(269) | HostPath 元数据判 R/W（readonly 位）；F_OK/R_OK/W_OK，X_OK 恒按目录/文件推断 |
| T2.3 | **定位读写** | pread64(17) pwrite64(18) fsync(74) fdatasync(75) | Windows std 无 pread：单线程模型下 seek→io→seek-back 可安全实现；sync_all/sync_data 直映 |
| T2.4 | **fd 复制** | dup(32) dup2(33) dup3(292) + fcntl F_DUPFD(0)/F_DUPFD_CLOEXEC(1030) | `Host` trait 加 `dup_file(&HostFile)`（Windows `try_clone`/`DuplicateHandle`）；fd 表克隆条目与标志 |
| T2.5 | **statx(332)** | 332 | 现代进程统计信息路径（glibc 必经，为未来铺路）：`HostStat` 字段已齐，组 `statx` 116B 结构 + mask 语义 |
| T2.6 | **musl/busybox 启动兜底 stub** | rt_sigaction(13) rt_sigprocmask(14) madvise(28) prlimit64(302) getrusage(98) | 诚实 stub：记录后返回 0/填充合理默认（与 set_robust_list 同模式）；信号**投递**仍 NONGOAL |
| T2.7 | **clock 扩展** | clock_gettime 支持 CLOCK_MONOTONIC_RAW(4) / BOOTTIME(7) | 映射到 host.monotonic_ns |

**明确不做（延续 NONGOALS）**：pipe2（无 fork 的单进程里语义失真 → **推迟到 0.0.4 与 fork/exec 议题一起决策**）、socket/epoll、clone/futex、信号投递、execve、动态链接。

**出口**：SYSCALLS.md 从 34 号扩到 ~50 号；file-io guest 升级 v2 覆盖 mkdir/unlink/rename/pread/pwrite/dup。

## 3. M3 — SpadaOS 就绪 + 架构专业化

| # | 任务 | 要点 |
|---|---|---|
| T3.1 | **Host trait 五组拆分（supertrait）** | 按现有 HOST.md 约定拆：`HostMem`（map/protect/unmap）、`HostFile`（open/open_dir/read/write/seek/stat/dup…）、`HostTime`（monotonic/realtime）、`HostRng`（random）、`HostTls`（set_fs_base）；`Host: HostMem + HostFile + HostTime + HostRng + HostTls` 持 thread/futex/process_exit。runtime 只依赖它用到的最小组；SpadaOS 实现者逐组填 |
| T3.2 | **spadaos.rs 骨架升级** | 每组一段 TODO 骨架 + 「SpadaOS 内核能力 ↔ Host 方法」映射表文档（capability/file/time/thread/futex 对应关系），接口面完全冻结 |
| T3.3 | **vela-abi 模块化** | 260 行单文件拆 `{syscall, errno, auxv, structs, mmap, open_flags}.rs` + lib.rs re-export（保持调用方零改动）；纯专业度/导航性 |
| T3.4 | **crate 元数据 + workspace lints** | 各 crate Cargo.toml 补 `description/license/readme`；`[workspace.lints]` 统一 rust/clippy 规则；修掉存量警告（如 windows.rs 的 function-cast） |
| T3.5 | **质量门进 CI** | `cargo fmt --check` + `cargo clippy --workspace -D warnings` 两步前置（在 build 之前，快速失败） |
| T3.6 | **guest 产物归位 guest/bin/** | 预编译 ELF 与源码分离（src/ 与产物混放不专业）；同步改 CI/doctor/run_hello 路径，一次性 PR |
| T3.7 | **文档架构** | README 工程结构图更新（反映 guest/bin、五组 Host、docs 全景）；HOST.md 重写为五组契约 |

**出口**：新 SpadaOS 实现者只需读 HOST.md 五组契约即可开工；clippy 零警告成为常态。

## 4. M4 — 收尾

- T4.1 file-io guest v2（覆盖 M2 新 syscall）+ bench guest 入库
- T4.2 SYSCALLS.md / CHANGELOG / 版本 0.0.3 / tag / Release（附 vela.exe + bench 对比表）

## 5. 依赖与顺序

```
T1.1 bench 基线（先行，冻结 0.0.2 数字）
  └→ T1.2/T1.3/T1.4（每项独立 bench 验证）
M2 各任务互相独立，可穿插
T3.1 supertrait 拆分先行 → T3.2 骨架 / T3.4 lints / T3.5 CI / T3.6 guest 归位
T4 收尾
```

建议节奏：每个 T 一个 commit；M1 出口打 `v0.0.3-alpha.1`（bench 表公布）。

## 6. 风险

| 风险 | 等级 | 对策 |
|---|---|---|
| VEH 固有成本占主导，用户态优化收益有限 | 中 | bench 先行；目标定为"可测得的改善 + 数字公开"，不拍胸脯倍数 |
| supertrait 拆分触发大范围 impl 重写 | 中 | 机械式改动（impl 块按组搬移）；61 测试护航；一次 PR 完成不拆散 |
| Windows 无 pread，seek-back 实现若引入并发会出错 | 低 | v0.x 单线程模型写进契约注释；HostFile 单所有权 |
| guest/bin 移动漏改路径 | 低 | grep 全仓路径引用 + CI 全绿验证 |
| chmod/fchmod Windows 语义单薄 | 低 | 0.0.3 不做，SYSCALLS.md 标注 |

## 7. 决策点（按推荐执行，除非另有指示）

1. **pipe2**：推荐 0.0.3 不做，0.0.4 与 fork/exec 一起设计（单进程无 fork 时管道语义失真）
2. **guest 产物移 `guest/bin/`**：推荐做（一次性同步 CI/doctor/测试路径）
3. **Host 分组粒度**：推荐按 HOST.md 既有五组（map/file/time/thread/futex），RNG 并入 time 组为 `HostTime`（时间与熵同属"宿主环境"）
4. **性能目标**：先测 0.0.2 基线再定硬指标；M1 出口只承诺"可测量改善且数字公开"

## 附录 — 调研依据

- musl x86_64 的 stat/fstat 包装走 newfstatat/fstat 传统号（man-pages 确认），0.0.2 已覆盖；statx 为 glibc/新内核路径预留 → T2.5 定位为"面向未来"
- WSL1 以内核 pico provider 做翻译仍承担往返成本；Vela 的用户态 VEH 架构优化空间在 dispatch 热路径（分发表、去分配、查找提前退出）——T1 系任务全部 bench 驱动
- busybox 静态版启动触碰 rt_sigaction/rt_sigprocmask/prlimit64 → T2.6 为 0.0.4 busybox 目标提前清障
