# DESIGN（从 VELA-V0-SPEC.md 精简）

## 总体数据流

```
vela.exe (PE)
 ├─ 解析 argv：vela run <elf> [args...]
 ├─ 读 ELF 字节
 ├─ vela-loader：校验 ELF64 / x86_64 / ET_DYN / 无 INTERP
 ├─ Host::map 在 0x0000_4000_0000 附近分配客户窗口（冲突则让系统自选，PIE 可接受任意基址）
 ├─ 按 PT_LOAD 拷贝段（整块 RW 映射，bss 由零填充保证）
 ├─ 扫描可执行段 0F 05 → 0F 0B（UD2）
 ├─ 按段收敛保护位（RX / RW / R，不长期 RWX）
 ├─ 建栈：argc/argv/envp/auxv（rsp%16==0，[rsp]=argc）
 ├─ 注册 fd 0/1/2 → 控制台
 ├─ 安装 VEH，保存宿主状态，切客户栈，jmp entry
 │
 客户执行 → UD2 → VEH 读 Rax/Rdi/Rsi/Rdx/R10/R8/R9
 │            → dispatch(nr, args) → 写回 Rax、Rip+=2
 │            → RCX=Rip+2、R11=EFlags（模拟硬件 syscall 副作用）
 └─ exit_group → Host 结束进程，退出码 status & 0xff
```

## syscall 拦截：UD2 + VEH（规格 16.7 已拍板）

- `0F 05` 与 `0F 0B` 等长，替换不搬指令。
- VEH 校验：EXCEPTION_ILLEGAL_INSTRUCTION + Rip 落在客户可执行映射 + Rip 处字节确为
  `0F 0B`（不吞真实非法指令）。
- Linux 第 4 参在 R10；Rip 检查用 loader 登记的 exec_ranges。
- 已知风险：VEH 处理帧压在客户 rsp 之下，可能踩 Linux 128 字节 red zone；v0
  hello 不受影响，未来可用方法 D（跳板）替换，dispatch 以上代码不动。

## 地址空间

- v0 仅静态 PIE：loader 选 2MiB/4KiB 页对齐基址 `load_bias`，所有 `p_vaddr` 加 bias。
- 堆：进程初始化时预留 8MiB 连续匿名块，`brk` 只在块内移动断点。
- 栈：8MiB 匿名块，向下增长。

## TLS/FS（v0.1 已落地，trampoline 方案）

- 启动时探测 wrfsbase：CPUID leaf7 EBX[1]（FSGSBASE）+ 一次性 VEH 保护的真实执行探测。
  支持 → 启用真切换；不支持 → `arch_prctl(SET_FS)` 仅记录并照常返回 0（规格 5.1 允许）。
- **关键实测结论**：在 VEH 处理器内直接 wrfsbase 会被 NtContinue 还原（内核保存/恢复
  异常现场的用户 FS 基址）。因此实际切换在异常完全返回后的用户态完成：
  dispatch 记录 `fs_apply_pending` → trap 改写 CONTEXT（Rip 指向 vela.exe 内的
  trampoline `wrfsbase r10; jmp rcx`，R10=新基址）→ 客户无内核参与地完成切换；
  之后的每次异常，内核保存/恢复的都已是客户基址，保持稳定。
- `guest/tls` 用「普通寻址写 marker + fs 相对读回」做决定性验证（`mmap 1t1 ok`）。
- VELA 自身代码不使用 FS（Windows x64 用户态 TEB 在 GS），切换后无需恢复。
- R10 在 trampoline 路径被借用一次（SysV caller-saved，musl syscall 包装器不依赖）。
- **TLS/FS 的硬件前提（重要）**：FS 基址切换依赖 CPU+OS 的 **FSGSBASE**（CPUID
  leaf7 EBX[1] 且 CR4.FSGSBASE 已启用）。物理机通常满足；但 Hyper-V/云虚拟机
  常因处理器兼容模式（为跨主机迁移裁剪特性集）或 VBS/HVCI 限制而**不可用**。
  不支持时 Vela 自动降级：`arch_prctl(SET_FS)` 仅记录并返回 0，依赖 TLS 的
  程序（静态 musl、glibc）无法运行并在首次 fs 访问时崩溃（诊断会给出 hint），
  无 TLS 的汇编程序不受影响——这正是规格 8.1 用无 libc hello 作 v0 门禁、
  musl hello（8.2）仅作加分项的原因。
- **三重防护（FSGSBASE 可用时）**：进入客户前用已映射的堆页预切 FS（内核从未
  见过宿主基址）→ arch_prctl 后由 trampoline 改为真实 TLS 区 → 每次 syscall
  返回 rdfsbase 自愈校验。另用被 VEH 吸收的 UD2 commit stub 强制内核按预切值
  重建保存状态，避免偶发还原到线程创建时的陈旧基址。
  本机（裸机 Server 2022）musl hello 300+ 次零失败。
- `SYS_SET_TID_ADDRESS` 在 x86_64 上是 **218**（初版误写 249，musl 启动会调用）。

## 动态加载（0.0.4）

musl 的动态执行不依赖 Vela 做重定位——`ld-musl-x86_64.so.1` 自身就是完整的
ELF 加载器。Vela 只做两件事：

1. **双映像装载**：客户 ELF 与解释器各自按静态 PIE 流程装载（各自
   span/bias，syscall patch 与保护位收敛不变）。解释器路径来自客户 ELF 的
   `PT_INTERP`，白名单 `ld-musl*`（其余诚实拒绝，不做通用 glibc 动态链接）。
2. **内核式 auxv**：`AT_BASE`=解释器 bias、`AT_PHDR/AT_ENTRY/AT_EXECFN`=
   客户侧，入口跳解释器 `_dlstart`。ld-musl 以 `AT_BASE` 推导自身基址、
   自我重定位、经 `arch_prctl(SET_FS)`/`set_tid_address` 建立线程环境，
   再按 `AT_PHDR` 重定位主程序并跳 `AT_ENTRY`。

文件映射支撑：ldso 自身的 `__map_file`（读 ELF）与 mallocng 的 brk 页
MAP_FIXED carve 都落在 M1 的文件映射 + Reserve 内就地覆盖语义上（见
SYSCALLS.md mmap 行）。解释器解析顺序：`--interp` 显式指定 > fs 映射翻译
> guest ELF 同目录同名文件回退。

## execve 重载（0.0.4）

vela 无 fork，进程内重载是 execve 的唯一诚实路径。重载在 CLI 的 trap 层
编排（loader 与栈构建都在该 crate；runtime 保持与 loader 单向依赖）：

1. 新映像先装载（失败返回 -errno，旧映像继续——Linux execve 失败语义）。
2. 成功后：清 exec-range 表 → 旧地址空间解除登记 → CLOEXEC fd 关闭
   （管道等跨重载保留）→ 重建堆/栈/auxv → TLS 状态清零（新程序需重新
   arch_prctl）→ 改写 CONTEXT 的 rip/rsp，返回后即运行新程序入口。
- **已知限制（如实记录）**：Windows 上旧 Reserve 块解除登记但不
  VirtualFree——实测对含 musl donate PROT_NONE 页的堆块 free/decommit
  会让进程在内核路径死亡（不经过 VEH、无诊断）。地址空间保留至进程退出。
- `pipe2` 与 fd 继承使重载有意义：非 CLOEXEC fd（如管道端）跨 execve 存活，
  `guest/bin/fs-exec` 端到端验证（pipe → dup2 → execve 自身 → fd 3 读取）。

## 软 TLS（--soft-tls，0.0.4 实验）

FSGSBASE 缺失（Hyper-V/云 VM/VBS）时 FS 基址无法切换，客户的 fs 前缀访问
必然 AV。`--soft-tls` 开启后 VEH 在 AV 分支软件模拟客户段内的 fs 前缀 mov：

- 解码 `64 [REX] 8b/89 modrm [sib] [disp]`：覆盖 musl 实际发射的全部形态
  （fs:0 SIB 绝对、RIP 相对、base+idx+disp、读写双向、r8-r15）；
- 有效地址 = 记录的客户 TLS 基址（arch_prctl 的 SET_FS 值，trap 时同步）
  加偏移，代为读写内存后 Rip 前进；
- 重入防护（模拟自身的访存再 AV 直接判死）、一次性慢速警告；
- 未覆盖形态仍走致命路径并输出指令字节，便于扩表。

价值：CI（Hyper-V runner）与云 VM 上的 musl 验收从"跳过"变"软跑通"
（`--soft-tls guest/bin/hello-dyn` 端到端输出问候并干净退出）。性能不承诺：
每次 fs 访问 = 一次异常往返，诊断/CI 可用，生产不可用。0.0.5 为解码表
补了表驱动回归测试（10 组合向量 + 负例），防止扩表时打坏 musl 既有形态。

## 工程地基（0.0.5）

- **exec-range 原地重注册**：`replace_guest_exec_ranges` 用前缀覆盖 + 尾部
  清零替代"clear + 重注册"，execve 重载不再受 32 静态槽累积限制。
- **mmap carve 清零**：Reserve 内 MAP_FIXED 覆盖显式清零，对齐 Linux
  "替换 = 匿名零页"语义（修掉上面"已知 v0 简化"第 2 条的前半句）。
- **abi 模块化**：vela-abi 拆 10 个子模块（syscalls/errno/mmap/open/fcntl/
  stat/statx/auxv/clock/structs），`pub use` 全量重导出保持 API 兼容；
  `every_dispatched_syscall_has_a_name` 测试锁住"名表完备"约束。
- **stdin 直通**：`GuestFd::StdIn` 走 file_ops 真实读取，`vela run pipe-a |
  vela run pipe-b` 宿主管道组合端到端可跑。
- **busybox 构建渠道**：CI 用 msys2 make + zig cc 交叉编译 busybox 1.36.1
  静态子集并验收（echo/nproc/true）。zig 0.13 Windows 工具链三处修补
  （depfile 剥离 / autoconf.h 强制生成 / GNU ld 专属链接参数中和）的
  决策记录在 `tools/build-busybox.sh` 注释。


## 依赖方向

```
vela-cli → vela-loader → vela-runtime → vela-fs
                              ↓            ↓
                          vela-abi      vela-sys
                                          ↓
                               windows | linux_dev | spadaos
```

- `LoadedImage`/`Segment` 定义在 runtime（GuestProcess 持有），loader 构造填充。
- `vela-runtime` 无 `cfg(target_os)`、无宿主类型；差异全部在 `vela-sys`。
- v0 零第三方依赖（不用 windows/goblin/bitflags crate），FFI 手写声明，降低
  构建内存与磁盘占用，并满足「无 SpadaOS 机器完整构建」。

## 已知 v0 简化

- `munmap` 只移除完全被覆盖的登记项（Windows 不能部分 VirtualFree）。
- `mmap` 无 MAP_SHARED（返回 ENOSYS）；文件映射仅限条件满足的 fd
  （offset/hint 64K 对齐，否则退化为匿名映射 + 读入）。
- execve 重载不释放旧 Reserve 块（Windows 内核路径致死，见 execve 节）。
- VEH 处理器在客户栈上执行（见上文 red zone 风险）。
