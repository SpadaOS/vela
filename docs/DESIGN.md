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
- **自愈机制（musl 实测必需）**：内核在某些转换路径会把用户 fs 基址恢复为旧值
  （表现为 musl 退出路径的 canary 检查偶发 fs=0 访问违例）。每次 syscall 返回时
  `rdfsbase` 校验当前基址，与 `proc.fs_base` 不符就再跳一次 trampoline 重设。
- **三重防护**：进入客户前用已映射的堆页预切 FS（内核从未见过宿主基址）→
  arch_prctl 后由 trampoline 改为真实 TLS 区 → 每次 syscall 返回自愈校验。
  本地 musl hello 300+ 次零失败；CI 机器上仍有 ≤2% 概率的极端时序命中
  （崩溃于 `__init_tp`/canary 的 fs 访问，两个 syscall 之间无自愈触发点），
  musl 集成测试因此允许 3 次重试。彻底修复需软件级 FS 保存/恢复（v0.1 评估）。
- `SYS_SET_TID_ADDRESS` 在 x86_64 上是 **218**（初版误写 249，musl 启动会调用）。

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
- `mmap` 仅匿名私有；`MAP_FIXED` 冲突返回 -ENOMEM。
- fstat/stat 未实现（-ENOSYS），musl 静态 hello 不需要。
- VEH 处理器在客户栈上执行（见上文 red zone 风险）。
