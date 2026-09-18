# HOST 契约

`vela-sys::Host` 是 runtime 与宿主之间的唯一边界（规格 2.4）：

- runtime **禁止** `#[cfg(target_os)]` 与任何 Windows/SpadaOS 类型。
- 路径在进入 Host 之前已由 vela-fs 翻译成宿主原生路径。
- 客户虚拟地址空间由 runtime/loader 管理，Host 只按请求 map/protect/unmap。
- `map` 返回的匿名内存必须零填充；Windows 实现初始 RW，随后由 runtime 显式
  `protect` 收敛（W^X）。
- `unmap` 在 Windows 上只能整块释放 reserve 基址；runtime 的 munmap 账本已按
  此假设设计（只移除完全覆盖的登记项）。

## 实现清单

| 宿主 | 状态 | 说明 |
|---|---|---|
| windows | v0 完整实现 | VirtualAlloc/VirtualProtect/VirtualFree、std 文件与控制台、RtlGenRandom、VEH 陷阱 |
| linux_dev | 逻辑测试壳 | 分配器模拟 map，仅供 loader/runtime 单元逻辑（真实执行客户 ELF 必须在 Windows） |
| spadaos | 空壳 | 只保证编译通过，调用即 `Unimplemented`；未来把 map/file/time/thread/futex 五组填满 |

## 未来扩展（v0 只预留接口，不实现，规格 13）

- `Host` 增加 `unix_bind` / `anon_shm` 以接外部 X server（第一代 GUI = 外部
  Windows X server + Vela 只提供通路；不要把网络设计死成只能 TCP）
- `thread_create` / `futex_wait` / `futex_wake`（clone 仅
  `CLONE_VM|CLONE_FILES|CLONE_SETTLS` 当线程用）
