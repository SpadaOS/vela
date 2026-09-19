# HOST 契约（五组，SpadaOS 就绪）

`vela-sys` 是 runtime 与宿主之间的唯一边界（规格 2.4）。0.0.3 起 `Host`
按 SpadaOS 内核能力拆为 **五组 supertrait**（PLAN-0.0.3 T3.1）：

```
Host = HostMem + HostFileOps + HostTime + HostTls
     + thread_exit / process_exit / thread_create(桩) / futex_wait/futex_wake(桩)
```

runtime 及以上禁止 `#[cfg(target_os)]` 与任何宿主类型；路径在进入 Host
之前已由 vela-fs 翻译成宿主原生路径；客户虚拟地址空间由 runtime/loader
管理，Host 只按请求 map/protect/unmap。

## 五组契约

| 组 | trait | 方法 | SpadaOS 内核能力对应 |
|---|---|---|---|
| map | `HostMem` | `map` / `protect` / `unmap`；0.0.4 起 `map_file` / `unmap_view` / `decommit` | 地址空间：匿名映射、W^X 收敛、整块释放；文件映射（Windows 走 `CreateFileMappingW` COW，写不回宿主文件） |
| file | `HostFileOps` | `open` `open_dir` `mkdir` `remove` `rename` `sync_file` `dup_file` `read` `write` `seek` `stat_path` `stat_file` `close` `stdio` | VFS：文件/目录 CRUD、元数据、句柄复制 |
| time | `HostTime` | `monotonic_ns` / `realtime` / `random` | 时钟：单调钟/实时钟；熵源 |
| thread | `HostTls` + `Host::thread_*` | `set_fs_base` / `thread_exit` / `thread_create`(桩) | TLS 寄存器切换、线程生命周期 |
| futex | `Host::futex_*` | `futex_wait`(桩) / `futex_wake`(桩) | 等待队列 |

## 关键约定

- `map` 返回的匿名内存必须零填充；Windows 实现初始 RW，随后由 runtime
  显式 `protect` 收敛（W^X）。
- `unmap` 在 Windows 上只能整块释放 reserve 基址；runtime 的 munmap 账本
  已按此假设设计（只移除完全覆盖的登记项）。
- `stat_*` 返回的 `ino/dev` 只需「同进程内稳定 + stat/getdents 一致」
  （musl 不要求真实 inode；Windows 实现用路径哈希）。
- `map_file` 的可写视图必须 COW（Windows 用 `PAGE_WRITECOPY`），客户写入
  **永不**回写宿主文件；对文件视图 `protect` 加 WRITE 会关闭 COW——
  runtime 已按此约束实现（0.0.4）。
- `set_fs_base` 需要 CPU+OS 的 FSGSBASE；不支持时 runtime 降级（仅记录），
  TLS 依赖程序无法运行——见 docs/DESIGN.md「TLS/FS」。
- pread64/pwrite64 的宿主层用 seek→io→seek-back 组合实现，依赖
  `HostFile` 单所有权（v0.x 单线程契约）。

## 实现清单

| 宿主 | 状态 | 说明 |
|---|---|---|
| windows | v0.3 完整实现 | VirtualAlloc/Protect/Free、std 文件与控制台、RtlGenRandom、VEH 陷阱 |
| linux_dev | 逻辑测试壳 | 分配器模拟 map，仅供 loader/runtime 单元逻辑（真实执行客户 ELF 必须在 Windows） |
| spadaos | 骨架 | 每组 `Unimplemented`；按上表五组逐组填满即为 SpadaOS 接入完成 |

## 未来扩展

- `Host` 增加 `unix_bind` / `anon_shm` 以接外部 X server（第一代 GUI =
  外部 Windows X server + Vela 只提供通路；不要把网络设计死成只能 TCP）
- `thread_create` / `futex_wait` / `futex_wake`（clone 仅
  `CLONE_VM|CLONE_FILES|CLONE_SETTLS` 当线程用）
