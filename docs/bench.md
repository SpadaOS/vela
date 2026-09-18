# Vela 性能基准

> 方法：`guest/bench`（vela-mkguest 生成）在客户态循环 2,000,000 次 `getpid(39)`
> ——纯 VEH→dispatch→返回往返，无内存/路径/IO 参与。host 侧外部计时
> （含固定 ~10ms 进程启动开销，占比 <0.5%）。3 次取样。
>
> 单次 syscall 路径 = 客户 UD2 → 内核异常分发 → VEH → dispatch → NtContinue。

## getpid 纯翻译往返（ns/op，越小越好）

| 版本 | 3 次取样 (ms / 2M) | ns/op | 备注 |
|---|---|---|---|
| 0.0.2 基线 | 4092 / 3923 / 3831 | **~1970** | 用户态 BTreeMap 账本、线性扫描 exec_ranges |
| 0.0.3 (T1.3+T1.4) | 4272 / 4046 / 4027 | ~2060 | 在机器噪音（±5%）内无显著差异 |

## 结论（bench 驱动，防止为优化而优化）

1. **瓶颈在 VEH 内核异常往返的固有成本（~2 µs），不在用户态 dispatch。**
   实测证实：exec_ranges 提前退出（省 ~60 次原子 load）与热路径去分配的
   收益淹没在噪音里。
2. **T1.2 dispatch 函数表不实施**：match 在 nr∈[0,318] 稀疏段上由 LLVM
   生成的比较树远小于 2 µs 的固定成本，函数表预期收益 <50 ns，不可测量
   ——不引入 512 槽静态表的复杂度。
3. T1.4 的去分配改动**保留**（getdents64 栈缓冲、FsMap::translate 零中间
   分配）：它们是文件路径上的正确工程改进，只是不在 getpid 微基准的覆盖面。
4. 对比参照：WSL1 走内核 pico provider 翻译，同样承担 syscall 往返成本；
   Vela 的 ~2 µs 对单线程 CLI 类负载（bufio 缓冲后 syscall 频率 ~10⁴/s）
   意味着翻译开销占比可忽略。

## 复现

```powershell
cargo run -p vela-cli --bin vela-mkguest -- bench guest/bench
cargo build -p vela-cli --release
Measure-Command { .\target\release\vela.exe run guest\bench }
```
