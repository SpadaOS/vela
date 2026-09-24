# Vela 性能基准

> 方法（PLAN-0.1.0 T0.2 定稿）：`guest/bench`（vela-mkguest 生成）在客户态
> 循环 2,000,000 次 `getpid(39)`——纯陷阱→dispatch→返回往返，无内存/路径/IO
> 参与。host 侧外部计时（含固定 ~10ms 进程启动开销，占比 <0.5%）。
> **5 次取样取中位数**（0.0.6 的 3 次取样曾出 8.9s/11.1s 差 25% 的废数据）。
> 有条件时**先钉 CPU 亲和再跑**（cmd：`start /AFFINITY 1 /B vela.exe run ...`）；
> 本机工具宿主限制无法设亲和的取样已在表中如实标注。
>
> 单次 syscall 路径（0.1.0 前为 VEH 后端）= 客户 UD2 → 内核异常分发 →
> VEH → dispatch → NtContinue；0.1.0 起新增岛页跳板对照列。

## getpid 纯翻译往返（ns/op，越小越好）

| 版本 | 取样 (ms / 2M) | ns/op | 备注 |
|---|---|---|---|
| 0.0.2 基线 | 4092 / 3923 / 3831 | **~1970** | 用户态 BTreeMap 账本、线性扫描 exec_ranges |
| 0.0.3 (T1.3+T1.4) | 4272 / 4046 / 4027 | ~2060 | 在机器噪音（±5%）内无显著差异 |
| 0.0.6 | 8862 / 11122 | ⚠ 废数据 | 本机负载噪音（run1/run2 差 25%），「显著高于 0.0.3」的结论**不成立**——0.0.4-0.0.5 热路径新增（fs heal、fork 分支）量级 <100ns，不足以解释 2x；教训：无钉核+中位数的取样不可作版本对比 |
| **0.1.0 基线（VEH）** | 4984 / 4556 / 5275 / 4617 / 4468 | **~2309** | 中位数 4617ms；同机 5 次无钉核（工具宿主限制）；与 0.0.3 基线 ±12% 内一致，佐证 0.0.6 的 2x 系噪音。M2 岛页跳板完成后以同法补 island 列 |

## fork 往返（0.0.6 新增；0.1.0 基线入表）

fork+exit+waitpid 全链路（fork-test guest，--soft-tls）：

| 版本 | 取样 (ms) | 中位数 | 备注 |
|---|---|---|---|
| 0.1.0 基线 | 81 / 70 / 77 / 71 / 79 | **77** | 全量 ~24MB 快照 + 子进程重建 + waitpid 单次往返；体感即时。M4 只读段共享完成后同法对照 |

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
