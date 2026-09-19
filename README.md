<div align="center">

# Vela

**在 Windows 用户态运行未经修改的 Linux x86_64 程序**

一个 `vela.exe` 进程 = 一个 Linux 进程<br>
不改内核 · 不用虚拟机 · 零第三方依赖 · 单文件交付

[![CI](https://github.com/SpadaOS/vela/actions/workflows/ci.yml/badge.svg)](https://github.com/SpadaOS/vela/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/SpadaOS/vela)](https://github.com/SpadaOS/vela/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[快速开始](#快速开始) · [能力矩阵](#能力矩阵) · [工作原理](#工作原理) · [文档](#文档)

</div>

---

Vela 是一个纯用户态的 **Linux ELF 翻译运行时**：加载未经修改的 Linux x86_64
程序，在加载期把 `syscall` 指令改写为陷阱，由 VEH 拦截后把 Linux 语义逐条
翻译到宿主 API。Vela 隶属 [SpadaOS](https://github.com/SpadaOS)——SpadaOS 的
ABI 自主演进、不在内核里做 Linux 兼容，Linux 软件通过 Vela 这个独立运行时
进入系统；Windows 是当前主宿主，接入 SpadaOS 只需实现 `Host` trait
（[docs/HOST.md](docs/HOST.md)）。

```text
     unmodified Linux ELF (asm / static musl / dynamic musl / busybox)
                           |
                           v
   .------------------------------------------------------.
   |  vela.exe   one host process = one Linux process     |
   |                                                      |
   |  loader    ELF parse, map, patch 0F 05 -> 0F 0B      |
   |  runtime   VEH trap -> dispatch -> Linux semantics   |
   |  vela-fs   path map: /lib/... -> C:\...              |
   |  vela-sys  Host trait = Windows API                  |
   '------------------------------------------------------'
                           |
                           v
          Windows user mode (no kernel change, no VM)
```

## 快速开始

零第三方依赖，任何能装 Rust 的机器都能完整构建：

```powershell
git clone https://github.com/SpadaOS/vela
cd vela
cargo build -p vela-cli --release
```

三条最有代表性的命令——汇编 hello、动态链接 musl、宿主管道组合：

```powershell
# 1. 无 libc 汇编 hello（183 字节静态 PIE）
.\target\release\vela.exe run guest\bin\hello
# hello from linux elf

# 2. 动态链接：ld-musl 解释器做重定位，musl 运行时 + TLS
.\target\release\vela.exe run --soft-tls guest\bin\hello-dyn
# hello from musl

# 3. 两个 vela 进程用 PowerShell 宿主管道组合
.\target\release\vela.exe run guest\bin\pipe-a | .\target\release\vela.exe run guest\bin\pipe-b
# pipe-b ok: 29 bytes, 3 lines
```

> [!TIP]
> `--soft-tls` 在 **FSGSBASE 缺失**的环境（Hyper-V / 多数云虚拟机）必须开启：
> Vela 会用 VEH 软件模拟客户 fs 段访问。裸机/支持 FSGSBASE 的机器不需要。
> 用 `vela doctor` 检查你的环境。

更多命令——文件 IO 全链路、execve 自重载、**用户态 fork**、busybox
shell（CI 现场构建，本地复现见 [tools/build-busybox.sh](tools/build-busybox.sh)）：

```powershell
.\target\release\vela.exe run --soft-tls guest\bin\file-io     # 文件 syscall 全链路
.\target\release\vela.exe run --soft-tls guest\bin\fs-exec     # pipe -> dup2 -> execve 自重载
.\target\release\vela.exe run --soft-tls guest\bin\fork-test   # fork -> 管道 -> waitpid
.\target\release\vela.exe run --soft-tls guest\bin\busybox sh -c "echo hello | wc -c"
# 6

.\target\release\vela.exe doctor    # 环境自检：FSGSBASE / 映射 / guest 清单
```

## 能力矩阵

v0.0.6 实测（CI 在 Windows runner 上自动验收全部 ✅ 项）：

| 能力 | 状态 | 说明 |
|---|:---:|---|
| 无 libc 汇编程序 | ✅ | 任何 Linux x86_64 静态 PIE |
| 静态 musl C 程序 | ✅ | 文件 IO 全链路（stat/getdents64/fcntl） |
| **动态链接** | ✅ | `ld-musl` 解释器全权重定位（0.0.4 起）；glibc 诚实拒绝 |
| **busybox 子集** | ✅ | echo/ls/cat/true/false/nproc/env/printf（0.0.5 起） |
| **用户态 fork** | ✅ | fork+waitpid 全语义：子进程从返回点继续、独立 pid、fd 继承（0.0.6 起） |
| **busybox shell** | ✅ | ash：`sh -c` 管道/重定向/变量/xargs（0.0.6 起） |
| mmap | ✅ | 匿名 + 文件映射（COW，写不回宿主文件） |
| **execve** | ✅ | 进程内重载，fd 跨重载保留；pipe2 管道 |
| TLS | ✅ | FSGSBASE 硬件路径，缺失时 `--soft-tls` 软件模拟 |
| 时间 / 熵 / 进程身份 | ✅ | clock/getrandom/uname/auxv 完整 |
| fork / 信号投递 | 🟨 | fork ✅（0.0.6 用户态快照实现）；信号投递 ❌（kill SIGKILL/SIGTERM 可用） |
| socket / epoll / GUI | ❌ | 返回 `-ENOSYS`，libc 有降级路径 |
| Go 程序 / 32 位 / ARM | ❌ | 见 [docs/NONGOALS.md](docs/NONGOALS.md) |

未实现的 syscall 一律返回 Linux 风格 `-ENOSYS`——行为可预期，而不是崩溃。
逐条兼容矩阵（约 60 条）见 [docs/SYSCALLS.md](docs/SYSCALLS.md)。

## 和 WSL 的区别

| | WSL1 | WSL2 | Vela |
|---|---|---|---|
| 机制 | NT 内核 pico driver | 轻量 VM + 真 Linux 内核 | 纯用户态翻译 |
| 改宿主内核 | 要 | 要 Hyper-V | **不要** |
| 兼容上限 | 中 | 高 | 低（诚实承认） |
| 单文件分发 | 否 | 否 | **是**（一个 exe） |
| 可移植到自主 OS | 否 | 否 | **是**（实现 `Host` trait 即可） |

Vela 的定位不是替代 WSL，而是给 **SpadaOS** 这类自主内核 OS 提供一条
不动内核的 Linux 生态接入路径，顺带让 Windows 获得一个零安装的 Linux
二进制启动器。

## 工作原理

1. **patch**：loader 解析 ELF 后，把代码段里所有 `syscall`（`0F 05`）改写为
   `UD2`（`0F 0B`）。
2. **陷阱**：客户执行到 `UD2` 触发异常，Vela 注册的 VEH 捕获，取出原始
   `syscall` 号与六个参数。
3. **翻译**：`vela-runtime::dispatch` 按 Linux 语义执行——路径交给
   `vela-fs` 翻译，文件/内存/时钟操作落到 `vela-sys` 的 `Host` trait。
4. **返回**：结果按 Linux ABI 写回寄存器，`NtContinue` 回到客户。

安全边界、COW 文件映射、软 TLS、execve 重载的实现细节与决策记录：
[docs/DESIGN.md](docs/DESIGN.md)。

## CLI 速查

```text
vela run [options] <linux-elf> [guest-args...]
vela doctor                          环境自检
vela --version | --help
```

| 选项 | 说明 |
|---|---|
| `--root <dir>` | 把宿主目录挂为客户根 `/` |
| `--map <g>=<host>` | 追加前缀映射（默认 `/mnt/c` → `C:\`） |
| `--env K=V` | 传递/覆盖环境变量；`K=` 表示删除 |
| `--uid <n>` / `--gid <n>` | 客户身份（默认 1000） |
| `--interp <path>` | 显式指定动态链接解释器 |
| `--stack-mb` / `--heap-mb` | 客户栈/堆大小（默认各 8 MiB） |
| `--soft-tls` | 软件模拟客户 fs 段（FSGSBASE 缺失环境） |
| `-v` / `VELA_LOG=1` | syscall 日志到 stderr（默认安静，只放行客户 stdout） |

退出码：客户 `exit` 的码；文件缺失 127；ELF 格式错误 1；用法错误 2。

## 测试与 CI

```powershell
.\scripts\verify.ps1        # 一键：构建 + 测试 + guest 验收（Windows）
cargo test --workspace      # 或仅测试
```

覆盖：ELF 解析与拒绝路径、syscall patch、dispatch 语义翻译、路径翻译、
soft-tls 解码表驱动回归，以及端到端验收（hello / torture / hello-dyn /
fs-exec / pipe 对 / busybox echo·nproc·true）。CI 在 Windows runner 上执行
同一流程并现场构建 busybox（msys2 make + zig cc musl）。

## 项目结构

```text
crates/
  vela-abi       Linux x86_64 ABI：syscall 号、errno、结构体（10 个子模块）
  vela-sys       Host trait + Windows / linux_dev 实现 + VEH 陷阱 + soft-tls
  vela-loader    ELF64 解析校验、加载、syscall patch
  vela-runtime   GuestProcess 与 dispatch：Linux 语义 -> Host 调用
  vela-fs        Linux 路径 -> 宿主原生路径翻译
  vela-cli       CLI + execve 重载编排 + guest 生成器
guest/           验收用 Linux ELF（源码 + 产物；busybox 由 CI 构建）
tools/           busybox 构建脚本
docs/            DESIGN / SYSCALLS / NONGOALS / HOST / bench / plans
scripts/         verify.ps1 / verify.sh
.github/         CI（Windows runner）
```

依赖方向单向：`cli -> loader -> runtime -> fs`，宿主差异全部收敛在
`vela-sys`；runtime 以上禁止 `cfg(target_os)`。

## 安全

> [!WARNING]
> Vela is not a security sandbox. Guest code shares the host process.

Linux 程序与 `vela.exe` 同进程、同权限，可访问用户能访问的一切，不要把
Vela 当沙箱用。杀毒软件可能对"进程内改可执行内存再执行"敏感：开发时若
被拦，给 `vela.exe` 加排除（Vela 不做任何加壳混淆）。漏洞报告流程见
[SECURITY.md](SECURITY.md)。

## 参与

提交信息遵循 [Conventional Commits](CONTRIBUTING.md)。核心规则：

- 主路径在 Windows 上验收（syscall patch + VEH 是 Windows 专属机制）。
- 没有 Windows 也能贡献：ELF 解析器、vela-abi、单元测试可 linux dev 构建。
- 提交前跑 `.\scripts\verify.ps1`；代码标识符全英文；宿主差异只进 vela-sys。
- 零第三方依赖是 v0 硬约束，新增依赖先开 issue。

## 路线

- **v0.0.6（当前）**：多进程之门——用户态 fork + wait4 真实化 + kill
  最小集 + busybox ash shell 解锁 + Release 挂产物
- v0.0.7 候选：fork 脏页快照优化、MAP_SHARED、信号投递地基（SIGCHLD/
  handler 帧）、utimensat
- v1：SpadaOS `Host` 填满（map/file/time/thread/futex 五组）、外部 X server
  通路

版本计划与历史决策：[docs/plans/](docs/plans/)、[docs/DESIGN.md](docs/DESIGN.md)。

## 许可

Apache-2.0（兼容层许可与 SpadaOS 内核许可分离，见 [LICENSE](LICENSE)）。
