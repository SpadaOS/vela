# Vela

<p align="center">
  <strong>SpadaOS 的 Linux ELF 翻译运行时</strong><br>
  纯用户态 · 不改内核 · 单文件运行
</p>

Vela 是一个运行在宿主用户态里的 **Linux ELF 翻译运行时**：加载未修改的
Linux x86_64 静态 PIE 二进制，拦截 `syscall` 指令，把 Linux 语义翻译到宿主 API。

- Windows 上：一个 `vela.exe` 进程 = 一个 Linux 进程。客户 `syscall` 在加载期被
  patch 成 `UD2`，由 VEH 进入 Vela 的 dispatch——纯用户态，不动内核。
- 隶属 **SpadaOS** 组织。SpadaOS 的 ABI 自主演进，**不**在内核里做 Linux 兼容；
  Linux 软件通过独立用户态运行时 Vela 进入系统。Windows 是当前的主宿主，
  未来接入 SpadaOS 只需实现 `Host` trait（见 [docs/HOST.md](docs/HOST.md)）。

## 不是什么

- **不是 WSL**，也不是 WSL 替代品：

  | | WSL1 | WSL2 | Vela |
  |---|---|---|---|
  | 机制 | NT 内核驱动翻译 | 轻量 VM + 真 Linux 内核 | 纯用户态翻译 |
  | 改宿主内核 | 要 | 要 Hyper-V | **不要** |
  | 兼容上限 | 中 | 高 | 低（诚实承认） |
  | 可移植到自主 OS | 否 | 否 | **是**（Host trait） |

- **不是** SpadaOS 内核模块。
- **不是** 模拟器 / QEMU。

## 能跑什么、不能跑什么

**能跑**（v0.0.1 实测）：

- 静态 musl C 程序 / 无 libc 汇编程序的 Linux x86_64 静态 PIE（`ET_DYN`、无 `PT_INTERP`）
- 白名单 syscall：`write` / `writev` / `read` / `open` / `openat` / `close` /
  `lseek` / `mmap`(匿名) / `mprotect` / `munmap` / `brk` / `uname` /
  `arch_prctl`(TLS) / `getrandom` / `clock_gettime` / `gettimeofday` / `getpid` 等
- 客户 TLS 真正可用（wrfsbase + trampoline，见 [docs/DESIGN.md](docs/DESIGN.md)）
- 未实现 syscall 返回 Linux 风格 `-ENOSYS`

**不能跑**：

- 动态链接（glibc / `ld-musl`）、Go 程序、GUI、socket、fork/exec、32 位 / ARM
- 完整清单见 [docs/NONGOALS.md](docs/NONGOALS.md)

## 快速开始

构建（零第三方依赖，任何能装 Rust 的机器都能完整构建）：

```powershell
cargo build -p vela-cli --release
```

运行：

```powershell
# 无 libc 汇编 hello（183 字节静态 PIE）
.\target\release\vela.exe run guest\hello
# hello from linux elf

# 静态 musl C hello（863KB，未修改源码）
.\target\release\vela.exe run guest\hello-musl
# hello from musl
```

日志：`VELA_LOG=1` 或 `-v` 在 stderr 打印 syscall 记录；默认安静，只让客户
stdout 出来。退出码：客户 `exit` 的码；文件缺失 127；ELF 格式错误 1。

guest 二进制的复现方式（zig cc / musl-gcc / 内置生成器）见 [guest/README.md](guest/README.md)。

## 测试

覆盖：ELF 解析与拒绝路径、syscall patch、dispatch 语义翻译、fs 路径翻译、
四个 guest 的端到端验收（hello / torture / tls / hello-musl）。所有测试都是
纯内存或单进程小负载。

```powershell
# 一键完整验证（构建 + 测试 + guest 验收）
.\scripts\verify.ps1          # Windows
./scripts/verify.sh           # Linux/macOS（仅逻辑检查）
# 或分步
cargo test --workspace
```
CI 在 Windows runner 上自动执行相同流程（见 `.github/workflows/ci.yml`）。

## 项目结构

```
crates/
  vela-abi       Linux x86_64 ABI：syscall 号、errno、结构体布局（零依赖）
  vela-sys       Host trait + windows / linux_dev / spadaos 实现 + VEH 陷阱
  vela-loader    ELF64 解析校验、PT_LOAD 加载、syscall patch（0F 05 → 0F 0B）
  vela-runtime   GuestProcess 与 dispatch：Linux 语义 → Host 调用
  vela-fs        Linux 风格路径 → 宿主原生路径翻译
  vela-cli       vela 命令行 + 客户启动（栈构造、切栈）+ 生成器工具
guest/           验收用 Linux ELF（源码与预编译产物）
docs/            DESIGN / NONGOALS / HOST
scripts/         一键验证脚本（verify.ps1 / verify.sh）
.github/         CI（Windows runner：build + test + guest 验收）
```

依赖方向单向：`cli → loader → runtime → fs`，宿主差异全部收敛在 `vela-sys`。

## 安全

> Vela is not a security sandbox. Guest code shares the host process.

Linux 程序与 `vela.exe` 同进程、同权限，可访问用户能访问的一切。不要把 Vela
当沙箱用。杀毒软件可能对「进程内改可执行内存再执行」敏感：开发时若被拦，给
`vela.exe` 加排除（Vela 不做任何加壳混淆）。

## 贡献

提交信息遵循 [Conventional Commits](CONTRIBUTING.md)，行为准则与安全报告流程见
[SECURITY.md](SECURITY.md)。核心规则：

- 主路径在 Windows（syscall patch + VEH 必须在 Windows 上验收）。
- 没有 Windows 也可以贡献：ELF 解析器、`vela-abi`、单元测试（loader/runtime
  逻辑可 linux dev 构建）。
- 提交前跑 `.\scripts\verify.ps1`（或 `cargo test --workspace`）。
- 代码标识符全英文；所有宿主差异走 `vela-sys::Host`，禁止在 runtime 以上出现
  `cfg(target_os)`。
- 零第三方依赖是 v0 硬约束；新增依赖需先开 issue 讨论。

## 路线

- v0.x：补全 musl 常用 syscall（fstat/stat）、busybox 静态子集
- v1：SpadaOS Host 填满（map/file/time/thread/futex 五组）、外部 X server 通路
- 设计细节与决策记录见 [docs/DESIGN.md](docs/DESIGN.md)

## 许可

Apache-2.0（兼容层与 SpadaOS 内核许可分离，见 [LICENSE](LICENSE)）。
