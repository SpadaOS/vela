# guest

本目录存放用于验收的 Linux x86_64 静态 PIE ELF（规格 8）。

## `hello`（v0 门禁）

`hello` 是一颗 **Linux ELF64 静态 PIE**，运行后向 stdout 打印：

```
hello from linux elf
```

### 复现方式一：真实汇编编译（推荐）

在 Linux / WSL 上：

```bash
clang -static-pie -nostdlib -o hello src/hello.S
# 或
gcc -static-pie -nostdlib -o hello src/hello.S
file hello   # 应显示 ELF 64-bit LSB pie executable
```

用产物覆盖本目录的 `hello`。

### 复现方式二：Vela 自带生成器

无 Linux 交叉环境时（规格 8.1 允许）：

```powershell
cargo run -p vela-cli --bin vela-mkhello -- guest/hello
```

生成器产出与汇编版语义一致的最小合法 ET_DYN ELF（单 PT_LOAD、R|X、
两条 `syscall` 指令），仓库内测试会校验其解析与 patch 行为。

## 其他 guest（vela-mkguest 生成）

```powershell
cargo run -p vela-cli --bin vela-mkguest -- torture guest/torture
cargo run -p vela-cli --bin vela-mkguest -- tls     guest/tls
```

- **torture**（4.5KB，双 PT_LOAD：RX 代码段 + RW 数据段）：
  brk / mmap / uname / getrandom / writev 全链路真执行，输出
  `Linuxmmap 1g1 ok`。不依赖 TLS，任何机器可跑。
- **tls**：在 torture 基础上验证 `arch_prctl(SET_FS)` 后 FS 相对寻址真正生效
  （普通寻址写 marker + fs 读回的决定性检查），输出 `mmap 1t1 ok`。
  需要 CPU+OS 支持 FSGSBASE（不支持时 fs 访问会崩溃——这是诚实的失败；
  集成测试会自动跳过）。

## `hello-musl`（规格 8.2，静态 musl C hello）

输出 `hello from musl`。Windows 上用 [zig](https://ziglang.org/download/) 交叉编译
（无需 WSL / musl-gcc；解压即用）：

```powershell
zig cc -target x86_64-linux-musl -fPIE -pie -O2 -o guest/hello-musl guest/src/hello-musl.c
```

> 注意：zig cc 会忽略 `-static-pie`（musl 目标默认静态），必须用
> `-fPIE -pie` 显式生成 ET_DYN，否则 Vela 会以 non-PIE 拒绝加载。

Linux/WSL 上等价命令：`musl-gcc -static-pie -O2 -o guest/hello-musl guest/src/hello-musl.c`。

## 禁止

- 用 MinGW 编出来的 PE 当测试（规格 8.3）
- 动态链接的 hello（有 PT_INTERP，v0 拒绝加载）
