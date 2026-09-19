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

## `file-io`（0.0.2 M1 出口，文件 syscall 全链路验收）

静态 musl C 程序，验收 `open/write/lseek/read/fstat/stat/fcntl/opendir
(getdents64)/getcwd` 全链路（源码 `src/file-io.c`，编译命令同上）。在
`/mnt/c/Windows/Temp` 内创建、回读、遍历并清理验收文件；全链路通过输出
`file-io all ok`。依赖 TLS（musl），仅 FSGSBASE 机器可跑（或配
`vela run --soft-tls`）；集成测试自动跳过。

## `hello-dyn`（0.0.4 M2 出口，动态 musl 链接验收）

**动态** musl C 程序（PT_INTERP 指向 `/lib/ld-musl-x86_64.so.1`）：

```powershell
zig cc -target x86_64-linux-musl -dynamic -fPIE -pie -O2 -o guest/bin/hello-dyn guest/src/hello-musl.c
```

配套解释器 `guest/bin/ld-musl-x86_64.so.1`（vela 按"guest ELF 同目录同名
文件"回退解析；也可 `--interp <host-path>` 或 `--map /lib=<host-dir>` 显式
指定）。解释器从 musl 1.2.5 源码构建（musl 1.2.5 源码 + zig libc.a 对象，
`-Wl,--whole-archive -Wl,-e,_dlstart` 重链接；zig 自带的 musl 树不含
dynlink.c，需从 musl.libc.org 补齐同版本源码）。

运行：`vela run --soft-tls guest/bin/hello-dyn` → 输出 `hello from musl`
并干净退出。`--soft-tls` 在 FSGSBASE 缺失的机器（Hyper-V/云 VM）上必须
开启，见 docs/DESIGN.md「软 TLS」。

## `fs-exec`（0.0.4 M3 出口，pipe2 + execve 重载验收）

静态 musl C 程序（`src/fs-exec.c`，编译命令同 hello-musl）：pipe2 建管道 →
写消息 → dup2 读端到 fd 3 → **execve 自身**（进程内重载）；第二阶段从
fd 3 读出消息，验证 fd 跨 execve 保留。通过输出
`fs-exec ok: pipe-across-execve`。musl 依赖 TLS，本机验证用 `--soft-tls`。

## `pipe-a` / `pipe-b`（0.0.5 M2 出口，宿主管道组合验收）

两个静态 musl C 程序（`src/pipe-a.c` / `src/pipe-b.c`）：pipe-a 向 stdout
写 3 行消息，pipe-b 从 stdin 逐块读取并统计字节/行数。宿主侧用真实管道
串起来：

```powershell
vela run guest\bin\pipe-a | vela run guest\bin\pipe-b
# pipe-b ok: 29 bytes, 3 lines
```

验证两件事：vela 的 stdout/stdin 与宿主管道全双工互通（GuestFd::StdIn
经 file_ops 真实读取、write 侧 flush 与 EOF 干净），以及两个独立 vela
进程各自生命周期正常（退出码 0）。编译命令同 hello-musl。

## `busybox`（0.0.5 M3 出口，CI 现场构建，不入库）

busybox 1.36.1 静态子集（allnoconfig + 白名单 applet：echo/ls/cat/true/
false/nproc/env/printf + CONFIG_STATIC），由 `tools/build-busybox.sh` 在
CI 上用 msys2 make + zig cc 交叉编译（musl 静态 PIE）。产物
`guest/bin/busybox` 仅存在于 CI 工作区，验收 echo/nproc/true：

```powershell
vela run --soft-tls guest\bin\busybox echo hello
vela run --soft-tls guest\bin\busybox nproc
vela run --soft-tls guest\bin\busybox true
```

本地复现需要 msys2（make/gcc/bzip2/curl）+ zig 0.13.0 在 PATH；脚本内
`cygpath` 处理 workspace 路径转换，并针对 zig 0.13 Windows 工具链做了三项
修补（depfile 剥离、autoconf.h 强制生成、GNU ld 专属链接参数中和）——
细节见脚本注释。

## 禁止

- 用 MinGW 编出来的 PE 当测试（规格 8.3）
- glibc 动态链接的 hello（非 musl 解释器，v0.0.4 诚实拒绝）
