# Vela 0.1.1：稳定性与发布收口

基线：`v0.1.0`。本版本继续只支持 Windows x86_64，目标是完成路径隔离、算术边界、ELF/fork/exec 可靠性、验证入口和发行包收口，并加入 `poll(2)` / `select(2)`。

## 范围

- `--root` 是隔离根；额外宿主目录必须通过显式 `--map` 声明。
- guest 资产统一放在 `guest/bin/`。
- `poll(2)` / `select(2)` 仅覆盖同步文件、标准流和 Vela pipe，fd 数量上限 1024。
- MAP_SHARED、信号投递、线程/futex、socket、glibc 和非 Windows 宿主继续不在范围内。

## 验收

`cargo fmt --all -- --check`、workspace/all-targets clippy、workspace tests、`scripts/verify.ps1 -RequireBusybox`、Windows guest acceptance，以及从发行 ZIP 临时解压后的 `vela --version`、`doctor`、静态/动态 guest、fork/exec/pipe/poll/select/BusyBox 基础命令。
