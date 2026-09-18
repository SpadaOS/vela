#!/usr/bin/env bash
# busybox 静态子集构建（PLAN-0.0.5 M3）。
# 运行环境：msys2（make/gcc）+ zig（PATH）。产物 guest/bin/busybox。
# 构建树在 workspace 内（/d/... 形式路径可被 msys2 参数转换正确处理）。
set -euo pipefail

BB_VER=1.36.1
WS="${GITHUB_WORKSPACE:-$(pwd)}"
# msys2：GITHUB_WORKSPACE 是 Windows 形式（D:\a\vela\vela），直接拼进 tar/mv
# 参数会被 msys2 转换搅坏（D\:\a\vela\vela），先显式转成 POSIX 形式
WS="$(cygpath -u "$WS")"
BB_SRC="$WS/.busybox-src"

command -v make >/dev/null || { echo "make not in PATH"; exit 1; }
command -v gcc >/dev/null || { echo "gcc not in PATH (HOSTCC)"; exit 1; }
command -v zig >/dev/null || { echo "zig not in PATH"; exit 1; }

if [ ! -d "$BB_SRC" ]; then
  curl -sSL -o /tmp/bb.tar.bz2 "https://busybox.net/downloads/busybox-$BB_VER.tar.bz2"
  tar -xjf /tmp/bb.tar.bz2 -C "$WS"
  mv "$WS/busybox-$BB_VER" "$BB_SRC"
fi
cd "$BB_SRC"

# 最小配置：allnoconfig（全部关闭）→ 白名单 applet + 静态
make -s allnoconfig HOSTCC=gcc
for f in ECHO LS CAT TRUE FALSE NPROC ENV PRINTF; do
  sed -i "s/^# CONFIG_${f} is not set/CONFIG_${f}=y/" .config
done
sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
# 固化 config（非交互应答全部默认）
yes "" | make oldconfig HOSTCC=gcc >/dev/null 2>&1 || true

# zig cc musl 默认静态；-fPIE -pie 生成 ET_DYN（vela 仅接受 PIE）。
# -j1：多 zig 进程共享缓存目录在 Windows 上有竞争（FileNotFound），串行规避；
# V=1：失败时日志可看到完整编译命令。
make V=1 -j1 \
  CC="zig cc -target x86_64-linux-musl -fPIE -pie" \
  HOSTCC=gcc

file busybox || true
cp busybox "$WS/guest/bin/busybox"
echo "busybox built: $(ls -l "$WS/guest/bin/busybox")"
