#!/usr/bin/env bash
# busybox 静态子集构建（PLAN-0.0.5 M3）。
# 在 msys2（make/gcc/curl）+ zig（PATH 中）环境运行；产物写入 guest/bin/busybox。
# applet 白名单：echo/ls/cat/true/false/nproc/env/printf。
set -euo pipefail

BB_VER=1.36.1
WS="${GITHUB_WORKSPACE:-$(pwd)}"
BB_SRC="/tmp/busybox-$BB_VER"

command -v zig >/dev/null || { echo "zig not in PATH"; exit 1; }
command -v make >/dev/null || { echo "make not in PATH"; exit 1; }

if [ ! -d "$BB_SRC" ]; then
  curl -sSL -o /tmp/bb.tar.bz2 "https://busybox.net/downloads/busybox-$BB_VER.tar.bz2"
  tar -xjf /tmp/bb.tar.bz2 -C /tmp
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

# zig cc musl 默认静态；-fPIE -pie 生成 ET_DYN（vela 仅接受 PIE）
make -j4 \
  CC="zig cc -target x86_64-linux-musl -fPIE -pie" \
  HOSTCC=gcc \
  CONFIG_PREFIX=/tmp/bb-install

file busybox || true
cp busybox "$WS/guest/bin/busybox"
echo "busybox built: $(ls -l "$WS/guest/bin/busybox")"
