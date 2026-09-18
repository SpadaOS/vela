#!/usr/bin/env bash
# busybox 静态子集构建（PLAN-0.0.5 M3）。
# 运行环境：msys2（make/gcc/curl/bzip2）+ musl.cc 交叉工具链。
# applet 白名单：echo/ls/cat/true/false/nproc/env/printf；产物 guest/bin/busybox。
set -euo pipefail

BB_VER=1.36.1
WS="${GITHUB_WORKSPACE:-$(pwd)}"
BB_SRC="/tmp/busybox-$BB_VER"
CROSS=/tmp/x86_64-linux-musl-cross

command -v make >/dev/null || { echo "make not in PATH"; exit 1; }
command -v gcc >/dev/null || { echo "gcc not in PATH (HOSTCC)"; exit 1; }

if [ ! -d "$CROSS/bin" ]; then
  echo "downloading musl.cc cross toolchain..."
  curl -sSL -o /tmp/cross.tgz "https://musl.cc/x86_64-linux-musl-cross.tgz"
  tar -xzf /tmp/cross.tgz -C /tmp
fi
export PATH="$CROSS/bin:$PATH"
command -v x86_64-linux-musl-gcc >/dev/null || { echo "cross gcc missing"; exit 1; }

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

# 静态 PIE：musl gcc + -fPIE -pie → ET_DYN
make -j4 \
  ARCH=x86_64 \
  CC=x86_64-linux-musl-gcc \
  CFLAGS="-fPIE -O2" \
  LDFLAGS="-pie"

file busybox || true
cp busybox "$WS/guest/bin/busybox"
echo "busybox built: $(ls -l "$WS/guest/bin/busybox")"
