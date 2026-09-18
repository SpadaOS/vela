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

# 诊断：zig 对 msys2 参数/路径转换高度敏感；MSYS 转换只对含 / 的参数发生，
# 本构建的 zig 命令行全是相对路径，排除转换干扰（CI 曾现 FileNotFound）
export MSYS2_ARG_CONV_EXCL="*"
export MSYS2_ENV_CONV_EXCL="*"

if [ ! -d "$BB_SRC" ]; then
  curl -sSL -o /tmp/bb.tar.bz2 "https://busybox.net/downloads/busybox-$BB_VER.tar.bz2"
  tar -xjf /tmp/bb.tar.bz2 -C "$WS"
  mv "$WS/busybox-$BB_VER" "$BB_SRC"
fi
cd "$BB_SRC"

# ---- 诊断区（CI 曾在 <1.2s 内 FileNotFound，无命令回显） ----
echo "DIAG zig: $(command -v zig) / $(zig version)"
echo "DIAG pwd-posix: $(pwd)"
echo "DIAG pwd-win: $(cmd //c cd 2>/dev/null || true)"
echo 'int main(void){return 0;}' > diag_t.c
if zig cc -target x86_64-linux-musl -c -o diag_t.o diag_t.c; then
  echo "DIAG trivial-compile OK"
else
  echo "DIAG trivial-compile FAIL rc=$?"
fi
ls -l diag_t.o 2>/dev/null || echo "DIAG diag_t.o missing"
# ---- 诊断区结束 ----

# 最小配置：allnoconfig（全部关闭）→ 白名单 applet + 静态
make -s allnoconfig HOSTCC=gcc
for f in ECHO LS CAT TRUE FALSE NPROC ENV PRINTF; do
  sed -i "s/^# CONFIG_${f} is not set/CONFIG_${f}=y/" .config
done
sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
# 固化 config（非交互应答全部默认）
yes "" | make oldconfig HOSTCC=gcc >/dev/null 2>&1 || true

# 显式强制生成 include/autoconf.h + include/config/auto.conf。
# CI 实测：主 make 会跳过 autoconf.h 生成规则（Makefile:521，本地不复现），
# 导致编译 -include include/autoconf.h 报 FileNotFound。silentoldconfig
# 匹配 %config 目标（Makefile:409），直接调用可绕过主 make 的规则判定。
rm -f include/autoconf.h
rm -rf include/config
make silentoldconfig HOSTCC=gcc
test -f include/autoconf.h || { echo "FATAL: include/autoconf.h not generated"; exit 1; }
test -f include/config/auto.conf || { echo "FATAL: include/config/auto.conf not generated"; exit 1; }

# zig cc musl 默认静态；-fPIE -pie 生成 ET_DYN（vela 仅接受 PIE）。
# -j1：规避多 zig 进程共享缓存的 Windows 竞争；V=1：失败时日志有完整命令。
make V=1 -j1 \
  CC="zig cc -target x86_64-linux-musl -fPIE -pie" \
  HOSTCC=gcc

file busybox || true
cp busybox "$WS/guest/bin/busybox"
echo "busybox built: $(ls -l "$WS/guest/bin/busybox")"
