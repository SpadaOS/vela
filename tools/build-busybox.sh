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

# zig 命令行全是相对路径，排除 msys2 参数/环境变量转换的干扰面
export MSYS2_ARG_CONV_EXCL="*"
export MSYS2_ENV_CONV_EXCL="*"

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

# 显式强制生成 include/autoconf.h（CI 主 make 会跳过生成规则，本地不复现）
rm -f include/autoconf.h
rm -rf include/config
make silentoldconfig HOSTCC=gcc
test -f include/autoconf.h || { echo "FATAL: include/autoconf.h not generated"; exit 1; }

# zig 0.13 Windows 下 -Wp,-MD,<depfile> 会瞬间 FileNotFound（zig 的 dep-file
# 缓存 bug，见 CI 二分日志：含 -Wp 必失败、去之立过）。CI 为一次性构建，
# 依赖追踪无意义：剥离 depfile 参数并禁用全部 fixdep 后处理（rule_cc_o_c
# 与 Kbuild.include 的 if_changed_dep 两处；宿主 gcc 工具链的 depfile 在
# Makefile.host 单独定义，但宿主工具已构建完成，同样禁用无害）。
sed -i 's/-Wp,-MD,\$(depfile) //' scripts/Makefile.lib
sed -i 's|scripts/basic/fixdep|: fixdep-disabled|' scripts/Makefile.build scripts/Kbuild.include
# zig 用 lld：GNU ld 专属链接参数（--sort-section/--sort-common/--warn-common/
# --verbose）不被支持，trylink 的 check_cc 探测在纯编译阶段无法发现，直接在
# 源头中和；CI 无 binutils，跳过 strip（未 strip 静态二进制对 vela 无影响）
sed -i 's|^SORT_SECTION=.*|SORT_SECTION=""|' scripts/trylink
sed -i 's|^SORT_COMMON=.*|SORT_COMMON=""|' scripts/trylink
sed -i 's|echo "-Wl,--warn-common -Wl,-Map,\$EXE.map -Wl,--verbose"|echo ""|' scripts/trylink
sed -i '/-Wl,--warn-common/d' scripts/trylink
sed -i '/-Wl,-Map,/d' scripts/trylink

# zig cc musl 默认静态；-fPIE -pie 生成 ET_DYN（vela 仅接受 PIE）。
# -j1：规避多 zig 进程共享缓存的 Windows 竞争；V=1：失败时日志有完整命令。
make V=1 -j1 SKIP_STRIP=y \
  CC="zig cc -target x86_64-linux-musl -fPIE -pie" \
  HOSTCC=gcc

file busybox || true
cp busybox "$WS/guest/bin/busybox"
echo "busybox built: $(ls -l "$WS/guest/bin/busybox")"
