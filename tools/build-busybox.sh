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

# ---- 二分诊断：make 调用下 zig 瞬间 FileNotFound，定位致命 flag ----
B="zig cc -target x86_64-linux-musl"
echo "BISECT trivial-repeat:"; echo 'int main(void){return 0;}' > diag_t.c
$B -c -o diag_t.o diag_t.c && echo "  t0 plain OK" || echo "  t0 plain FAIL"
echo "BISECT v1 full flags:"
$B -fPIE -pie -Wp,-MD,applets/.applets.o.d -Iinclude -Ilibbb -include include/autoconf.h \
   -D_GNU_SOURCE -DNDEBUG -DBB_VER='"1.36.1"' -Wold-style-definition \
   -DKBUILD_BASENAME='"applets"' -DKBUILD_MODNAME='"applets"' \
   -c -o applets/bisect1.o applets/applets.c && echo "  v1 OK" || echo "  v1 FAIL"
echo "BISECT v2 no -Wp:"
$B -fPIE -pie -Iinclude -Ilibbb -include include/autoconf.h \
   -D_GNU_SOURCE -DNDEBUG -DBB_VER='"1.36.1"' -Wold-style-definition \
   -DKBUILD_BASENAME='"applets"' -DKBUILD_MODNAME='"applets"' \
   -c -o applets/bisect2.o applets/applets.c && echo "  v2 OK" || echo "  v2 FAIL"
echo "BISECT v3 no pie:"
$B -fPIE -Wp,-MD,applets/.applets.o.d -Iinclude -Ilibbb -include include/autoconf.h \
   -D_GNU_SOURCE -DNDEBUG -DBB_VER='"1.36.1"' -Wold-style-definition \
   -DKBUILD_BASENAME='"applets"' -DKBUILD_MODNAME='"applets"' \
   -c -o applets/bisect3.o applets/applets.c && echo "  v3 OK" || echo "  v3 FAIL"
echo "BISECT v4 no -include:"
$B -fPIE -pie -Wp,-MD,applets/.applets.o.d -Iinclude -Ilibbb \
   -D_GNU_SOURCE -DNDEBUG -DBB_VER='"1.36.1"' -Wold-style-definition \
   -DKBUILD_BASENAME='"applets"' -DKBUILD_MODNAME='"applets"' \
   -c -o applets/bisect4.o applets/applets.c && echo "  v4 OK" || echo "  v4 FAIL"
echo "BISECT v5 plain applets.c:"
$B -c -o applets/bisect5.o applets/applets.c && echo "  v5 OK" || echo "  v5 FAIL"
ls -l applets/*.o 2>/dev/null || echo "BISECT: no objects produced"
# ---- 二分诊断结束 ----

# zig cc musl 默认静态；-fPIE -pie 生成 ET_DYN（vela 仅接受 PIE）。
# -j1：规避多 zig 进程共享缓存的 Windows 竞争；V=1：失败时日志有完整命令。
make V=1 -j1 \
  CC="zig cc -target x86_64-linux-musl -fPIE -pie" \
  HOSTCC=gcc

file busybox || true
cp busybox "$WS/guest/bin/busybox"
echo "busybox built: $(ls -l "$WS/guest/bin/busybox")"
