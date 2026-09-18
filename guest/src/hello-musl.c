/* guest/src/hello-musl.c —— 规格 8.2：musl 静态 PIE C hello（v0 加分项）。
 * Windows 上用 zig cc 交叉编译（无需 WSL/musl-gcc，见 guest/README.md）：
 *   zig cc -target x86_64-linux-musl -static-pie -O2 -o guest/hello-musl guest/src/hello-musl.c
 * Linux/WSL 上等价命令：
 *   musl-gcc -static-pie -O2 -o guest/hello-musl guest/src/hello-musl.c
 */
#include <unistd.h>

int main(void) {
    const char s[] = "hello from musl\n";
    write(1, s, sizeof s - 1);
    return 0;
}
