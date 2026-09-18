/* guest/src/fs-exec.c —— PLAN-0.0.4 T3.4 验收 guest：
 * forkfree 地验证 pipe2 + fd 跨 execve 保留 + execve 自身重载。
 *
 * 阶段 1（无参数）：pipe2 建管道 → 写消息 → dup2 读端到 fd 3 →
 *                  execve 自身（argv[1]="stage2"）
 * 阶段 2（"stage2"）：从 fd 3 读出消息并输出（证明 fd 跨 execve 存活）
 *
 * Windows 上编译（musl 静态 PIE）：
 *   zig cc -target x86_64-linux-musl -static-pie -O2 -o guest/bin/fs-exec guest/src/fs-exec.c
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc >= 2 && argv[1][0] == 's' && strcmp(argv[1], "stage2") == 0) {
        char buf[32];
        long n = read(3, buf, sizeof buf - 1);
        if (n <= 0) {
            const char e[] = "fs-exec: stage2 read failed\n";
            write(2, e, sizeof e - 1);
            return 1;
        }
        buf[n] = 0;
        const char ok[] = "fs-exec ok: ";
        write(1, ok, sizeof ok - 1);
        write(1, buf, n);
        const char nl[] = "\n";
        write(1, nl, 1);
        return 0;
    }

    int pfd[2];
    /* O_NONBLOCK：走 SYS_pipe2 直达路径（zig 的 musl pipe2 在 flags=0 时
     * 退化为 pipe()，x86_64 无该 syscall）。vela 的管道本身即非阻塞语义。 */
    if (pipe2(pfd, O_NONBLOCK) != 0) {
        const char e[] = "fs-exec: pipe2 failed\n";
        write(2, e, sizeof e - 1);
        return 1;
    }
    const char msg[] = "pipe-across-execve";
    if (write(pfd[1], msg, sizeof msg - 1) != (long)(sizeof msg - 1)) {
        const char e[] = "fs-exec: pipe write failed\n";
        write(2, e, sizeof e - 1);
        return 1;
    }
    /* 写端用完即关：阶段 2 的 read 以 EOF 收尾也不阻塞 */
    close(pfd[1]);
    if (dup2(pfd[0], 3) < 0) {
        const char e[] = "fs-exec: dup2 failed\n";
        write(2, e, sizeof e - 1);
        return 1;
    }
    char *argv2[] = { argv[0], "stage2", 0 };
    char *envp2[] = { 0 };
    execve(argv[0], argv2, envp2);
    const char f[] = "fs-exec: execve failed\n";
    write(2, f, sizeof f - 1);
    return 1;
}
