/* guest/src/fork-test.c —— PLAN-0.0.6 M1 验收：fork 语义端到端。
 * fork → 子进程写管道（验证从返回点继续执行 + 独立 pid）→
 * 父进程 waitpid 回收（验证真实等待 + 退出码）→ 读回消息。 */
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        puts("fork-test: pipe failed");
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        puts("fork-test: fork failed");
        return 1;
    }
    if (pid == 0) {
        /* 子进程：必须从 fork 返回点继续（而非重跑 main）——
         * 走到这里本身就证明快照/上下文恢复成立 */
        close(fds[0]);
        char msg[64];
        int n = snprintf(msg, sizeof msg, "child ok %u", (unsigned)getpid());
        write(fds[1], msg, n);
        close(fds[1]);
        _exit(42);
    }
    /* 父进程：读子进程消息 + waitpid 收尸 */
    close(fds[1]);
    char buf[64] = {0};
    ssize_t n = read(fds[0], buf, sizeof buf - 1);
    close(fds[0]);
    if (n <= 0) {
        puts("fork-test: pipe read failed");
        return 1;
    }
    int status = 0;
    pid_t w = waitpid(pid, &status, 0);
    if (w != pid) {
        puts("fork-test: waitpid mismatch");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 42) {
        puts("fork-test: bad exit status");
        return 1;
    }
    printf("fork-test ok: [%s] exit=%d\n", buf, WEXITSTATUS(status));
    return 0;
}
