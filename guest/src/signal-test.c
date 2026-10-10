#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static volatile sig_atomic_t seen;
static void handler(int sig) { if (sig == SIGUSR1) seen++; }

int main(void) {
    struct sigaction sa = {0};
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, 0) != 0) return 2;
    if (kill(getpid(), SIGUSR1) != 0 || seen != 1) return 3;
    sigset_t set;
    sigemptyset(&set); sigaddset(&set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &set, 0) != 0) return 4;
    if (kill(getpid(), SIGUSR1) != 0 || seen != 1) return 5;
    if (sigprocmask(SIG_UNBLOCK, &set, 0) != 0) return 6;
    for (volatile int i = 0; i < 100000; ++i) {}
    if (seen != 2) return 7;
    puts("signal-test ok: handler, mask, pending");
    return 0;
}
