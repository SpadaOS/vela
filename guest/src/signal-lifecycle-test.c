#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"signal-lifecycle:%d: %s errno=%d\n",__LINE__,#x,errno); return 1; } } while(0)
static volatile sig_atomic_t seen, children;
static void handler(int sig) { if(sig==SIGUSR1) seen++; else if(sig==SIGCHLD) children++; }
extern char **environ;
static atomic_int wait_returned;
static int main_tid, release_fd;
static void *interrupt_wait(void *unused) {
    (void)unused;
    while(!atomic_load(&wait_returned)) {
        if(syscall(SYS_tgkill,getpid(),main_tid,SIGUSR1)) return (void *)1;
        sched_yield();
    }
    return write(release_fd,"x",1)==1 ? 0 : (void *)2;
}

int main(int argc, char **argv) {
    struct sigaction action={0}, actual={0};action.sa_handler=handler;sigemptyset(&action.sa_mask);
    sigset_t mask;sigemptyset(&mask);sigaddset(&mask,SIGUSR1);
    if(argc==2) {
        CHECK(sigaction(SIGUSR1,0,&actual)==0 && actual.sa_handler==SIG_DFL);
        CHECK(sigaction(SIGPIPE,0,&actual)==0 && actual.sa_handler==SIG_IGN);
        sigset_t after;CHECK(sigprocmask(SIG_SETMASK,0,&after)==0 && sigismember(&after,SIGUSR1));
        stack_t stack;CHECK(sigaltstack(0,&stack)==0 && (stack.ss_flags&SS_DISABLE));
        CHECK(sigaction(SIGUSR1,&action,0)==0);
        CHECK(sigprocmask(SIG_UNBLOCK,&mask,0)==0 && seen==1);
        puts("signal-lifecycle-test ok: fork dispositions/mask/pending, SIGCHLD before wait, exec reset/mask/pending");
        return 0;
    }
    CHECK(sigaction(SIGUSR1,&action,0)==0);
    CHECK(sigaction(SIGCHLD,&action,0)==0);
    CHECK(sigprocmask(SIG_BLOCK,&mask,0)==0);
    CHECK(kill(getpid(),SIGUSR1)==0 && seen==0);
    pid_t pid=fork();CHECK(pid>=0);
    if(pid==0) {
        CHECK(sigprocmask(SIG_UNBLOCK,&mask,0)==0 && seen==0);
        CHECK(kill(getpid(),SIGUSR1)==0 && seen==1);
        _exit(0);
    }
    // A waiting parent receives SIGCHLD before reaping, at a trap safe point.
    struct timespec timeout={3,0};
    if(!children) CHECK(ppoll(0,0,&timeout,0)==-1 && errno==EINTR);
    CHECK(children==1);
    int status;while(waitpid(pid,&status,0)==-1) CHECK(errno==EINTR);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(sigprocmask(SIG_UNBLOCK,&mask,0)==0 && seen==1);
    CHECK(signal(SIGCHLD,SIG_DFL)!=SIG_ERR);
    int gate[2];CHECK(pipe(gate)==0);pid=fork();CHECK(pid>=0);
    if(!pid) { close(gate[1]);char byte;_exit(read(gate[0],&byte,1)==1?0:1); }
    close(gate[0]);release_fd=gate[1];main_tid=syscall(SYS_gettid);
    pthread_t thread;void *thread_result;CHECK(pthread_create(&thread,0,interrupt_wait,0)==0);
    CHECK(waitpid(pid,&status,0)==-1 && errno==EINTR);
    atomic_store(&wait_returned,1);
    CHECK(pthread_join(thread,&thread_result)==0 && !thread_result);
    close(gate[1]);while(waitpid(pid,&status,0)==-1) CHECK(errno==EINTR);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(signal(SIGPIPE,SIG_IGN)!=SIG_ERR);
    CHECK(sigprocmask(SIG_BLOCK,&mask,0)==0);
    int before=seen;CHECK(kill(getpid(),SIGUSR1)==0 && seen==before);
    char *next[]={argv[0],"--exec",0};execve(argv[0],next,environ);CHECK(0);
}
