#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"signal-wait:%d: %s errno=%d\n",__LINE__,#x,errno); return 1; } } while(0)
static _Thread_local volatile sig_atomic_t local_seen;
static atomic_int ready, done, seen, target;
static int pair[2], mode, ep, futex_word;
static unsigned char alternate[32768];
static volatile uintptr_t handler_stack;
static void *wait_fail(int code) { fprintf(stderr,"waiter failed: %d\n",code); atomic_store(&done,-1); return (void *)(uintptr_t)code; }
static void handler(int signal) {
    (void)signal;
    char marker;
    handler_stack = (uintptr_t)&marker;
    local_seen++;
    atomic_fetch_add(&seen,1);
    __asm__ volatile("pxor %%xmm0, %%xmm0" ::: "xmm0");
}
static void *waiter(void *unused) {
    (void)unused;
    sigset_t blocked, empty;
    sigemptyset(&empty); sigemptyset(&blocked); sigaddset(&blocked,SIGUSR1);
    atomic_store(&target,syscall(SYS_gettid));
    if ((mode==0 || mode==5 || mode==6) && pthread_sigmask(SIG_BLOCK,&blocked,0)) return wait_fail(1);
    atomic_store(&ready,1);
    if (mode==0) {
        struct timespec timeout={2,0};
        int result=ppoll(0,0,&timeout,&empty);
        if(result!=-1 || errno!=EINTR || local_seen!=1) return wait_fail(2);
        sigset_t after; pthread_sigmask(SIG_SETMASK,0,&after);
        if(!sigismember(&after,SIGUSR1)) return wait_fail(3);
    } else if(mode>=3) {
        struct timespec timeout={2,0};
        struct epoll_event event;
        int result;
        if(mode==3) result=syscall(SYS_futex,&futex_word,0,0,&timeout,0,0);
        else if(mode==4) result=epoll_wait(ep,&event,1,2000);
        else if(mode==5) result=pselect(0,0,0,0,&timeout,&empty);
        else result=epoll_pwait(ep,&event,1,2000,&empty);
        if(result!=-1 || errno!=EINTR || !local_seen) return wait_fail(6);
        if(mode==5 || mode==6) {
            sigset_t after;pthread_sigmask(SIG_SETMASK,0,&after);
            if(!sigismember(&after,SIGUSR1)) return wait_fail(7);
        }
    } else {
        char byte;
        ssize_t count=read(pair[1],&byte,1);
        if(mode==1 && (count!=-1 || errno!=EINTR || !local_seen)) return wait_fail(4);
        if(mode==2 && (count!=1 || byte!='r' || !local_seen)) return wait_fail(5);
    }
    atomic_store(&done,1);
    return 0;
}
static void *queue_main(void *unused) {
    (void)unused;
    int result=syscall(SYS_tgkill,getpid(),atomic_load(&target),SIGUSR1);
    atomic_store(&done,result ? -1 : 1);
    return 0;
}
int main(void) {
    struct sigaction action={0}; action.sa_handler=handler;
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1,&action,0)==0);
    CHECK(sigaction(SIGTERM,&action,0)==0);
    struct sigaction unsupported=action;unsupported.sa_flags=SA_SIGINFO;
    CHECK(sigaction(SIGUSR2,&unsupported,0)==-1 && errno==EINVAL);
    CHECK(kill(getpid(),SIGSTOP)==-1 && errno==ENOSYS);
    CHECK(kill(getpid(),SIGTERM)==0 && local_seen==1);
    sigset_t all, actual; sigfillset(&all);
    CHECK(pthread_sigmask(SIG_SETMASK,&all,0)==0);
    CHECK(pthread_sigmask(SIG_SETMASK,0,&actual)==0);
    CHECK(!sigismember(&actual,SIGKILL) && !sigismember(&actual,SIGSTOP));
    sigemptyset(&all); CHECK(pthread_sigmask(SIG_SETMASK,&all,0)==0);
    fprintf(stderr,"stage: signal mask baseline\n");

    // Queue to the main guest tid while it executes no syscall. The next
    // getpid has a nonzero result which must survive handler/sigreturn.
    atomic_store(&target,syscall(SYS_gettid)); atomic_store(&done,0);
    pthread_t thread; void *result;
    int before=local_seen;
    CHECK(pthread_create(&thread,0,queue_main,0)==0);
    while(!atomic_load(&done)) { __asm__ volatile("pause"); }
    CHECK(atomic_load(&done)==1);
    CHECK(syscall(SYS_getpid)==getpid() && local_seen==before+1);
    CHECK(pthread_join(thread,&result)==0 && !result);
    fprintf(stderr,"stage: nonzero syscall delivery\n");

    stack_t stack={.ss_sp=alternate,.ss_size=sizeof(alternate)};
    CHECK(sigaltstack(&stack,0)==0);
    action.sa_flags=SA_ONSTACK;
    CHECK(sigaction(SIGUSR1,&action,0)==0);
    unsigned char input[16] __attribute__((aligned(16)))={1,2,3,4,5,6,7,8};
    unsigned char output[16] __attribute__((aligned(16)))={0};
    long call;
    __asm__ volatile("movdqu %[in], %%xmm0\n\tmov $62, %%eax\n\tsyscall\n\tmovdqu %%xmm0, %[out]"
        : "=a"(call), [out] "=m"(output) : "D"((long)getpid()),"S"((long)SIGUSR1),[in]"m"(input) : "rcx","r11","memory","xmm0");
    CHECK(call==0 && !memcmp(input,output,16));
    CHECK(handler_stack>=(uintptr_t)alternate && handler_stack<(uintptr_t)(alternate+sizeof(alternate)));
    CHECK(sigaltstack(0,&stack)==0 && !(stack.ss_flags&SS_ONSTACK));
    fprintf(stderr,"stage: alternate stack and SIMD\n");
    action.sa_flags=0;
    CHECK(sigaction(SIGUSR1,&action,0)==0);

    ep=epoll_create1(0); CHECK(ep>=0);
    for(mode=0;mode<7;mode++) {
        fprintf(stderr,"stage: wait mode %d\n",mode);
        atomic_store(&ready,0); atomic_store(&done,0); atomic_store(&seen,0);
        action.sa_flags=mode==2 ? SA_RESTART : 0;
        CHECK(sigaction(SIGUSR1,&action,0)==0);
        CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
        CHECK(pthread_create(&thread,0,waiter,0)==0);
        while(!atomic_load(&ready)) sched_yield();
        CHECK(syscall(SYS_tgkill,getpid(),atomic_load(&target),SIGUSR1)==0);
        if(mode==0 || mode==5 || mode==6) {
            while(!atomic_load(&done)) sched_yield();
        } else {
            while(!atomic_load(&seen) || (mode==1 && !atomic_load(&done))) {
                int sent=syscall(SYS_tgkill,getpid(),atomic_load(&target),SIGUSR1);
                CHECK(sent==0 || errno==ESRCH);
                sched_yield();
            }
            if(mode==2) CHECK(write(pair[0],"r",1)==1);
        }
        CHECK(pthread_join(thread,&result)==0 && !result);
        close(pair[0]); close(pair[1]);
    }
    close(ep);
    puts("signal-wait-test ok: thread masks/tids, nonzero return, SIGTERM, alternate stack, SIMD, ppoll, socket EINTR and SA_RESTART");
    return 0;
}
