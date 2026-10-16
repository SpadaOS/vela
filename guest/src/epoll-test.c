#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"epoll:%d: %s errno=%d\n",__LINE__,#x,errno); return 1; } } while(0)
static int shared_ep;
static atomic_int waiting;
static void *epoll_waiter(void *unused) {
    (void)unused;struct epoll_event event;
    atomic_store(&waiting,1);
    if(epoll_wait(shared_ep,&event,1,2000)!=1 || event.data.u64!=99 || !(event.events&EPOLLIN)) return (void *)1;
    return 0;
}
int main(void) {
    int ep = epoll_create1(EPOLL_CLOEXEC), pair[3][2]; CHECK(ep >= 0);
    struct epoll_event ev = { .events = EPOLLIN }, got[3];
    for (int i=0;i<3;i++) {
        CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair[i]) == 0);
        ev.data.u64 = i+1;
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, pair[i][1], &ev) == 0);
        CHECK(write(pair[i][0], "x", 1) == 1);
    }
    unsigned seen=0;
    for(int i=0;i<3;i++) { CHECK(epoll_wait(ep,got,1,1000)==1); seen |= 1u<<got[0].data.u64; }
    CHECK(seen==14);
    int watched=pair[0][1], alias=dup(watched); CHECK(alias >= 0);
    close(watched);
    int reused=socket(AF_INET,SOCK_DGRAM,0); CHECK(reused==watched);
    ev.data.u64=4;
    CHECK(epoll_ctl(ep,EPOLL_CTL_ADD,reused,&ev)==0);
    CHECK(epoll_wait(ep,got,3,0)==3);
    close(alias);
    CHECK(epoll_wait(ep,got,3,0)==2);
    ev.events=EPOLLIN|EPOLLET;
    CHECK(epoll_ctl(ep,EPOLL_CTL_MOD,pair[1][1],&ev)==-1 && errno==EINVAL);
    CHECK(epoll_ctl(ep,EPOLL_CTL_ADD,ep,&ev)==-1 && errno==EINVAL);
    CHECK(epoll_ctl(ep,EPOLL_CTL_ADD,1,&ev)==-1 && errno==EPERM);
    close(reused);
    for(int i=0;i<3;i++) { close(pair[i][0]); if(i)close(pair[i][1]); }
    close(ep);
    shared_ep=epoll_create1(0);CHECK(shared_ep>=0);
    int pipefd[2];CHECK(pipe(pipefd)==0);
    pthread_t thread;void *result;CHECK(pthread_create(&thread,0,epoll_waiter,0)==0);
    while(!atomic_load(&waiting)) sched_yield();
    ev=(struct epoll_event){.events=EPOLLIN,.data.u64=99};
    CHECK(epoll_ctl(shared_ep,EPOLL_CTL_ADD,pipefd[0],&ev)==0);
    CHECK(write(pipefd[1],"p",1)==1);
    CHECK(pthread_join(thread,&result)==0 && !result);
    ev.events=EPOLLIN|EPOLLRDHUP;CHECK(epoll_ctl(shared_ep,EPOLL_CTL_MOD,pipefd[0],&ev)==0);
    CHECK(epoll_ctl(shared_ep,EPOLL_CTL_DEL,pipefd[0],0)==0);
    CHECK(epoll_wait(shared_ep,got,1,0)==0);
    close(pipefd[0]);close(pipefd[1]);close(shared_ep);
    puts("epoll-test ok: fairness, dup/close/reuse identity, flags and targets");
    return 0;
}
