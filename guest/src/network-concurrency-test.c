#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "network-concurrency:%d: %s (errno %d)\n", __LINE__, #x, errno); return 1; } } while (0)
static int pair[2];
static atomic_int ready;
static int pipe_mode;
static void *reader(void *unused) {
    (void)unused;
    atomic_store(&ready, 1);
    char bytes[4096];
    size_t total = 0;
    for (;;) {
        ssize_t n = read(pair[1], bytes, sizeof(bytes));
        if (n < 0) return (void *)1;
        if (!n) break;
        for (ssize_t i = 0; i < n; ++i) if (bytes[i] != 'v') return (void *)2;
        total += n;
    }
    if (total != 1024*1024) return (void *)3;
    if (!pipe_mode && write(pair[1], "reply", 5) != 5) return (void *)4;
    return 0;
}

static int listener;
static void *acceptor(void *unused) {
    (void)unused;
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    atomic_store(&ready, 1);
    int fd = accept4(listener, (struct sockaddr *)&peer, &length, SOCK_CLOEXEC);
    if (fd < 0 || length != sizeof(peer) || peer.sin_family != AF_INET || !peer.sin_port) return (void *)5;
    char data[8];
    if (read(fd, data, sizeof(data)) != 3 || memcmp(data, "tcp", 3)) return (void *)6;
    if (write(fd, "yes", 3) != 3) return (void *)7;
    close(fd);
    return 0;
}

int main(void) {
    pthread_t thread;
    void *result;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    fprintf(stderr, "stage: pair reader start\n");
    CHECK(pthread_create(&thread, 0, reader, 0) == 0);
    while (!atomic_load(&ready)) sched_yield();
    char block[8192]; memset(block, 'v', sizeof(block));
    for (size_t sent = 0; sent < 1024*1024;) {
        size_t remaining = 1024*1024 - sent;
        ssize_t n = write(pair[0], block, remaining < sizeof(block) ? remaining : sizeof(block));
        CHECK(n > 0); sent += n;
    }
    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    fprintf(stderr, "stage: sent payload and EOF\n");
    char reply[8];
    CHECK(read(pair[0], reply, sizeof(reply)) == 5 && !memcmp(reply, "reply", 5));
    CHECK(pthread_join(thread, &result) == 0 && !result);
    fprintf(stderr, "stage: pair joined\n");
    int alias = dup(pair[0]); CHECK(alias >= 0);
    CHECK(fcntl(alias, F_SETFL, O_NONBLOCK) == 0);
    CHECK(fcntl(pair[0], F_GETFL) & O_NONBLOCK);
    CHECK(close(pair[0]) == 0);
    CHECK(shutdown(pair[1], SHUT_WR) == 0);
    CHECK(read(alias, reply, sizeof(reply)) == 0);
    CHECK(fork() == -1 && errno == ENOSYS);
    close(alias); close(pair[1]);

    // Native pipes must release the shared guard under sustained backpressure.
    int pipefd[2];CHECK(pipe(pipefd)==0);pair[0]=pipefd[1];pair[1]=pipefd[0];
    pipe_mode=1;atomic_store(&ready,0);
    CHECK(pthread_create(&thread,0,reader,0)==0);
    while(!atomic_load(&ready)) sched_yield();
    for(size_t sent=0;sent<1024*1024;) {
        size_t remaining=1024*1024-sent;
        ssize_t count=write(pair[0],block,remaining<sizeof(block)?remaining:sizeof(block));
        CHECK(count>0);sent+=count;
    }
    close(pair[0]);CHECK(pthread_join(thread,&result)==0 && !result);close(pair[1]);
    fprintf(stderr,"stage: pipe backpressure joined\n");

    listener = socket(AF_INET, SOCK_STREAM, 0); CHECK(listener >= 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    CHECK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CHECK(listen(listener, 4) == 0);
    socklen_t length = sizeof(addr);
    CHECK(getsockname(listener, (struct sockaddr *)&addr, &length) == 0);
    atomic_store(&ready, 0);
    CHECK(pthread_create(&thread, 0, acceptor, 0) == 0);
    fprintf(stderr, "stage: acceptor start\n");
    while (!atomic_load(&ready)) sched_yield();
    int client = socket(AF_INET, SOCK_STREAM, 0); CHECK(client >= 0);
    CHECK(connect(client, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    fprintf(stderr, "stage: TCP connected\n");
    CHECK(write(client, "tcp", 3) == 3);
    CHECK(read(client, reply, sizeof(reply)) == 3 && !memcmp(reply, "yes", 3));
    CHECK(pthread_join(thread, &result) == 0 && !result);
    close(client); close(listener);
    puts("network-concurrency-test ok: bounded backpressure, bidirectional IO, blocking accept, aliases, fork boundary");
    return 0;
}
