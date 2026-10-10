#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 2;
    int ep = epoll_create1(0);
    if (ep < 0) return 3;
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = pair[1]};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, pair[1], &ev) != 0) return 4;
    if (write(pair[0], "ok", 2) != 2) return 5;
    struct epoll_event got = {0};
    if (epoll_wait(ep, &got, 1, 1000) != 1 || got.data.fd != pair[1]) return 6;
    char buf[8] = {0};
    if (read(pair[1], buf, sizeof(buf)) != 2 || memcmp(buf, "ok", 2) != 0) return 7;
    close(ep); close(pair[0]); close(pair[1]);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return 8;
    struct sockaddr_in loop = {0};
    loop.sin_family = AF_INET;
    loop.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&loop, sizeof(loop)) != 0) return 9;
    if (listen(listener, 4) != 0) return 10;
    socklen_t loop_len = sizeof(loop);
    if (getsockname(listener, (struct sockaddr *)&loop, &loop_len) != 0) return 11;
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0 || connect(client, (struct sockaddr *)&loop, sizeof(loop)) != 0) return 12;
    int accepted = accept(listener, NULL, NULL);
    if (accepted < 0) return 13;
    if (write(client, "tcp", 3) != 3 || read(accepted, buf, sizeof(buf)) != 3 || memcmp(buf, "tcp", 3) != 0) return 14;
    close(accepted); close(client); close(listener);

    int udp_a = socket(AF_INET, SOCK_DGRAM, 0);
    int udp_b = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_a < 0 || udp_b < 0) return 15;
    struct sockaddr_in udp_addr = {0};
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(udp_b, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) != 0) return 16;
    socklen_t udp_len = sizeof(udp_addr);
    if (getsockname(udp_b, (struct sockaddr *)&udp_addr, &udp_len) != 0) return 17;
    if (sendto(udp_a, "udp", 3, 0, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) != 3) return 18;
    memset(buf, 0, sizeof(buf));
    if (recvfrom(udp_b, buf, sizeof(buf), 0, NULL, NULL) != 3 || memcmp(buf, "udp", 3) != 0) return 19;
    close(udp_a); close(udp_b);

    puts("socket-test ok: socketpair, tcp, udp, epoll");
    return 0;
}
