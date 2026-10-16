#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"socket-edge:%d: %s errno=%d\n",__LINE__,#x,errno); return 1; } } while(0)
static volatile sig_atomic_t pipes;
static void sigpipe(int sig) { (void)sig; pipes++; }
static long long now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec*1000LL+t.tv_nsec/1000000; }
extern char **environ;

int main(int argc, char **argv) {
    if(argc==5) {
        CHECK(fcntl(atoi(argv[2]),F_GETFD)==-1 && errno==EBADF);
        CHECK(fcntl(atoi(argv[3]),F_GETFD)>=0);
        CHECK(fcntl(atoi(argv[4]),F_GETFD)==-1 && errno==EBADF);
        puts("socket-edge-test ok: IPv6, connect/SO_ERROR, accept4, options/timeouts, UDP messages, EFAULT, SIGPIPE and exec");
        return 0;
    }
    int one=1, value=0; socklen_t size=sizeof(value);
    int listener=socket(AF_INET6,SOCK_STREAM|SOCK_NONBLOCK,0);
    CHECK(listener>=0);
    CHECK(setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one))==0);
    CHECK(getsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&value,&size)==0 && value==1 && size==4);
    CHECK(setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&one,1)==-1 && errno==EINVAL);
    struct sockaddr_in6 loop={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
    CHECK(bind(listener,(struct sockaddr *)&loop,sizeof(loop))==0);
    CHECK(listen(listener,4)==0);
    size=sizeof(loop); CHECK(getsockname(listener,(struct sockaddr *)&loop,&size)==0 && size==28);
    int client=socket(AF_INET6,SOCK_STREAM|SOCK_NONBLOCK,0); CHECK(client>=0);
    struct sockaddr_in6 local={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
    CHECK(bind(client,(struct sockaddr *)&local,sizeof(local))==0);
    size=sizeof(local); CHECK(getsockname(client,(struct sockaddr *)&local,&size)==0);
    int result=connect(client,(struct sockaddr *)&loop,sizeof(loop)); CHECK(result==0 || (result==-1 && errno==EINPROGRESS));
    struct pollfd poller={.fd=client,.events=POLLOUT}; CHECK(poll(&poller,1,1000)==1);
    size=4; CHECK(getsockopt(client,SOL_SOCKET,SO_ERROR,&value,&size)==0 && value==0);
    CHECK(connect(client,(struct sockaddr *)&loop,sizeof(loop))==-1 && errno==EISCONN);
    CHECK(setsockopt(client,IPPROTO_TCP,TCP_NODELAY,&one,4)==0);
    size=4; CHECK(getsockopt(client,IPPROTO_TCP,TCP_NODELAY,&value,&size)==0 && value==1);
    struct sockaddr_in6 peer={0}; size=2;
    int accepted=accept4(listener,(struct sockaddr *)&peer,&size,SOCK_NONBLOCK|SOCK_CLOEXEC);
    CHECK(accepted>=0 && size==28 && peer.sin6_family==AF_INET6);
    CHECK((fcntl(accepted,F_GETFL)&(O_NONBLOCK|O_ACCMODE))==(O_NONBLOCK|O_RDWR));
    CHECK(fcntl(accepted,F_GETFD)&FD_CLOEXEC);
    size=sizeof(peer); CHECK(getpeername(accepted,(struct sockaddr *)&peer,&size)==0 && peer.sin6_port==local.sin6_port);
    CHECK(fcntl(accepted,F_SETFL,0)==0);
    struct timeval timeout={.tv_usec=30000}, got={0};
    CHECK(setsockopt(accepted,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
    size=sizeof(got); CHECK(getsockopt(accepted,SOL_SOCKET,SO_RCVTIMEO,&got,&size)==0 && got.tv_usec==30000);
    char data[32]; long long start=now_ms();
    CHECK(recv(accepted,data,1,0)==-1 && errno==EAGAIN && now_ms()-start>=20 && now_ms()-start<1500);
    timeout.tv_usec=1000000; CHECK(setsockopt(accepted,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==-1 && errno==EINVAL);
    CHECK(send(client,"peek",4,MSG_NOSIGNAL)==4);
    CHECK(recv(accepted,data,2,MSG_PEEK)==2 && !memcmp(data,"pe",2));
    CHECK(recv(accepted,data,4,0)==4 && !memcmp(data,"peek",4));
    CHECK(recv(accepted,data,1,MSG_DONTWAIT)==-1 && errno==EAGAIN);
    CHECK(send(client,data,1,MSG_OOB)==-1 && errno==EOPNOTSUPP);
    CHECK(shutdown(client,SHUT_WR)==0);
    poller=(struct pollfd){.fd=accepted,.events=POLLIN|POLLRDHUP}; CHECK(poll(&poller,1,1000)==1 && (poller.revents&POLLRDHUP));
    CHECK(read(accepted,data,1)==0);
    close(client); close(accepted); close(listener);
    fprintf(stderr,"stage: IPv6 TCP and timeouts\n");

    // A closed, dynamically allocated port supplies a deterministic refusal.
    listener=socket(AF_INET,SOCK_STREAM,0); CHECK(listener>=0);
    struct sockaddr_in ipv4={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener,(struct sockaddr *)&ipv4,sizeof(ipv4))==0);
    size=sizeof(ipv4); CHECK(getsockname(listener,(struct sockaddr *)&ipv4,&size)==0); close(listener);
    client=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0); CHECK(client>=0);
    result=connect(client,(struct sockaddr *)&ipv4,sizeof(ipv4)); CHECK(result==-1 && (errno==EINPROGRESS || errno==ECONNREFUSED));
    poller=(struct pollfd){.fd=client,.events=POLLOUT}; CHECK(poll(&poller,1,5000)==1);
    size=4; CHECK(getsockopt(client,SOL_SOCKET,SO_ERROR,&value,&size)==0 && value==ECONNREFUSED);
    size=4; result=getsockopt(client,SOL_SOCKET,SO_ERROR,&value,&size);
    if(result || value) fprintf(stderr,"SO_ERROR second: result=%d value=%d size=%u\n",result,value,size);
    CHECK(result==0 && value==0); close(client);

    int receiver=socket(AF_INET,SOCK_DGRAM,0), sender=socket(AF_INET,SOCK_DGRAM,0); CHECK(receiver>=0 && sender>=0);
    ipv4.sin_port=0; CHECK(bind(receiver,(struct sockaddr *)&ipv4,sizeof(ipv4))==0);
    size=sizeof(ipv4); CHECK(getsockname(receiver,(struct sockaddr *)&ipv4,&size)==0);
    struct iovec out[2]={{"abc",3},{"def",3}};
    struct msghdr msg={.msg_name=&ipv4,.msg_namelen=sizeof(ipv4),.msg_iov=out,.msg_iovlen=2};
    CHECK(sendmsg(sender,&msg,MSG_NOSIGNAL)==6);
    void *bad=mmap(0,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); CHECK(bad!=MAP_FAILED);
    CHECK(recvfrom(receiver,bad,1,0,0,0)==-1 && errno==EFAULT);
    struct iovec in={0}; in.iov_base=data;in.iov_len=3;
    struct sockaddr_in source={0};
    msg=(struct msghdr){.msg_name=&source,.msg_namelen=sizeof(source),.msg_iov=&in,.msg_iovlen=1};
    CHECK(recvmsg(receiver,&msg,MSG_TRUNC)==6 && (msg.msg_flags&MSG_TRUNC) && msg.msg_namelen==16 && source.sin_family==AF_INET && !memcmp(data,"abc",3));
    CHECK(sendto(sender,"x",1,0,(struct sockaddr *)&ipv4,sizeof(ipv4))==1);
    size=16; CHECK(recvfrom(receiver,data,1,0,bad,&size)==-1 && errno==EFAULT);
    CHECK(recvfrom(receiver,data,1,0,0,0)==1 && data[0]=='x');
    msg.msg_control=data;msg.msg_controllen=1; CHECK(recvmsg(receiver,&msg,0)==-1 && errno==EOPNOTSUPP);
    CHECK(socketpair(AF_UNIX,SOCK_STREAM,1,(int *)data)==-1);
    munmap(bad,4096);close(receiver);close(sender);
    fprintf(stderr,"stage: SO_ERROR, UDP messages and bad pointers\n");
    int pair[2]; CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    CHECK(signal(SIGPIPE,sigpipe)!=SIG_ERR); CHECK(shutdown(pair[0],SHUT_WR)==0);
    CHECK(send(pair[0],"x",1,MSG_NOSIGNAL)==-1 && errno==EPIPE && pipes==0);
    CHECK(write(pair[0],"x",1)==-1 && errno==EPIPE && pipes==1);
    CHECK(fcntl(pair[0],F_SETFD,FD_CLOEXEC)==0);
    int ep=epoll_create1(EPOLL_CLOEXEC);CHECK(ep>=0);
    char a[16],b[16],c[16];snprintf(a,sizeof(a),"%d",pair[0]);snprintf(b,sizeof(b),"%d",pair[1]);snprintf(c,sizeof(c),"%d",ep);
    char *next[]={argv[0],"--exec",a,b,c,0};
    execve(argv[0],next,environ);CHECK(0);
}
