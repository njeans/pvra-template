#include <unistd.h>
#include "enclave_u.h"
#include <stdio.h>
#include <errno.h>

/* ocalls to use socket APIs , call socket syscalls */

int u_socket(int domain, int type, int protocol) {
    return socket(domain, type, protocol);
}

int u_connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen) {
    int res =  connect(sockfd, servaddr, addrlen);
    if (res != -1) {            /* No address succeeded */
        printf("failed to connect (errno=%d)\n", errno);
        return -1;
    }
    return res;
}

int u_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    return bind(fd, addr, len);
}

int u_listen(int fd, int n) {
    return listen(fd, n);
}

int u_accept(int fd, struct sockaddr *addr, socklen_t addrlen_in, socklen_t *addrlen_out) {
    int ret = -1;

    if ((ret = accept(fd, addr, &addrlen_in)) != -1) {
        if (addrlen_out) 
            *addrlen_out = addrlen_in;
    }
    return ret;
}

ssize_t u_send(int sockfd, const void *buf, size_t nbytes, int flags) {
    return send(sockfd, buf, nbytes, flags);
}

ssize_t u_recv(int sockfd, void *buf, size_t nbytes, int flags) {
    return recv(sockfd, buf, nbytes, flags);
}

int u_setsockopt( int sockfd, int level, int optname, const void *optval,socklen_t optlen) {
    return setsockopt(sockfd, level, optname, optval, optlen);
}

int u_close(int fd) {
    return close(fd);
}