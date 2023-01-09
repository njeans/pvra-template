#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "enclave_u.h"

int ocall_socket(int domain, int type, int protocol) {
    return socket(domain, type, protocol);
}

int ocall_connect(int sockfd, const struct sockaddr *servaddr, socklen_t addrlen) {
    return connect(sockfd, servaddr, addrlen);
}

ssize_t ocall_recv(int sockfd, void *buf, size_t len, int flags) {
    return recv(sockfd, buf, len, flags);
}

ssize_t ocall_send(int sockfd, const void *buf, size_t nbytes, int flags) {
    return send(sockfd, buf, nbytes, flags);
}

int ocall_close(int fd) {
    return close(fd);
}
