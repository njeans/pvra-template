#include "enclave.h"

#include "enclave_t.h"
#include "sgx_trts.h"

/* support socket APIs inside enclave */

/* for socket APIs, refer to https://en.wikipedia.org/wiki/Berkeley_sockets */

int socket(int domain, int type, int protocol) {
    int ret = -1;

    if (u_socket(&ret, domain, type, protocol) == SGX_SUCCESS) 
        return ret;

    return -1;
}

int connect (int sockfd, const struct sockaddr *servaddr, socklen_t addrlen) {
    int ret = -1;
    if (u_connect(&ret, sockfd, servaddr, addrlen) == SGX_SUCCESS)
        return ret;

    return -1;
}

int bind(int sockfd, const struct sockaddr* servaddr, socklen_t addrlen) {
    int ret = -1;

    if (u_bind(&ret, sockfd, servaddr, addrlen) == SGX_SUCCESS)
        return ret;

    return -1;
}

int listen(int sockfd, int backlog) {
    int ret = -1;

    if (u_listen(&ret, sockfd, backlog) == SGX_SUCCESS)
        return ret;

    return -1;
}


int accept(int sockfd, struct sockaddr* addr, socklen_t *addrlen) {
    int ret = -1;
    socklen_t addrlen_in = 0;

    if ((addr && !addrlen) || (addrlen && !addr)) {
        return -1;
    }

    if (addr && addrlen) {
        addrlen_in = *addrlen;
    }

    if (u_accept(&ret, sockfd, addr, addrlen_in, addrlen) == SGX_SUCCESS)
        return ret;

    return -1;
}

ssize_t send(int sockfd, const void *buf, size_t nbytes, int flags)
{
    ssize_t ret = 0; 

    if (u_send(&ret, sockfd, buf, nbytes, flags) == SGX_SUCCESS)
        return ret;

    return -1;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    ssize_t ret = 0;

    if (u_recv(&ret, fd, buf, len, flags) == SGX_SUCCESS)
        return ret;
	
    return -1;
}

int setsockopt(int fd,int level, int optname, const void *optval, socklen_t optlen) {
    int ret = -1;

    //errno = 0;

    if (!optval || !optlen)
    {
     //   errno = EINVAL;
        return -1;
    }

    if (u_setsockopt(&ret, fd, level, optname, optval, optlen) != SGX_SUCCESS) {
      //  errno = EINVAL;
        return -1;
    }

    return ret;
}

int close(int sockfd) {
    int ret = -1;
    if (u_close(&ret, sockfd) == SGX_SUCCESS)
        return ret;

    return -1;
}
