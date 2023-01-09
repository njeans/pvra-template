#include <sys/socket.h>

#include "enclave.h"
#include "enclave_t.h"
#include "sgx_trts.h"


ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    ssize_t ret;
    sgx_status_t sgx_status = ocall_recv(&ret, sockfd, buf, len, flags);
    if (sgx_status == SGX_SUCCESS) {
        return ret;
    }
    return -1;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    ssize_t ret;
    sgx_status_t sgx_status = ocall_send(&ret, sockfd, buf, len, flags);
    if (sgx_status == SGX_SUCCESS) {
        return ret;
    }
    return -1;
}

int socket(int domain, int type, int protocol) {
    int ret;
    sgx_status_t sgx_status = ocall_socket(&ret, domain, type, protocol);
    if (sgx_status == SGX_SUCCESS) {
        return ret;
    }
    return -1;    
}

int connect (int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
    int ret;
    sgx_status_t sgx_status = ocall_connect(&ret, sockfd, servaddr, addrlen);
    if (sgx_status == SGX_SUCCESS)
        return ret;

    return -1;
}

int close(int sockfd) {
    int ret;
    if (ocall_close(&ret, sockfd) == SGX_SUCCESS)
        return ret;

    return -1;
}