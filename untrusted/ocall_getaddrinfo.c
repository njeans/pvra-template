#include "enclave_u.h"
#include <stdio.h>
#include <netdb.h>

int ocall_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo* result) {
    struct addrinfo *res;
    int ret = getaddrinfo(node, service, hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(ret));
        return ret;
    }
    memcpy(result, res, sizeof(struct addrinfo));
    freeaddrinfo(res);
    return ret;
}

void ocall_gai_print_strerror(int errcode) {
    fprintf(stderr, "%s\n", gai_strerror(errcode));
}
