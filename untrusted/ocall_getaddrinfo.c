#include "enclave_u.h"
#include <stdio.h>
#include <netdb.h>

int ocall_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo* result) {
    struct addrinfo *res;
    int ret = getaddrinfo(node, service, hints, &res);
    if (ret != 0) {
        printf("getaddrinfo error: %s\n", gai_strerror(ret));
        return ret;
    }
    memcpy(result, res, sizeof(struct addrinfo));
    freeaddrinfo(res);
    return ret;
}

void ocall_gai_print_strerror(int errcode) {
    printf("%s\n", gai_strerror(errcode));
}

int ocall_test(struct addrinfo *res, size_t max_return) {
    uint8_t * s = (uint8_t *) malloc(max_return);
    for (size_t i = 0; i < max_return; i++)
    {
        s[i] = 'G';
    }
    memcpy(res, s, max_return);    
    return 0;
}
