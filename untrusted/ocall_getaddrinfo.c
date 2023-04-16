#include <stdio.h>
#include <netdb.h>
#include <string.h>

#include "enclave_u.h"

int ocall_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, uint8_t* addr_data, size_t res_size, int * num_ret) {
    struct addrinfo *result, *rp;
    int num = 0;
    memset(addr_data, 0, res_size);
    int ret = getaddrinfo(node, service, hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo() error: %s\n", gai_strerror(ret));
        return ret;
    }
    size_t offset = 0;
    size_t canonname_size = 0;
    if (result->ai_canonname){
        canonname_size = strlen(result->ai_canonname) + 1;
    }
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (offset + canonname_size + sizeof(struct addrinfo) + rp->ai_addrlen >= res_size) {
            break;
        }
        memcpy(addr_data + offset, rp, sizeof(struct addrinfo));
        memcpy(addr_data + offset + sizeof(struct addrinfo), rp->ai_addr, rp->ai_addrlen);
        offset += sizeof(struct addrinfo) + rp->ai_addrlen;
        num++;
    }
    *num_ret = num;
    if (result->ai_canonname) {
        memcpy(addr_data + offset, result->ai_canonname, canonname_size);
        offset += canonname_size;
    }
    freeaddrinfo(result);
    return ret;
}

void ocall_gai_print_strerror(int errcode) {
    fprintf(stderr, "%s\n", gai_strerror(errcode));
}
