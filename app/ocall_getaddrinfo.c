#include "enclave_u.h"
#include <stdio.h>
#include <netdb.h>
//#include "netdb.h"

int ocall_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo* result) {
    printf("\n<in ocall_getaddrinfo>\n");
    struct addrinfo *res, *rp;
    printf("hints.ai_flags %d\n", hints->ai_flags);
    printf("node %s\n", node);
    printf("service %s\n", service);
    int ret = getaddrinfo(node, service, hints, &res);
    if (ret != 0) {
        printf("getaddrinfo error: ");
        gai_strerror(ret);
        return ret;
    }
    memcpy(result, res, sizeof(struct addrinfo));
//    for (size_t i=0; i<max_num; i++) {
//        if (i > max_num || rp->ai_next == NULL) {
//            rp->ai_next = NULL;
//            printf("got %lu ++ addrinfo\n", i);
//            break;
//        }
//        rp = rp->ai_next;
//    }
//    result = &res;
    freeaddrinfo(res);
    return ret;
}

void ocall_gai_print_strerror(int errcode) {
    printf("\n<in ocall_gai_print_strerror>\n");
    printf("%s\n", gai_strerror(errcode));
}