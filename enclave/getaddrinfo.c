
#include <string.h>
#include <netdb.h>
#include <openssl/ssl.h>

#include <sgx_error.h>

#include "enclave_t.h"
#include "enclave.h"

static uint32_t MAX_ADDRINFO_RET = 2;

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
    int ret;
    size_t max_ret = MAX_ADDRINFO_RET * (sizeof(struct addrinfo) + sizeof(struct sockaddr)) + strlen(node) + 1;
    uint8_t * addr_data = malloc(max_ret);
    int num_ret;
    sgx_status_t sgxres = ocall_getaddrinfo(&ret, node, service, hints, addr_data, max_ret, &num_ret);
    if(sgxres == SGX_SUCCESS && num_ret <= MAX_ADDRINFO_RET) {
        size_t offset = 0;
        struct addrinfo * ai, *prev = NULL;
        for (int i = 0; i < num_ret; i++) {
            ai = malloc(sizeof(struct addrinfo));
            memcpy(ai, addr_data + offset, sizeof(struct addrinfo));
            ai->ai_canonname = NULL;
            ai->ai_next = NULL;
            ai->ai_addr = NULL;
            struct sockaddr * sa = (struct sockaddr *) malloc(sizeof(struct sockaddr));
            memcpy(sa, addr_data + offset + sizeof(struct addrinfo), sizeof(struct sockaddr));
            offset += sizeof(struct addrinfo) + sizeof(struct sockaddr);
            ai->ai_addr = sa;
            if (prev)
                prev->ai_next = ai;
            if (i == 0){
                *result = ai;
            }
            prev = ai;
        }
        if (addr_data + offset) {
            char * canonname = addr_data + offset;
            size_t max_len = strlen(node);
            size_t canonname_size = strnlen(canonname, max_len) + 1;
            (*result)->ai_canonname = (char *) malloc(canonname_size);
            memset((*result)->ai_canonname, 0, canonname_size);
            memcpy((*result)->ai_canonname, canonname, canonname_size-1);
        }
    } else {
        ret = -1;
    }
    free(addr_data);
    addr_data = NULL;
    return ret;
}

void freeaddrinfo(struct addrinfo *ai) {
    struct addrinfo *rp, *next;
    if (ai){
        if (ai->ai_canonname) {
            free(ai->ai_canonname);
            ai->ai_canonname = NULL;
        }
        next = ai->ai_next;
        for (rp = ai; rp != NULL; rp = next) {
            next = rp->ai_next;
            free(rp->ai_addr);
            rp->ai_addr = NULL;
            free(rp);
        }
        ai = NULL;
    }
}