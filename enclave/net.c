#include <netdb.h>
 #include <openssl/ssl.h>

#include <sgx_error.h>

#include "enclave_t.h"
#include "enclave.h"

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    int ret;
    struct addrinfo * result = malloc(sizeof(struct addrinfo));
    sgx_status_t sgxres = ocall_getaddrinfo(&ret, node, service, hints, result);
    if(sgxres == SGX_SUCCESS) {
        *res = result;
    }
    return ret;
}

void freeaddrinfo(struct addrinfo *ai) {
    if (ai)
        free(ai);
}

//  int SSL_connect(SSL *ssl) {
//     return -1;
//  }
