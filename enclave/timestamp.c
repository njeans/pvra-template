#include <netdb.h>
#include <sys/socket.h>


#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>

#include "enclave_t.h"

#include "constants.h"
#include "ca_bundle.h"

static char *ciphers_list = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256\0";

#define _XOPEN_SOURCE 700

//todo add link to wolfssl example
#if defined(XMALLOC_USER) || defined(XMALLOC_OVERRIDE)
    #warning verification of heap hint pointers needed when overriding default malloc/free
#endif

#if defined(WOLFSSL_STATIC_MEMORY)
/* check on heap hint when used, aborts if pointer is not in Enclave.
 * In the default case where wolfSSL_Malloc is used the heap hint pointer is not
 * used.*/
static void checkHeapHint(WOLFSSL_CTX* ctx, WOLFSSL* ssl)
{
    WOLFSSL_HEAP_HINT* heap;
    if ((heap = (WOLFSSL_HEAP_HINT*)wolfSSL_CTX_GetHeap(ctx, ssl)) != NULL) {
        if(sgx_is_within_enclave(heap, sizeof(WOLFSSL_HEAP_HINT)) != 1)
            abort();
        if(sgx_is_within_enclave(heap->memory, sizeof(WOLFSSL_HEAP)) != 1)
            abort();
    }
}
#endif /* WOLFSSL_STATIC_MEMORY */


int get_time(char * datetime, struct tm * tm) {
    int res;
    char tmp[20];
    memcpy(tmp, datetime, 4);
    tmp[4] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm->tm_year = res;
    printf("year %s %d\n", tmp, tm->tm_year);
    memcpy(tmp, datetime + 5, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm->tm_mon = res;
    printf("month %s %d\n", tmp, tm->tm_mon);
    memcpy(tmp, datetime + 8, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm->tm_mday = res;
    printf("day %s %d\n", tmp, tm->tm_mday);
    memcpy(tmp, datetime + 11, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm->tm_hour = res;
    printf("hour %s %d\n", tmp, tm->tm_hour);
    memcpy(tmp, datetime + 14, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;    
    tm->tm_min = res;
    printf("min %s %d\n", tmp, tm->tm_min);
    memcpy(tmp, datetime + 17, 2);
    tmp[2] = 0;
    res = atoi(tmp);
    if (res == 0) return -1;
    tm->tm_sec = res;
    printf("sec %s %d\n", tmp, tm->tm_sec);
    return 0;
}

int worldtimeapi() {
    int err;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    char* server_name = "www.worldtimeapi.org";
    char* server_port = "443";
    char* send_buff = "GET api/timezone/GMT HTTP/1.1\r\nHost: www.worldtimeapi.org\n\n\r\n\0";
    WOLFSSL_CTX* ctx;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    err = getaddrinfo(server_name, server_port, &hints, &result);
    if (err != 0) {
        printf_stderr("worldtimeapi() getaddrinfo err %d\n", err);
        return -1;
    }

    int socketfd = create_socket(server_name, server_port);
    if (socketfd == -1) {
        printf_stderr("worldtimeapi() create_socket() failed!\n");
        return -1;
    }

    if(DEBUGPRINT) printf("worldtimeapi() create_socket success\n");


}

uint64_t timeapiio(struct tm * curr_time) {
    int err, ret, socketfd;
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_CTX* ctx = NULL;
    char buff[1024] = { 0 };
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    char* server_name = "www.timeapi.io\0";
    char* server_port = "443\0";
    char* send_buff = "GET /api/Time/current/zone?timeZone=UTC HTTP/1.1\r\nHost: www.timeapi.io\n\n\r\n\0";

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;
    
    err = getaddrinfo(server_name, server_port, &hints, &result);
    if (err != 0) {
        printf_stderr("timeapiio() getaddrinfo err %d\n", err);
        ret = 0;
        goto cleanup;
    }

    socketfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (socketfd == -1) {
        printf_stderr("timeapiio() socket() failed\n");
        ret = 0;
        goto cleanup;
    }

    if(DEBUGPRINT) printf("timeapiio() socket success\n");

    err = connect(socketfd, result->ai_addr, result->ai_addrlen);
    if (err != 0) {
        printf_stderr("timeapiio() connect failed\n");
        ret = err;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() connect success\n");
    // if(DEBUGPRINT) wolfSSL_Debugging_ON();

    err = wolfSSL_Init();
    if (err != SSL_SUCCESS) {
        printf_stderr("timeapiio() wolfSSL_Init err %d\n", err);
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_Init success\n");

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());

    if (ctx == NULL) {
        printf_stderr("timeapiio() wolfSSL_CTX_new err\n");
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_CTX_new success\n");


    err = wolfSSL_CTX_set_cipher_list(ctx, ciphers_list);
    if (err != SSL_SUCCESS) {
        printf_stderr("timeapiio() wolfSSL_Init err %d\n", err);
        ret = 0;
        goto cleanup;
    }

    err = wolfSSL_CTX_load_verify_buffer(ctx, default_ca_bundle, strlen(default_ca_bundle), SSL_FILETYPE_PEM);
    if (err != SSL_SUCCESS) {
        printf_stderr("timeapiio() wolfSSL_CTX_load_verify_buffer err %d\n", err);
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_CTX_load_verify_buffer success\n");

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf_stderr("timeapiio() wolfSSL_new err\n");
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_new success\n");

    err = wolfSSL_set_fd(ssl, socketfd);
    if (err != SSL_SUCCESS) {
        printf_stderr("timeapiio() wolfSSL_set_fd err %d\n", err);
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_set_fd success\n");

    err = wolfSSL_connect(ssl);
    if (err != SSL_SUCCESS) {
        printf("timeapiio() wolfSSL_connect err %d\n", err);
        printf_stderr("timeapiio() wolfSSL_connect err %d\n", err);
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_connect success\n");

    err = wolfSSL_write(ssl, send_buff, strlen(send_buff) + 1);
    if (err != strlen(send_buff) + 1) {
        printf_stderr("timeapiio() wolfSSL_write partial write %d != %d\n", err, strlen(send_buff) + 1);
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_write success\n");

    err = wolfSSL_read(ssl, buff, sizeof(buff)-1);
    if (err < 0) {
        printf_stderr("timeapiio() wolfSSL_read err %d\n", err);
        ret = 0;
        goto cleanup;
    }
    if(DEBUGPRINT) printf("timeapiio() wolfSSL_read success\n%s\n", buff);
    char * datetime = strstr(buff, "dateTime") + 11;
    if (datetime == NULL) {
        ret = -1;
    } else {
        printf("dateTime %s\n", datetime);
        ret = get_time(datetime, curr_time);
    }
    goto cleanup;


cleanup:
    if (result != NULL) {
        freeaddrinfo(result);
        result = NULL;
    }
    if (ssl != NULL) {
        wolfSSL_free(ssl);
        ssl = NULL;
    }
    if (ctx != NULL) {
        wolfSSL_CTX_free(ctx);
        ctx = NULL;
    }
    wolfSSL_Cleanup();
    return ret;
}


int get_timestamp(struct tm *curr_time) {
    return timeapiio(curr_time);
}