#include "enclave_state.h"
#include "appPVRA.h"
#include "ca_bundle.h"
#include "enclave_t.h"

#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>


/* COMMAND0 Kernel Definition */
struct cResponse getTS(struct ES *enclave_state, struct cInputs *CI, uint32_t uidx)
{
    if(DEBUGPRINT) printf("[nts] getTS %d\n", uidx);
    struct cResponse ret;
    memset(ret.message, 0, 100);
    ret.error = 0;
    if(DEBUGPRINT) printf("[nts] getTS %d\n", uidx);

    uint64_t timestamp = get_timestamp();
    if (timestamp == 0) {
        ret.error = 1;
        sprintf(ret.message, "failed getTS %u", uidx);
    } else {
        sprintf(ret.message, "success getTS %u", uidx);
    }
    ret.timestamp = timestamp;

    return ret;
}

uint64_t get_timestamp() {

    sgx_status_t ret;
    int err;
    SSL* ssl_session = NULL;
    char* server_name = "www.google.com\0";//worldtimeapi.org
    char* server_port = "443\0";
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("[timestamp] SSL_CTX_new failed!\n");
        return 0;
    }
    if(DEBUGPRINT) printf("[nts] SSL_CTX_new\n");

    ret = initalize_ssl_context(ssl_confctx, ctx);
    if (ret != SGX_SUCCESS) {
        printf("[timestamp] initalize_ssl_context() failed!\n");
        return 0;
    }

    X509 * cert = NULL;
    unsigned char *ca_buff, *p;
    BIO *bio;
    bio = BIO_new(BIO_s_mem());
    BIO_puts(bio, default_ca_bundle);
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
//    BIO_free(bio);
//    bio = NULL;

//    ca_buff = (unsigned char *) malloc(sizeof(default_ca_bundle));
//    memcpy(ca_buff, default_ca_bundle, sizeof(default_ca_bundle));
//    p = ca_buff;
//    printf("%lu %s\n",sizeof(default_ca_bundle), ca_buff);
//    cert = NULL;
//    cert = d2i_X509(NULL, &p, sizeof(default_ca_bundle));
//    if (!d2i_X509(&cert, &p, sizeof(default_ca_bundle))) {
    if (cert == NULL) {
        printf("[timestamp] PEM_read_bio_X509() failed!\n");
        return 0;
    }
    err = SSL_CTX_use_certificate(ctx, cert);
    if (err != 1) {
        printf("[timestamp] SSL_CTX_use_certificate() failed!\n");
        return 0;
    }
    if(DEBUGPRINT) printf("[nts] SSL_CTX_use_certificate\n");
    free(ca_buff);
    ssl_session = SSL_new(ctx);
    if (ssl_session == NULL) {
        printf("[timestamp] SSL_new failed! ");
        printSSLError();
        return 0;
    }
    if(DEBUGPRINT) printf("[nts] SSL_new\n");

    int socketfd = create_socket(server_name, server_port);
    if (socketfd == -1) {
        printf("[timestamp] create_socket() failed!\n");
        return 0;
    }
    err = setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (0 > err) {
        printf("[timestamp] setsockopt() failed!\n");
        return 0;
    }
    if(DEBUGPRINT) printf("[nts] create_socket success\n");
    SSL_set_fd(ssl_session, socketfd);
    if(DEBUGPRINT) printf("[nts] create_socket z\n");
//    err = SSL_connect(ssl_session);
    if ((err = sgxssl_connect(ssl_session)) != 1){
        printf("[timestamp] SSL_connect() failed!\n");
        printSSLError();
        return 0;
    }
    if(DEBUGPRINT) printf("[nts] create_socket y\n");
//	err = SSL_do_handshake(ssl_session);
//    if (err != 1) {
//        printf("[timestamp] SSL_do_handshake() failed!\n");
//        printSSLError();
//        return 0;
//    }
    if(DEBUGPRINT) printf("[nts] SSL_connect success\n");
    unsigned char buf[200];
    int bytes_written = 0;
    int bytes_read = 0;
    int ssl_err = 0;
    size_t max_read_len = sizeof(buf) - 1;
    char * CLIENT_PAYLOAD = "GET /api/timezone/GMT HTTP/1.1\r\n\r\n\0";

    while ((bytes_written = SSL_write(ssl_session, CLIENT_PAYLOAD, sizeof(CLIENT_PAYLOAD))) <= 0) {
        ssl_err = SSL_get_error(ssl_session, bytes_written);
        if (ssl_err != SSL_ERROR_WANT_WRITE) {
            printf("[timestamp] Failed! SSL_write returned %d\n", ssl_err);
            return 0;
        }
    }
    if(DEBUGPRINT) printf("[timestamp] %d bytes written\n", bytes_written);

    while(1) {
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(ssl_session, buf, max_read_len);
        if (bytes_read <= 0) {
            ssl_err = SSL_get_error(ssl_session, bytes_read);
            if (ssl_err != SSL_ERROR_WANT_READ){
               printf("[timestamp] Failed! SSL_read returned %d\n", ssl_err);
               return 0;
            } else {
                break;
            }
        }
    }
    if(DEBUGPRINT) printf("[timestamp] %d bytes written\n", bytes_read);
    printf("[timestamp] %s\n", buf);

    uint64_t time = 12;
    return time;
}

unsigned long inet_addr2(const char *str)
{
    unsigned long lHost = 0;
    char *pLong = (char *)&lHost;
    char *p = (char *)str;
    while (p)
    {
        *pLong++ = atoi(p);
        p = strchr(p, '.');
        if (p)
            ++p;
    }
    return lHost;
}

int create_socket(char* server_name, char* server_port)
{
    int sockfd = -1;
	struct addrinfo hints, result;
    memset(&hints, 0, sizeof(struct addrinfo));

    int err;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;
    hints.ai_flags = 0;
    printf("a\n");
    err = getaddrinfo2(server_name, server_port, &hints, &result);
    printf("b\n");
    if (err != 0) {
        printf("[timestamp] Cannot gethostbyname ");
        gai_strerror_print(err);
        return -1;
    }
    printf("e %d %d %d\n",result.ai_family, result.ai_socktype, result.ai_protocol);
//    for (rp = result; rp != NULL; rp = rp->ai_next) {
    sockfd = socket(result.ai_family, result.ai_socktype, result.ai_protocol);
    if (sockfd == -1) {
        char errbuff[100];
        memset(errbuff, 0, 100);
//         printf("[timestamp] failed to connect to %s:%s (errno=%d,%u)\n", server_name, server_port, errno, errno);
        int answer = strerror_r(errno, errbuff, 100);
         printf("[timestamp] failed to create socket to %s:%s (errno=%s)\n", server_name, server_port, errbuff);
         return -1;
    }

    if (connect(sockfd, result.ai_addr, result.ai_addrlen) != -1) {
        printf("[timestamp] failed to connect to %s:%s (errno=%d)\n", server_name, server_port, errno);
        return -1;
    }

//    }
    if(DEBUGPRINT) printf("[timestamp] create socket %d\n", sockfd);

//    if (rp == NULL) {               /* No address succeeded */
//        printf("[timestamp] failed to connect to %s:%s (errno=%d)\n", server_name, server_port, errno);
//        return -1;
//    }
//    freeaddrinfo(result);

    if(DEBUGPRINT) printf("connected to %s:%s\n", server_name, server_port);
    return sockfd;
}

sgx_status_t initalize_ssl_context(SSL_CONF_CTX* ssl_conf_ctx, SSL_CTX* ctx)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // Configure the SSL context based on Open Enclave's security guidance.
    const char* cipher_list_tlsv12_below =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-"
        "AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-"
        "AES256-SHA384:"
        "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384";
    const char* cipher_list_tlsv13 =
        "TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
    const char* supported_curves = "P-521:P-384:P-256";

    SSL_CONF_CTX_set_ssl_ctx(ssl_conf_ctx, ctx);
    SSL_CONF_CTX_set_flags(
        ssl_conf_ctx,
        SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CLIENT);
    int ssl_conf_return_value = -1;
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MinProtocol", "TLSv1.3")) < 0)
    {
        printf("Setting MinProtocol for ssl context configuration failed with error %d \n", ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MaxProtocol", "TLSv1.3")) < 0)
    {
        printf("Setting MaxProtocol for ssl context configuration failed with error %d\n", ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "CipherString", cipher_list_tlsv12_below)) < 0)
    {
        printf("Setting CipherString for ssl context configuration failed with error %d\n", ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "Ciphersuites", cipher_list_tlsv13)) < 0)
    {
        printf("Setting Ciphersuites for ssl context configuration failed with error %d\n", ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "Curves", supported_curves)) < 0)
    {
        printf("Setting Curves for ssl context configuration failed with error %d\n", ssl_conf_return_value);
        goto exit;
    }
    if (!SSL_CONF_CTX_finish(ssl_conf_ctx))
    {
        printf("Error finishing ssl context configuration \n");
        goto exit;
    }
    ret = SGX_SUCCESS;
exit:
    return ret;
}

void printSSLError(void){
    SSL_load_error_strings();
    int sslerr = ERR_get_error();
    if (sslerr != 0){
        char buff[256];
        ERR_error_string_n(sslerr, buff, sizeof(buff));
        printf("%s", buff);
    }
    printf("\n");
}

/* Initializes the Function Pointers to Function Names Above */
int initFP(struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*)){
    (functions[0]) = &getTS;

  if(DEBUGPRINT) printf("Initialized Application Kernels\n");
  return 0;
}


/* Initializes the Application Data as per expectation */
int initES(struct ES* enclave_state, struct dAppData *dAD)
{
    dAD->num_dDS = 0;
    return 0;
}

int initAD(struct ES* enclave_state, struct dAppData *dAD)
{
    return 0;
}

void formatResponse(struct cResponse *ret, int error, char * message) {
    ret->error = error;
    memcpy(ret->message, message, 100);
}

/* Debug Print Statement to Visualize clientCommands */
void print_clientCommand(struct clientCommand *CC, uint32_t uidx){
  printf("[template] Readable eCMD: {[CT]:%d [CI]:%d [SN]:%lu}", CC->eCMD.CT, uidx, CC->seqNo);
}

