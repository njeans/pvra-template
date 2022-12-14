#include <stdbool.h>

#include <openssl/ssl.h>


#ifndef __APPPVRA_H__
#define __APPPVRA_H__


#define NUM_COMMANDS 1
#define NUM_USERS 4

struct cInputs
{
};

struct cResponse
{
	uint32_t error;
	char message[100];
	uint64_t timestamp;
};

struct AD
{
};

uint64_t get_timestamp();
sgx_status_t initalize_ssl_context(SSL_CONF_CTX* ssl_conf_ctx, SSL_CTX* ctx);
#endif
