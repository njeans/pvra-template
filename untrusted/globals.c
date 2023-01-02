#include "app.h"

/* Globals */
uint64_t tsc_dump[50];
int tsc_idx;

sgx_enclave_id_t enclave_id;
sgx_launch_token_t launch_token;
int launch_token_updated;
sgx_status_t sgx_lasterr;


void *quote_buffer = NULL;
size_t quote_buffer_size;

void *signature_buffer = NULL;
size_t signature_buffer_size;

void *sealed_state_buffer = NULL;
size_t sealed_state_buffer_size;


void *enclave_pubkey_buffer = NULL;


void *signedFT_buffer = NULL;
size_t signedFT_buffer_size;
void *eCMD_buffer = NULL;
size_t eCMD_buffer_size;



void *cResponse_buffer = NULL;
size_t cResponse_buffer_size;

void *cRsig_buffer = NULL;

void *sealed_out_buffer = NULL;
size_t sealed_out_buffer_size;


void *FT_buffer = NULL;
size_t FT_buffer_size;


void *pubkeys_buffer = NULL;
size_t pubkeys_buffer_size;

void *enclave_pubkey_signature_buffer = NULL;
void *user_addr_signature_buffer = NULL;

void *auditlog_buffer = NULL;
size_t auditlog_buffer_size;

void *auditlog_signature_buffer = NULL;


