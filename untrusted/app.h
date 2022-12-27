#ifndef _APP_H
#define _APP_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include <openssl/bn.h>

#include <sgx_quote.h>
#include <sgx_uae_epid.h>
#include <sgx_urts.h>

/* Globals */

#define AESGCM_128_MAC_SIZE 16
#define AESGCM_128_IV_SIZE 12
#define HASH_SIZE 32

extern sgx_enclave_id_t enclave_id;
extern sgx_launch_token_t launch_token;
extern int launch_token_updated;
extern sgx_status_t sgx_lasterr;

extern uint64_t tsc_dump[50];
extern int tsc_idx;

extern void *signature_buffer;
extern size_t signature_buffer_size;

extern void * enclave_pubkey_signature_buffer;
extern void * user_addr_signature_buffer;

extern void *quote_buffer;
extern size_t quote_buffer_size;

extern void *sealed_state_buffer;
extern size_t sealed_state_buffer_size;

extern void *enclave_pubkey_buffer;


extern void *signedFT_buffer;
extern size_t signedFT_buffer_size;
extern void *eCMD_buffer;
extern size_t eCMD_buffer_size;

extern void *cResponse_buffer;
extern size_t cResponse_buffer_size;
extern void *cRsig_buffer;


extern void *sealed_out_buffer;
extern size_t sealed_out_buffer_size;

extern void *FT_buffer;
extern size_t FT_buffer_size;

extern void *pubkeys_buffer;
extern size_t pubkeys_buffer_size;

extern void *auditlog_buffer;
extern size_t auditlog_buffer_size;

extern void *auditlog_signature_buffer;


/* Function prototypes */

bool initPVRA(uint64_t num_users);
bool commandPVRA(void);
bool auditlogPVRA(void);

const char *decode_sgx_status(sgx_status_t status);

bool create_enclave(const char *const enclave_binary);

bool enclave_get_init_buffer_sizes(uint64_t num_users);
bool enclave_get_cmd_buffer_sizes(void);
bool enclave_get_audit_buffer_sizes(void);

bool allocate_buffers(void);

bool read_file_into_memory(const char *const filename, void **buffer,
                           size_t *buffer_size);

bool load_seal(const char *const sealedstate_file);

bool load_keys(const char *const keys_file);

bool load_ft(const char *const FT_file);

bool load_sig(const char *const signedFT_file);

bool load_cmd(const char *const eCMD_file);

bool format_sig(const char *const sig_file);

// bool save_enclave_state(const char *const statefile);
bool save_enclave_state(const char *const sealedprivkey_file,
                        const char *const sealedpubkey_file);

BIGNUM *bignum_from_little_endian_bytes_32(const unsigned char *const bytes);

bool save_signature(const char *const signature_file, unsigned char *signature_src_buffer, size_t signature_size);

bool save_public_key(const char *const public_key_file);

bool save_quote(const char *const quote_file);

bool save_seal(const char *const sealedstate_file);

bool save_sealO(const char *const sealedout_file);

bool save_enclave_key(void);

bool save_cResponse(const char *const cResponse_file);

bool save_auditlog(const char *const auditlog_file);

void destroy_enclave(void);

void cleanup_buffers(void);

// base64
char *base64_encode(const char *msg, size_t sz);
char *base64_decode(const char *msg, size_t *sz);

// hexutils
int from_hexstring(unsigned char *dest, const void *src, size_t len);
void print_hexstring(FILE *fp, const void *src, size_t len);
void print_hexstring_nl(FILE *fp, const void *src, size_t len);

#endif /* !_APP_H */
