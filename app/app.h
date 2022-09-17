/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

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

extern sgx_enclave_id_t enclave_id;
extern sgx_launch_token_t launch_token;
extern int launch_token_updated;
extern sgx_status_t sgx_lasterr;

extern void *public_key_buffer;          /* unused for signing */
extern size_t public_key_buffer_size;    /* unused for signing */
extern void *sealed_pubkey_buffer;       /* unused for signing */
extern size_t sealed_pubkey_buffer_size; /* unused for signing */
extern void *sealed_privkey_buffer;
extern size_t sealed_privkey_buffer_size;
extern void *aes_gcm_key_buffer;
extern size_t aes_gcm_key_buffer_size;
extern char * encrypted_message_buffer;
extern char * decrypted_message_buffer;
extern size_t encrypt_decrypt_message_size;
extern char * json_student_buffer;
extern size_t json_student_buffer_size;
extern char * json_enclave_state_buffer;
extern size_t json_enclave_state_buffer_size;
extern void *signature_buffer;
extern size_t signature_buffer_size;
extern void *input_buffer;
extern size_t input_buffer_size;
extern void *quote_buffer;
extern size_t quote_buffer_size;

extern void *sealed_state_buffer;
extern size_t sealed_state_buffer_size;

/* Function prototypes */

bool initPVRA(void);

bool commandPVRA(void);

const char *decode_sgx_status(sgx_status_t status);

FILE *open_file(const char *const filename, const char *const mode);

bool create_enclave(const char *const enclave_binary);

bool enclave_get_buffer_sizes(void);

bool allocate_buffers(void);

bool read_file_into_memory(const char *const filename, void **buffer,
                           size_t *buffer_size);

bool load_enclave_state(const char *const statefile);

bool load_sealed_data(const char *const sealed_data_file, void *buffer,
                      size_t buffer_size);

bool load_sealedprivkey(const char *const sealedprivkey_file);

bool load_sealedpubkey(const char *const sealedpubkey_file);

bool load_input_file(const char *const input_file);

bool load_text(const char *const txt_file, char * text, size_t * text_size);

bool enclave_sign_data(void);

bool enclave_generate_key(void);

bool enclave_generate_key_vsc(void);

bool enclave_mbedtls_test(char  * enc_enclave_state_txt_file, char  * enc_client_input_txt_file);
bool enclave_verify_enclave_state_and_command_signature(char  * enc_enclave_state_txt_file, char  * enc_client_input_txt_file, 
                                                        char * signature_file, char * pub_key_txt_file, int counter);
bool enclave_sign_enclave_state_and_command(char  * enc_enclave_state_txt_file, char  * enc_client_input_txt_file, 
                                            int counter, char * priv_key_txt_file, char * signature_out_file);
bool enclave_generate_key_ecdsa(uint8_t * pub_key_out_file, uint8_t * priv_key_out_file);

size_t get_encrypted_buffer_size();
size_t get_decrypted_buffer_size();
bool copy_to_decrypted_buffer(uint8_t * decMessageIn, size_t messageSize);
bool copy_to_encrypted_buffer(uint8_t * encMessageIn, size_t messageSize);
bool encrypt_file(char * dec_txt_file_in, char * enc_txt_file_out);
bool decrypt_file(char * enc_txt_file_in, char * dec_txt_file_out);
bool enclave_encrypt_aes();
bool enclave_decrypt_aes();

bool create_student_json(char * name, char * uin);
bool encrypt_and_save_json_student(char * txt_file_out);
bool load_and_decrypt_json_student(char * txt_file_in);
bool test_json(char * s);

bool create_client_input_json(char * txt_file, int uuid, int command, char result);
bool create_enclave_state_json(char * txt_file);
bool enclave_enclave_state_add_counter_mismatch(char * enc_enclave_state_txt_file, char  * enc_client_input_txt_file, int delta);
bool encrypt_and_save_json_enclave_state(char * txt_file_out);
bool load_and_decrypt_json_enclave_state(char * txt_file_in);
bool add_user_json_enclave_state(char * txt_file);
bool test_ecall_vsc();

bool enclave_generate_quote(sgx_report_data_t report_data);
bool enclave_gen_quote();

// bool save_enclave_state(const char *const statefile);
bool save_enclave_state(const char *const sealedprivkey_file,
                        const char *const sealedpubkey_file);
bool save_state(const char *const statefile, void *buffer, size_t buffer_size);

bool save_aes_gcm_key(const char *const key_file);

bool save_text(char * text, size_t text_size, const char *const txt_file);

BIGNUM *bignum_from_little_endian_bytes_32(const unsigned char *const bytes);

bool save_signature(const char *const signature_file);

bool save_public_key(const char *const public_key_file);

bool save_quote(const char *const quote_file);

void destroy_enclave(void);

void cleanup_buffers(void);

// base64
char *base64_encode(const char *msg, size_t sz);
char *base64_decode(const char *msg, size_t *sz);

// hexutils
int from_hexstring(unsigned char *dest, const void *src, size_t len);
void print_hexstring(FILE *fp, const void *src, size_t len);
void print_hexstring_nl(FILE *fp, const void *src, size_t len);
const char *hexstring(const void *src, size_t len);

#endif /* !_APP_H */
