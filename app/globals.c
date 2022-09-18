/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "app.h"

/* Globals */

sgx_enclave_id_t enclave_id;
sgx_launch_token_t launch_token;
int launch_token_updated;
sgx_status_t sgx_lasterr;

void *public_key_buffer;
size_t public_key_buffer_size;
void *sealed_pubkey_buffer;
size_t sealed_pubkey_buffer_size;
void *sealed_privkey_buffer;
size_t sealed_privkey_buffer_size;
void *aes_gcm_key_buffer;
size_t aes_gcm_key_buffer_size = 16;
char * encrypted_message_buffer;
char * decrypted_message_buffer;
size_t encrypt_decrypt_message_size = 2048;
char * json_student_buffer;
size_t json_student_buffer_size = 2048;
char * json_enclave_state_buffer;
size_t json_enclave_state_buffer_size = 2048;

void *input_buffer;
size_t input_buffer_size;
void *quote_buffer;
size_t quote_buffer_size;


void *signature_buffer;
size_t signature_buffer_size;


void *sealed_state_buffer;
size_t sealed_state_buffer_size;


void *pub_enckey_buffer;
size_t pub_enckey_buffer_size;


void *signedFT_buffer;
size_t signedFT_buffer_size;
void *eCMD_buffer;
size_t eCMD_buffer_size;
void *eAESkey_buffer;
size_t eAESkey_buffer_size;



void *cResponse_buffer;
size_t cResponse_buffer_size;

void *sealed_out_buffer;
size_t sealed_out_buffer_size;


