/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"

bool allocate_buffers() {
  printf("[GatewayApp]: Allocating buffers\n");
  sealed_privkey_buffer = calloc(sealed_privkey_buffer_size, 1);
  public_key_buffer = calloc(public_key_buffer_size, 1);
  sealed_pubkey_buffer = calloc(sealed_pubkey_buffer_size, 1);
  signature_buffer = calloc(signature_buffer_size, 1);
  aes_gcm_key_buffer = calloc(aes_gcm_key_buffer_size, 1);
  encrypted_message_buffer = calloc(encrypt_decrypt_message_size, 1);
  decrypted_message_buffer = calloc(encrypt_decrypt_message_size, 1);
  json_student_buffer = calloc(json_student_buffer_size, 1);
  json_enclave_state_buffer = calloc(json_enclave_state_buffer_size, 1);



  sealed_state_buffer_size = 924;
  sealed_state_buffer = calloc(sealed_state_buffer_size, 1);

  if (sealed_privkey_buffer == NULL || sealed_pubkey_buffer == NULL ||
      signature_buffer == NULL || public_key_buffer == NULL ||
      aes_gcm_key_buffer == NULL || encrypted_message_buffer == NULL ||
      decrypted_message_buffer == NULL || json_student_buffer == NULL ||
      json_enclave_state_buffer == NULL) {
    fprintf(stderr,
            "[GatewayApp]: allocate_buffers() memory allocation failure\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

void cleanup_buffers() {
  printf("[GatewayApp]: Deallocating buffers\n");

  if (sealed_privkey_buffer != NULL) {
    free(sealed_privkey_buffer);
    sealed_privkey_buffer = NULL;
  }

  if (sealed_pubkey_buffer != NULL) {
    free(sealed_pubkey_buffer);
    sealed_pubkey_buffer = NULL;
  }

  if (public_key_buffer != NULL) {
    free(public_key_buffer);
    public_key_buffer = NULL;
  }

  if (signature_buffer != NULL) {
    free(signature_buffer);
    signature_buffer = NULL;
  }

  if (aes_gcm_key_buffer != NULL) {
    free(aes_gcm_key_buffer);
    signature_buffer = NULL;
  }

  if (encrypted_message_buffer != NULL) {
    free(encrypted_message_buffer);
    encrypted_message_buffer = NULL;
  }

  if (decrypted_message_buffer != NULL) {
    free(decrypted_message_buffer);
    decrypted_message_buffer = NULL;
  }

  if (json_student_buffer != NULL) {
    free(json_student_buffer);
    json_student_buffer = NULL;
  }

  if (quote_buffer != NULL) {
    free(quote_buffer);
    quote_buffer = NULL;
  }

  if (input_buffer != NULL) {
    free(input_buffer);
    input_buffer = NULL;
  }

  if (sealed_state_buffer != NULL) {
    free(sealed_state_buffer);
    sealed_state_buffer = NULL;
  }
}
