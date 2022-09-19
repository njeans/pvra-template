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



  sealed_state_buffer_size = 6912;
  sealed_state_buffer = calloc(sealed_state_buffer_size, 1);

  sealed_out_buffer_size = 6912;
  sealed_out_buffer = calloc(sealed_out_buffer_size, 1);

  pub_enckey_buffer_size = 451;
  pub_enckey_buffer = calloc(pub_enckey_buffer_size, 1);

  cResponse_buffer_size = 1;
  cResponse_buffer = calloc(cResponse_buffer_size, 1);

  cRsig_buffer_size = signature_buffer_size;
  cRsig_buffer = calloc(cRsig_buffer_size, 1);



/*void *signedFT_buffer;
size_t signedFT_buffer_size;
void *eCMD_buffer;
size_t eCMD_buffer_size;
void *eAESkey_buffer;
size_t eAESkey_buffer_size;



void *cResponse_buffer;
size_t cResponse_buffer_size;

void *sealed_out_buffer;
size_t sealed_out_buffer_size;
*/


  if (sealed_privkey_buffer == NULL || sealed_pubkey_buffer == NULL ||
      signature_buffer == NULL || public_key_buffer == NULL ||
      aes_gcm_key_buffer == NULL || encrypted_message_buffer == NULL ||
      decrypted_message_buffer == NULL || json_student_buffer == NULL ||
      json_enclave_state_buffer == NULL || pub_enckey_buffer == NULL || 
      sealed_state_buffer == NULL
      || cResponse_buffer == NULL
      || sealed_out_buffer == NULL
      || cRsig_buffer == NULL
      ) {
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

  if (pub_enckey_buffer != NULL) {
    free(pub_enckey_buffer);
    pub_enckey_buffer = NULL;
  }

  if (signedFT_buffer != NULL) {
    free(signedFT_buffer);
    signedFT_buffer = NULL;
  }

  if (eCMD_buffer != NULL) {
    free(eCMD_buffer);
    eCMD_buffer = NULL;
  }

  if (eAESkey_buffer != NULL) {
    free(eAESkey_buffer);
    eAESkey_buffer = NULL;
  }

  if (cResponse_buffer != NULL) {
    free(cResponse_buffer);
    cResponse_buffer = NULL;
  }

  if (cRsig_buffer != NULL) {
    free(cRsig_buffer);
    cRsig_buffer = NULL;
  }

  if (sealed_out_buffer != NULL) {
    free(sealed_out_buffer);
    sealed_out_buffer = NULL;
  }

}
