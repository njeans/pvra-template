/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

size_t get_encrypted_buffer_size() {
  size_t lenEnc = encrypt_decrypt_message_size;
  for (int i = encrypt_decrypt_message_size; i > 0; i--) {
    if (encrypted_message_buffer[i - 1] != 0) {
      lenEnc = i;
      break;
    }
  }
  return lenEnc;
}

size_t get_decrypted_buffer_size() {
  size_t lenDec = encrypt_decrypt_message_size;
  for (int i = encrypt_decrypt_message_size; i > 0; i--) {
    if (decrypted_message_buffer[i - 1] != 0) {
      lenDec = i;
      break;
    }
  }
  return lenDec;
}

bool copy_to_decrypted_buffer(uint8_t * decMessageIn, size_t messageSize) {
  // calculate the size of the decrypted message
  size_t lenMsg = messageSize;
  if (lenMsg > encrypt_decrypt_message_size) {
    printf("\n[GatewayApp]: Message to be copied to decryption buffer is too large!\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return (sgx_lasterr == SGX_SUCCESS);
  }
  memset(decrypted_message_buffer, 0, encrypt_decrypt_message_size);
  memcpy(decrypted_message_buffer, decMessageIn, lenMsg);
  return (sgx_lasterr == SGX_SUCCESS);
}

bool copy_to_encrypted_buffer(uint8_t * encMessageIn, size_t messageSize) {
  // Calculate the size of the encrypted message
  size_t lenEnc = messageSize;
  if (lenEnc > encrypt_decrypt_message_size) {
    printf("\n[GatewayApp]: Message to be copied to encryption buffer is too large!\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return (sgx_lasterr == SGX_SUCCESS);
  }
  memset(encrypted_message_buffer, 0, encrypt_decrypt_message_size);
  memcpy(encrypted_message_buffer, encMessageIn, lenEnc);
  return (sgx_lasterr == SGX_SUCCESS);
}

bool encrypt_file(char * dec_txt_file_in, char * enc_txt_file_out) {
  size_t text_size;
  char text[encrypt_decrypt_message_size];
  memset(text, 0, encrypt_decrypt_message_size);

  bool success = (
    load_text(dec_txt_file_in, text, &text_size) &&
    copy_to_decrypted_buffer(text, text_size) &&
    enclave_encrypt_aes() &&
    save_text(encrypted_message_buffer, get_encrypted_buffer_size(), enc_txt_file_out)
  );
  return success;
}

bool decrypt_file(char * enc_txt_file_in, char * dec_txt_file_out) {
  size_t text_size;
  char text[encrypt_decrypt_message_size];
  memset(text, 0, encrypt_decrypt_message_size);

  bool success = (
    load_text(enc_txt_file_in, text, &text_size) &&
    copy_to_encrypted_buffer(text, text_size) &&
    enclave_decrypt_aes() &&
    save_text(decrypted_message_buffer, strlen(decrypted_message_buffer), dec_txt_file_out)
  );
  return success;
}

bool enclave_encrypt_aes() {
  memset(encrypted_message_buffer, 0, encrypt_decrypt_message_size);
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  size_t lenDec = get_decrypted_buffer_size();
  if (lenDec >= encrypt_decrypt_message_size) {
    printf("\n[GatewayApp]: Message to be encrypted is too large!\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return (sgx_lasterr == SGX_SUCCESS);
  }

  printf("\n[GatewayApp]: Calling enclave to encrypt data\n");

  /*
   * Invoke ECALL, 'ecall_encrypt_aes()', to generate a key
   */
  sgx_lasterr = ecall_encrypt_aes(enclave_id, &ecall_retval, 
    aes_gcm_key_buffer, decrypted_message_buffer, lenDec, encrypted_message_buffer);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_encrypt_aes returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

bool enclave_decrypt_aes() {
  memset(decrypted_message_buffer, 0, encrypt_decrypt_message_size);
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  size_t lenEnc = get_encrypted_buffer_size();
  if (lenEnc >= encrypt_decrypt_message_size) {
    printf("\n[GatewayApp]: Message to be decrypted is too large!\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return (sgx_lasterr == SGX_SUCCESS);
  }

  printf("\n[GatewayApp]: Calling enclave to encrypt data\n");

  /*
   * Invoke ECALL, 'ecall_decrypt_aes()', to generate a key
   */
  sgx_lasterr = ecall_decrypt_aes(enclave_id, &ecall_retval, 
    aes_gcm_key_buffer, encrypted_message_buffer, lenEnc, decrypted_message_buffer);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_key_gen_and_seal returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}