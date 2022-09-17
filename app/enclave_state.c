/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"

bool load_enclave_state(const char *const statefile) {
  void *new_buffer;
  size_t new_buffer_size;

  printf("[GatewayApp]: Loading enclave state\n");

  bool ret_status =
      read_file_into_memory(statefile, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (sealed_privkey_buffer != NULL) {
    free(sealed_privkey_buffer);
    sealed_privkey_buffer = NULL;
  }

  /* Put new buffer into context */
  sealed_privkey_buffer = new_buffer;
  sealed_privkey_buffer_size = new_buffer_size;

  return ret_status;
}

bool load_sealed_data(const char *const sealed_data_file, void *buffer,
                      size_t buffer_size) {
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status =
      read_file_into_memory(sealed_data_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (buffer != NULL) {
    free(buffer);
    buffer = NULL;
  }

  /* Put new buffer into context */
  buffer = new_buffer;
  buffer_size = new_buffer_size;

  return ret_status;
}

bool load_sealedpubkey(const char *const sealedpubkey_file) {
  printf("[GatewayApp]: Loading sealed public key\n");
  // bool ret_status = load_sealed_data(sealedpubkey_file,
  // sealed_pubkey_buffer,
  //                                   sealed_pubkey_buffer_size);
  // return ret_status;
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status =
      read_file_into_memory(sealedpubkey_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (sealed_pubkey_buffer != NULL) {
    free(sealed_pubkey_buffer);
    sealed_pubkey_buffer = NULL;
  }

  /* Put new buffer into context */
  sealed_pubkey_buffer = new_buffer;
  sealed_pubkey_buffer_size = new_buffer_size;

  return ret_status;
}


bool save_sealed_state(const char *const sealedstate_file) {
  // bool ret_status = true;
  // ret_status = save_state(sealedprivkey_file, sealed_privkey_buffer,
  //                        sealed_privkey_buffer_size);
  // ret_status = save_state(sealedpubkey_file, sealed_pubkey_buffer,
  //                        sealed_pubkey_buffer_size);
  // return ret_status;
  bool ret_status = true;

  printf("[GatewayApp]: Saving sealed enclave state\n");

  FILE *sk_file = open_file(sealedstate_file, "wb");

  if (sk_file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(sealed_privkey_buffer, sealed_privkey_buffer_size, 1, sk_file) !=
      1) {
    fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(sk_file);

  printf("[GatewayApp]: Saving enclave state - sealed pub key\n");

  FILE *file = open_file(sealedstate_file, "wb");

  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(sealed_pubkey_buffer, sealed_pubkey_buffer_size, 1, file) != 1) {
    fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(file);

  return ret_status;
}

bool save_enclave_state(const char *const sealedprivkey_file,
                        const char *const sealedpubkey_file) {
  // bool ret_status = true;
  // ret_status = save_state(sealedprivkey_file, sealed_privkey_buffer,
  //                        sealed_privkey_buffer_size);
  // ret_status = save_state(sealedpubkey_file, sealed_pubkey_buffer,
  //                        sealed_pubkey_buffer_size);
  // return ret_status;
  bool ret_status = true;

  printf("[GatewayApp]: Saving enclave state - sealed priv key\n");

  FILE *sk_file = open_file(sealedprivkey_file, "wb");

  if (sk_file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(sealed_privkey_buffer, sealed_privkey_buffer_size, 1, sk_file) !=
      1) {
    fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(sk_file);

  printf("[GatewayApp]: Saving enclave state - sealed pub key\n");

  FILE *file = open_file(sealedpubkey_file, "wb");

  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(sealed_pubkey_buffer, sealed_pubkey_buffer_size, 1, file) != 1) {
    fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(file);

  return ret_status;
}

bool save_state(const char *const statefile, void *buffer, size_t buffer_size) {
  bool ret_status = true;

  printf("[GatewayApp]: Saving enclave state\n");

  FILE *file = open_file(statefile, "wb");

  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_enclave_state() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(buffer, buffer_size, 1, file) != 1) {
    fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(file);

  return ret_status;
}

bool save_aes_gcm_key(const char *const key_file) {
  bool ret_status = true;

  printf("[GatewayApp]: Saving AES GCM key to file\n");

  FILE *aes_key_file = open_file(key_file, "wb");

  if (aes_key_file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_aes_gcm_key() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(aes_gcm_key_buffer, aes_gcm_key_buffer_size, 1, aes_key_file) !=
      1) {
    fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(aes_key_file);

  return ret_status;
}

bool load_aes_128_key(const char *const statefile) {
  void *new_buffer;
  size_t new_buffer_size;
  uint8_t temp_aes_key_buffer[16]; // 16 bytes is the size of a 128-bit key

  printf("[GatewayApp]: Loading AES-128 key\n");

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (aes_gcm_key_buffer != NULL) {
    memcpy(temp_aes_key_buffer, aes_gcm_key_buffer, 16);
    free(aes_gcm_key_buffer);
    aes_gcm_key_buffer = NULL;
  }

  bool ret_status =
      read_file_into_memory(statefile, &new_buffer, &new_buffer_size);

  if (ret_status != 1 || new_buffer_size != 16) {
    memcpy(aes_gcm_key_buffer, temp_aes_key_buffer, 16);
    printf("[GatewayApp]: Error reading AES-128 key into buffer\n");
  } else {
    /* Put new buffer into context */
    aes_gcm_key_buffer = new_buffer;
    aes_gcm_key_buffer_size = new_buffer_size;
  }

  return ret_status;
}

bool save_text(char * text, size_t text_size, const char *const txt_file) {
  bool ret_status = true;

  printf("[GatewayApp]: Saving text to output file\n");

  FILE *txt_file_obj = open_file(txt_file, "wb");

  if (txt_file_obj == NULL) {
    fprintf(stderr, "[GatewayApp]: save_text() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(text, text_size, 1, txt_file_obj) !=
      1) {
    fprintf(stderr, "[GatewayApp]: Enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(txt_file_obj);

  return ret_status;
}

bool load_text(const char *const txt_file, char * text, size_t * text_size) {
  size_t new_buffer_size;
  printf("[GatewayApp]: Loading text file ");
  printf(txt_file);
  printf("\n");

  char * text_2;
  char ** text_3 = &text_2;
  bool ret_status = read_file_into_memory(txt_file, text_3, &new_buffer_size);
  *text_size = new_buffer_size;
  memcpy(text, *text_3, new_buffer_size);

  // return ret_status;
  return 1;
}
