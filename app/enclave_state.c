/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

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

bool load_seal(const char *const sealedstate_file) {
  printf("[hcPVRA]: Loading sealed state\n");
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status = read_file_into_memory(sealedstate_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (sealed_state_buffer != NULL) {
    free(sealed_state_buffer);
    sealed_state_buffer = NULL;
  }

  /* Put new buffer into context */
  sealed_state_buffer = new_buffer;
  sealed_state_buffer_size = new_buffer_size;

  return ret_status;
}

bool load_sig(const char *const signedFT_file) {
  printf("[hcPVRA]: Loading signedFT\n");
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status = read_file_into_memory(signedFT_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (signedFT_buffer != NULL) {
    free(signedFT_buffer);
    signedFT_buffer = NULL;
  }

  /* Put new buffer into context */
  signedFT_buffer = new_buffer;
  signedFT_buffer_size = new_buffer_size;

  return ret_status;
}


bool load_cmd(const char *const eCMD_file) {
  printf("[hcPVRA]: Loading eCMD\n");
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status = read_file_into_memory(eCMD_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (eCMD_buffer != NULL) {
    free(eCMD_buffer);
    eCMD_buffer = NULL;
  }

  /* Put new buffer into context */
  eCMD_buffer = new_buffer;
  eCMD_buffer_size = new_buffer_size;

  return ret_status;
}

bool load_key(const char *const eAESkey_file) {
  printf("[hcPVRA]: Loading eAESkey\n");
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status = read_file_into_memory(eAESkey_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (eAESkey_buffer != NULL) {
    free(eAESkey_buffer);
    eAESkey_buffer = NULL;
  }

  /* Put new buffer into context */
  eAESkey_buffer = new_buffer;
  eAESkey_buffer_size = new_buffer_size;

  return ret_status;
}

bool save_sealed_state(const char *const sealedstate_file) {

  bool ret_status = true;
  printf("[Gateway]: saving sealed enclave state.\n");

  FILE *sk_file = open_file(sealedstate_file, "wb");

  if (sk_file == NULL) {
    fprintf(stderr, "[Gateway]: save_enclave_state() fopen failed.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(sealed_state_buffer, sealed_state_buffer_size, 1, sk_file) != 1) {
    fprintf(stderr, "[Gateway]: enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(sk_file);
  return ret_status;
}

bool save_sealedout_state(const char *const sealedout_file) {

  bool ret_status = true;
  printf("[Gateway]: saving sealed out enclave state.\n");

  FILE *sk_file = open_file(sealedout_file, "wb");

  if (sk_file == NULL) {
    fprintf(stderr, "[Gateway]: save_enclave_state() fopen failed.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(sealed_out_buffer, sealed_out_buffer_size, 1, sk_file) != 1) {
    fprintf(stderr, "[Gateway]: enclave state only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(sk_file);
  return ret_status;
}

bool save_cResponse(const char *const cResponse_file) {

  bool ret_status = true;
  printf("[Gateway]: saving cResponse.\n");

  FILE *sk_file = open_file(cResponse_file, "wb");

  if (sk_file == NULL) {
    fprintf(stderr, "[Gateway]: save_cResponse()) fopen failed.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(cResponse_buffer, cResponse_buffer_size, 1, sk_file) != 1) {
    fprintf(stderr, "[Gateway]: cResponse only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(sk_file);
  return ret_status;
}

bool save_cRsig(const char *const cRsig_file) {
  bool ret_status = true;
  ECDSA_SIG *ecdsa_sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  FILE *file = NULL;
  unsigned char *sig_buffer = NULL;
  int sig_len = 0;
  int sig_len2 = 0;

  if (cRsig_buffer_size != 64) {
    fprintf(stderr,
            "[GatewayApp]: assertion failed: signature_buffer_size == 64\n");
    ret_status = false;
    goto cleanup;
  }

  ecdsa_sig = ECDSA_SIG_new();
  if (ecdsa_sig == NULL) {
    fprintf(stderr, "[GatewayApp]: memory alloction failure ecdsa_sig\n");
    ret_status = false;
    goto cleanup;
  }

  r = bignum_from_little_endian_bytes_32((unsigned char *)cRsig_buffer);
  s = bignum_from_little_endian_bytes_32((unsigned char *)cRsig_buffer +
                                         32);
  if (!ECDSA_SIG_set0(ecdsa_sig, r, s)) {
    ret_status = false;
    goto cleanup;
  }

  sig_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
  if (sig_len <= 0) {
    ret_status = false;
    goto cleanup;
  }

  sig_len2 = i2d_ECDSA_SIG(ecdsa_sig, &sig_buffer);
  if (sig_len != sig_len2) {
    ret_status = false;
    goto cleanup;
  }

  file = open_file(cRsig_file, "wb");
  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_signature() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

  if (fwrite(sig_buffer, (size_t)sig_len, 1, file) != 1) {
    fprintf(stderr, "GatewayApp]: ERROR: Could not write signature\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

cleanup:
  if (file != NULL) {
    fclose(file);
  }
  if (ecdsa_sig) {
    ECDSA_SIG_free(ecdsa_sig); /* Above will also free r and s */
  }
  if (sig_buffer) {
    free(sig_buffer);
  }

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
