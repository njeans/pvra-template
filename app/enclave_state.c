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


bool load_keys(const char *const keys_file) {
  //printf("[hcPVRA] Loading sealed state\n");
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status = read_file_into_memory(keys_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (pubkeys_buffer != NULL) {
    free(pubkeys_buffer);
    pubkeys_buffer = NULL;
  }

  /* Put new buffer into context */
  pubkeys_buffer = new_buffer;
  pubkeys_buffer_size = new_buffer_size;

  return ret_status;
}


bool load_seal(const char *const sealedstate_file) {
  printf("[hcPVRA] Loading sealed state from file\n");

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (sealed_state_buffer != NULL) {
    free(sealed_state_buffer);
    sealed_state_buffer = NULL;
  }

  /* Put new buffer into context */
  bool ret = read_file_into_memory(sealedstate_file, &sealed_state_buffer, &sealed_state_buffer_size);
  return ret;
}

bool load_sig(const char *const signedFT_file) {
  printf("[hcPVRA] Loading signedFT\n");
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status = read_file_into_memory(signedFT_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (signedFT_buffer != NULL) {
    free(signedFT_buffer);
    signedFT_buffer = NULL;
  }

  if (new_buffer_size != 8) {
    printf("[enclave_state.c] FT buffer size %lu != 8\n", new_buffer_size);
    return false;
  }
  /* Put new buffer into context */
  signedFT_buffer = new_buffer;

  return ret_status;
}

bool load_ft(const char *const FT_file) {
  //printf("[hcPVRA] Loading FT\n");
  void *new_buffer;
  size_t new_buffer_size;

  bool ret_status = read_file_into_memory(FT_file, &new_buffer, &new_buffer_size);

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (FT_buffer != NULL) {
    free(FT_buffer);
    FT_buffer = NULL;
  }

  /* Put new buffer into context */
  FT_buffer = new_buffer;
  FT_buffer_size = new_buffer_size;

  return ret_status;
}


bool load_cmd(const char *const eCMD_file) {
  printf("[hcPVRA] Loading eCMD\n");

  /* If we previously allocated a buffer, free it before putting new one in
   * its place */
  if (eCMD_buffer != NULL) {
    free(eCMD_buffer);
    eCMD_buffer = NULL;
  }

  /* Put new buffer into context */
  bool ret_status = read_file_into_memory(eCMD_file, &eCMD_buffer, &eCMD_buffer_size);

  return ret_status;
}

bool save_signature(const char *const signature_file, unsigned char *signature_src_buffer, size_t signature_src_buffer_size) {
  bool ret_status = true;
  FILE *file = NULL;

  if (signature_src_buffer_size != 64 && signature_src_buffer_size != 65) {
    fprintf(stderr,
            "[GatewayApp]: assertion failed: signature_src_buffer_size != 64 or 65\n");
    ret_status = false;
    goto cleanup;
  }

  file = open_file(signature_file, "wb");
  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_signature() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

  if (fwrite(signature_src_buffer, signature_src_buffer_size, 1, file) != 1) {
    fprintf(stderr, "GatewayApp]: ERROR: Could not write signature\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

cleanup:
  if (file != NULL) {
    fclose(file);
  }

  return ret_status;
}

bool save_message(void) {
  bool ret_status = true;
  FILE *file = NULL;
  file = open_file("enclave_enc_pubkey.bin", "wb");
  if (file == NULL) {
    fprintf(stderr, "[GatewayApp]: save_signature() fopen failed\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

  if (fwrite(enclave_pubkey_buffer, 64, 1, file) != 1) {
    fprintf(stderr, "GatewayApp]: ERROR: Could not write signature\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
    goto cleanup;
  }

cleanup:
  if (file != NULL) {
    fclose(file);
  }

  return ret_status;
}

bool save_quote(const char *const quote_file) {
  bool ret_status = true;

  printf("[GatewayApp]: Saving quote size: %lu\n", quote_buffer_size);

  FILE *fquote = open_file(quote_file, "wb");

  if (fquote == NULL) {
    fprintf(stderr, "[GatewayApp]: save_quote() fopen failed %s\n",quote_file);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  //printf("\n[GatewayApp]: MRENCLAVE: \n");
  if (fwrite((char *)quote_buffer, quote_buffer_size, 1, fquote) != 1) {
    fprintf(stderr, "[GatewayApp]: Quote only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(fquote);

  return ret_status;
}


bool save_seal(const char *const sealedstate_file) {

  bool ret_status = true;
  //printf("[Gateway]: saving sealed enclave state.\n");

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

bool save_sealO(const char *const sealedout_file) {

  bool ret_status = true;
  //printf("[hcPVRA] Persisting enclave state.\n");

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
  //printf("[Gateway]: saving cResponse.\n");

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

bool save_auditlog(const char *const auditlog_file) {

  bool ret_status = true;
  printf("[Gateway]: saving auditlog.\n");

  FILE *sk_file = open_file(auditlog_file, "wb");

  if (sk_file == NULL) {
    fprintf(stderr, "[Gateway]: save_auditlog()) fopen failed.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    return false;
  }

  if (fwrite(auditlog_buffer, auditlog_buffer_size, 1, sk_file) != 1) {
    fprintf(stderr, "[Gateway]: auditLog only partially written.\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
    ret_status = false;
  }

  fclose(sk_file);
  return ret_status;
}

bool format_sig(const char *const cRsig_file) {
  bool ret_status = true;
  ECDSA_SIG *ecdsa_sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  FILE *file = NULL;
  unsigned char *sig_buffer = NULL;
  int sig_len = 0;
  int sig_len2 = 0;

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


bool save_cRsig(const char *const cRsig_file) {
  bool ret_status = true;
  ECDSA_SIG *ecdsa_sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  FILE *file = NULL;
  unsigned char *sig_buffer = NULL;
  int sig_len = 0;
  int sig_len2 = 0;

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
