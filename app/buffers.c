/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include "app.h"
#include "appPVRA.h"

//#define INITSEALSIZE 7184
//#define INITSEALSIZE 7024

bool allocate_buffers(void) {
  printf("[agPVRA] Allocating buffers\n");
  signature_buffer_size = 65;
  signature_buffer = calloc(signature_buffer_size, 1);

  auditlog_buffer = calloc(auditlog_buffer_size, 1);

  auditlog_signature_buffer = calloc(65, 1);


  // if it is NULL it was not loaded from the seal state file
  if (sealed_state_buffer == NULL)
    sealed_state_buffer = calloc(sealed_state_buffer_size, 1);

  sealed_out_buffer = calloc(sealed_out_buffer_size, 1);

  enclave_pubkey_buffer = calloc(64, 1);
  enclave_pubkey_signature_buffer = malloc(64);
  user_addr_signature_buffer = malloc(65);
  cResponse_buffer_size = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + sizeof(struct cResponse);
  cResponse_buffer = calloc(cResponse_buffer_size, 1);

  cRsig_buffer = calloc(64, 1);

  FT_buffer_size = 64;
  FT_buffer = calloc(FT_buffer_size, 1);


  if (signature_buffer == NULL ||
      sealed_state_buffer == NULL ||
      cResponse_buffer == NULL ||
      sealed_out_buffer == NULL ||
      cRsig_buffer == NULL ||
      FT_buffer == NULL) {
    fprintf(stderr, "[agPVRA] allocate_buffers() memory allocation failure\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

void cleanup_buffers(void) {
  printf("[GatewayApp]: Deallocating buffers\n");



  if (signature_buffer != NULL) {
    free(signature_buffer);
    signature_buffer = NULL;
  }

  if (quote_buffer != NULL) {
    free(quote_buffer);
    quote_buffer = NULL;
  }

  if (sealed_state_buffer != NULL) {
    free(sealed_state_buffer);
    sealed_state_buffer = NULL;
  }

  if (signedFT_buffer != NULL) {
    free(signedFT_buffer);
    signedFT_buffer = NULL;
  }

  if (eCMD_buffer != NULL) {
    free(eCMD_buffer);
    eCMD_buffer = NULL;
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

  if (FT_buffer != NULL) {
    free(FT_buffer);
    FT_buffer = NULL;
  }

}
