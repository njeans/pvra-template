#include <stdio.h>
#include <stdlib.h>

#include "app.h"
#include "appPVRA.h"


bool allocate_buffers(void) {
  printf("[agPVRA] Allocating buffers\n");
  signature_buffer_size = 65;
  signature_buffer = malloc(signature_buffer_size);

  auditlog_buffer = malloc(auditlog_buffer_size);

  auditlog_signature_buffer = malloc(65);


  // if it is NULL it was not loaded from the seal state file
  if (sealed_state_buffer == NULL)
    sealed_state_buffer = malloc(sealed_state_buffer_size);

  sealed_out_buffer = malloc(sealed_out_buffer_size);

  enclave_pubkey_buffer = malloc(64);
  enclave_pubkey_signature_buffer = malloc(64);
  user_addr_signature_buffer = malloc(65);
  cResponse_buffer_size = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + sizeof(struct cResponse);
  cResponse_buffer = malloc(cResponse_buffer_size);

  cRsig_buffer = malloc(64);


  if (signature_buffer == NULL ||
      auditlog_buffer == NULL ||
      auditlog_signature_buffer == NULL ||
      sealed_state_buffer == NULL ||
      sealed_out_buffer == NULL ||
      enclave_pubkey_buffer == NULL ||
      enclave_pubkey_signature_buffer == NULL ||
      user_addr_signature_buffer == NULL ||
      cResponse_buffer == NULL ||
      cRsig_buffer == NULL) {
    fprintf(stderr, "[agPVRA] allocate_buffers() memory allocation failure\n");
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  return (sgx_lasterr == SGX_SUCCESS);
}

void cleanup_buffers(void) {
  printf("Deallocating buffers\n");

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

  if (auditlog_buffer != NULL) {
    free(auditlog_buffer);
    auditlog_buffer = NULL;
  }

  if (auditlog_signature_buffer != NULL) {
    free(auditlog_signature_buffer);
    auditlog_signature_buffer = NULL;
  }

  if (FT_buffer != NULL) {
    free(FT_buffer);
    FT_buffer = NULL;
  }

  if (enclave_pubkey_buffer != NULL) {
    free(enclave_pubkey_buffer);
    enclave_pubkey_buffer = NULL;
  }

  if (enclave_pubkey_signature_buffer != NULL) {
    free(enclave_pubkey_signature_buffer);
    enclave_pubkey_signature_buffer = NULL;
  }

  if (pubkeys_buffer != NULL) {
    free(pubkeys_buffer);
    pubkeys_buffer = NULL;
  }

  if (user_addr_signature_buffer != NULL) {
    free(user_addr_signature_buffer);
    user_addr_signature_buffer = NULL;
  }

}
