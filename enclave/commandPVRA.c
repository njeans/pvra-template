/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclavestate.h"

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */

sgx_status_t ecall_commandPVRA(
      char *sealedstate, size_t sealedstate_size, 
      char *signedFT, size_t signedFT_size, 
      char *eCMD, size_t eCMD_size, 
      char *eAESkey, size_t eAESkey_size, 
      char *cResponse, size_t cResponse_size) {


  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  // Step 1: Calculate sealed/encrypted data length.
  uint32_t unsealed_data_size =
      sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealedstate);
  uint8_t *const unsealed_data =
      (uint8_t *)malloc(unsealed_data_size); 
  // Check malloc return;
  if (unsealed_data == NULL) {
    print("\n[Enclave]: malloc(unsealed_data_size) failed !\n");
    return ret;
  }

  // Step 2: Unseal data.
  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealedstate, NULL, NULL,
                             unsealed_data, &unsealed_data_size)) !=
      SGX_SUCCESS) {
    print("\n[Enclave]: sgx_unseal_data() failed !\n");
    return ret;
  }

  struct ES *enclave_state;
  enclave_state = malloc(sizeof(struct ES));
  memcpy(enclave_state, unsealed_data, sizeof(struct ES));






  ocallrdtsc();
  ret = SGX_SUCCESS;

  return ret;
}
