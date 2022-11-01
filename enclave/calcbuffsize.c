/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include "enclavestate.h"
#include <secp256k1_recovery.h>

/**
 * This function calculates the sizes of buffers needed for the untrusted app to
 * store data (public key, sealed private key and signature) from the enclave.
 *
 * @param epubkey_size            Output parameter for size of public key.
 * @param esealedprivkey_size     Output parameter for size of sealed private
 * key.
 * @param esignature_size         Output parameter for size of signature.
 * @param cResponse_size         Output parameter for size of cResponse struct.
 *
 * @return                        SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */

sgx_status_t ecall_calc_buffer_sizes(size_t *esignature_size, size_t *esignature_rec_size, size_t *esealed_state_size, size_t *cResponse_size) {
  *esignature_size = sizeof(secp256k1_ecdsa_signature);
  *esignature_rec_size = sizeof(secp256k1_ecdsa_recoverable_signature);
  *cResponse_size = sizeof(struct cResponse);
  struct ES enclave_state;
  struct dAppData dAD;
  int initES_ret = initES(&enclave_state, &dAD);

  uint32_t unsealed_data_size = sizeof(struct ES) + sizeof(struct dAppData);
  for(int i = 0; i < dAD.num_dDS; i++) {
    unsealed_data_size += sizeof(struct dynamicDS);
    unsealed_data_size += dAD.dDS[i]->buffer_size;
  }
  uint32_t init_seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);

  *esealed_state_size = init_seal_size;

  //printf("SAMPLED SIZE %d\n",*esignature_size);
  //printf("SAMPLED SIZE %d\n",init_seal_size);

  return SGX_SUCCESS;
}
