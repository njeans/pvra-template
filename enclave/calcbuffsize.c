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

#include "enclave_state.h"

#ifdef MERKLE_TREE
#include "merkletree.h"
#endif

#ifdef MERKLE_TREE
size_t calc_auditlog_buffer_size(struct ES * enclave_state, merkle_tree * mt, size_t * mt_size) {

  char *data[NUM_USERS];
  size_t block_size = get_user_leaf(enclave_state, &data);
  if(DEBUGPRINT) {
      printf("[eaPVRA] PRINTING User Leaf Nodes leaf_size: %d %p\n", block_size, data);
      for(int i = 0; i < NUM_USERS; i++) {
        printf("User[%d]: ", i);
        print_hexstring(data[i], block_size);
      }
  }
  build_tree(mt, data, NUM_USERS, block_size);
  if(DEBUGPRINT) {
       printf("[eaPVRA] PRINTING User Merkle Tree\n");
       print_tree(mt);
    }
  *mt_size = tree_size(mt);
#else
  size_t calc_auditlog_buffer_size(struct ES * enclave_state) {
  size_t mt_size = 0;
#endif

  uint64_t audit_index = enclave_state->auditmetadata.audit_index;
  return sizeof(enclave_state->auditmetadata.audit_num)+audit_index*(sizeof(packed_address_t)+HASH_SIZE+sizeof(uint64_t))+*mt_size;
}

/**
 * This function calculates the sizes of buffers needed for the untrusted app to
 * store data sealdata and the auditlog buffer from the enclave.
 * @param [in] sealedstate: incoming previous enclave state seal.
 * @param [out] newsealedstate_size      Output parameter for size of new seal state.
 * @param [out] newauditlog_buffer_size  Output parameter for size of audit log.
 * @return                        SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */
sgx_status_t ecall_calc_buffer_sizes(uint8_t *sealedstate, size_t sealedstate_size, size_t *newsealedstate_size, size_t *newauditlog_buffer_size) {
  struct ES enclave_state;
  struct dAppData dAD;
  sgx_status_t ret = SGX_SUCCESS;
  ret = unseal_enclave_state(sealedstate, &enclave_state, &dAD);
  if (ret != SGX_SUCCESS) {
    return ret;
  }

  ret = initES(&enclave_state, &dAD);
  if (ret != SGX_SUCCESS) {
    return ret;
  }

  uint32_t unsealed_data_size = sizeof(struct ES) + sizeof(struct dAppData);
  for(int i = 0; i < dAD.num_dDS; i++) {
    unsealed_data_size += sizeof(struct dynamicDS);
    unsealed_data_size += dAD.dDS[i]->buffer_size;
  }
  uint32_t seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);

  *newsealedstate_size = seal_size;

#ifdef MERKLE_TREE
   merkle_tree mt;
   size_t mt_size;
  *newauditlog_buffer_size = calc_auditlog_buffer_size(&enclave_state, &mt, &mt_size);
#else
  *newauditlog_buffer_size = calc_auditlog_buffer_size(&enclave_state);
#endif

  return ret;
}

/**
 * This function calculates the sizes of buffers needed for the untrusted app to
 * store data (public key, sealed private key and signature) from the enclave.
 *
 * @param [out] sealed_state_size       Output parameter for size of initial seal state.
 * @return                        SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */

sgx_status_t ecall_init_buffer_sizes(size_t *sealed_state_size) {

  struct ES enclave_state;
  struct dAppData dAD;
  sgx_status_t ret = SGX_SUCCESS;
  ret = initES(&enclave_state, &dAD);//todo does the size depend on ES? --note it is required to get the right size
  if (ret != SGX_SUCCESS) {
    return ret;
  }

  uint32_t unsealed_data_size = sizeof(struct ES) + sizeof(struct dAppData);
  for(int i = 0; i < dAD.num_dDS; i++) {
    unsealed_data_size += sizeof(struct dynamicDS);
    unsealed_data_size += dAD.dDS[i]->buffer_size;
  }
  uint32_t seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);

  *sealed_state_size = seal_size;

  return ret;
}