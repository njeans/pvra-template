//#include <stdarg.h>
//#include <stdio.h>
//
//#include "enclave.h"
//#include <enclave_t.h>
//
//#include <sgx_tcrypto.h>
//#include <sgx_tseal.h>
//#include <sgx_utils.h>

#include "enclave_state.h"



sgx_status_t unseal_enclave_state(const sgx_sealed_data_t * sealedstate, struct ES * enclave_state, struct dAppData * dAD) {
    sgx_status_t ret = SGX_SUCCESS;
    
    uint32_t unsealed_data_size = sgx_get_encrypt_txt_len(sealedstate);
    uint8_t *const unsealed_data = (uint8_t *)malloc(unsealed_data_size);
    if (unsealed_data == NULL) {
        printf("[unsealES] malloc(unsealed_data_size) failed!\n");
        return SGX_ERROR_OUT_OF_MEMORY; //todo change to unexpected?
    }

    ret = sgx_unseal_data((sgx_sealed_data_t *)sealedstate, NULL, NULL, unsealed_data, &unsealed_data_size);
    if (ret != SGX_SUCCESS) {
        printf("[unsealES] sgx_unseal_data() failed!\n");
        return ret;
    }

    memcpy(enclave_state, unsealed_data, sizeof(struct ES));
    int offset = sizeof(struct ES);
    
    memcpy(dAD, unsealed_data + offset, sizeof(struct dAppData));
    offset += sizeof(struct dAppData);
    
    struct dynamicDS **dDS = (struct dynamicDS **)calloc(dAD->num_dDS, sizeof(struct dynamicDS *));
    dAD->dDS = dDS;
    
    for(int i = 0; i < dAD->num_dDS; i++) {
        struct dynamicDS *tDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
        memcpy(tDS, unsealed_data + offset, sizeof(struct dynamicDS));
        offset += sizeof(struct dynamicDS);
        dAD->dDS[i] = tDS;
    }
    
    for(int i = 0; i < dAD->num_dDS; i++) {
        dAD->dDS[i]->buffer = unsealed_data + offset;
        offset += dAD->dDS[i]->buffer_size;
    }
    
    ret = initAD(enclave_state, dAD);
    return ret;
}

sgx_status_t seal_enclave_state(const sgx_sealed_data_t * sealedstate, size_t sealedstate_size, size_t *actualsealedstate_size, struct ES * enclave_state, struct dAppData * dAD) {
    uint32_t unsealed_data_size = sizeof(struct ES) + sizeof(struct dAppData);
    for(int i = 0; i < dAD->num_dDS; i++) {
      unsealed_data_size += sizeof(struct dynamicDS);
      unsealed_data_size += dAD->dDS[i]->buffer_size;
    }
    uint8_t *const unsealed_data = (uint8_t *)malloc(unsealed_data_size);

    int unsealed_offset = 0;
    memcpy(unsealed_data + unsealed_offset, enclave_state, sizeof(struct ES));
    unsealed_offset += sizeof(struct ES);

    memcpy(unsealed_data + unsealed_offset, dAD, sizeof(struct dAppData));
    unsealed_offset += sizeof(struct dAppData);

    for(int i = 0; i < dAD->num_dDS; i++) {
      memcpy(unsealed_data + unsealed_offset, dAD->dDS[i], sizeof(struct dynamicDS));
      unsealed_offset += sizeof(struct dynamicDS);
    }

    for(int i = 0; i < dAD->num_dDS; i++) {
      memcpy(unsealed_data + unsealed_offset, dAD->dDS[i]->buffer, dAD->dDS[i]->buffer_size);
      unsealed_offset += dAD->dDS[i]->buffer_size;
    }

    if(unsealed_offset != unsealed_data_size) {
      printf("[seal_es] creating unsealed_data blob error.\n");
      return SGX_ERROR_UNEXPECTED;
    }

    // FREE dynamic AD metadata structs
    for(int i = 0; i < dAD->num_dDS; i++) {
      if(dAD->dDS[i] != NULL)
        free(dAD->dDS[i]);
    }
    if(dAD->dDS != NULL)
      free(dAD->dDS);

    uint32_t seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);

  if(sealedstate_size < seal_size) {
    printf("[seal_es] Size allocated for seal is insufficient. %lu < %lu\n", sealedstate_size, seal_size);
    return SGX_ERROR_INVALID_PARAMETER;
  }
    sgx_status_t ret = sgx_seal_data(0U, NULL, unsealed_data_size, unsealed_data, seal_size, sealedstate);
    if(ret != SGX_SUCCESS) {
      printf("[seal_es] sgx_seal_data() failed. %d\n", ret);
    }
    *actualsealedstate_size = seal_size;

    return ret;
}

#ifdef MERKLE_TREE
size_t calc_auditlog_buffer_size(struct ES * enclave_state, merkle_tree * mt, size_t * out_mt_size) {

  char *data[NUM_USERS];
  size_t block_size = get_user_leaf(enclave_state, &data);
  if(DEBUGPRINT) {
      printf("[eaPVRA] PRINTING User Leaf Nodes leaf_size: %d\n", block_size);
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
  size_t mt_size = tree_size(mt);
  *out_mt_size = mt_size;
#else
  size_t calc_auditlog_buffer_size(struct ES * enclave_state) {
  size_t mt_size = 0;
#endif

  uint64_t audit_index = enclave_state->auditmetadata.audit_index;
  return sizeof(enclave_state->auditmetadata.audit_num)+audit_index*(sizeof(packed_address_t)+HASH_SIZE+sizeof(uint64_t))+mt_size;
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

