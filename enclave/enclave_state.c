#include <sgx_tseal.h>
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

