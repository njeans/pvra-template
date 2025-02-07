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


/**
 * This function calculates the size of the audit log struct (struct AL)
 * @param [in] num_entries: number of entries in the audit log struct
 * @return size_t size
 */
size_t calc_auditlog_size(size_t num_entries) {
  return num_entries*(sizeof(struct audit_entry_t));
}

/**
 * This function calculates the size of the application data (struct dAppData)
 * @param [in] dAD: current struct holding the appData
 * @return size_t data_size
 */
size_t calc_appdata_size(struct dAppData * dAD) {
  size_t data_size = sizeof(struct dAppData) +  (dAD->num_dDS * sizeof(struct dynamicDS));
  for(int i = 0; i < dAD->num_dDS; i++) {
    data_size += dAD->dDS[i].buffer_size;
  }
  return data_size;
}

size_t calc_enclave_state_size(struct ES * enclave_state) {
  return sizeof(struct ES) + (enclave_state->num_users * sizeof(pubkey_t))+ (enclave_state->num_users * sizeof(uint64_t));
}

/**
 * This function calculates the sizes of buffers needed for the audit log
 * to be returned from ecall_auditlogPVRA **not including merkle tree proof**
 * @param [in] auditlog: current struct AL that will be used for creating the output
 * @return size_t buffer size
 */
size_t calc_auditlog_out_buffer_size(struct AL * auditlog) {
  /**
   * Audit log format
   * [64 bytes (uint64_t) audit number] +
   * for each entry in log (auditlog->num_entries)
   *      [32 bytes (packed_address_t) ethereum address of user who posted command] +
   *      [32 bytes (uint8_t [32]) hash of command] +
   *      [64 bytes (uint64_t) sequence number for user who posted command] +
  */
  //todo create auditlog out struct with calc_auditlog_out function?
  return sizeof(auditlog->audit_num)+calc_auditlog_size(auditlog->num_entries);
}

#ifdef MERKLE_TREE
/**
 * This function calculates the sizes of buffers needed for the merkle tree in the 
 * audit log that will be returned from ecall_auditlogPVRA
 * @param [in] enclave_state: current struct ES that will be used for creating the merkle tree
 * @return size_t buffer size
 */
size_t calc_merkletree_out_buffer_size(struct ES * enclave_state) {
  size_t block_size = calc_user_leaf_size(enclave_state);
  size_t enc_block_size = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + block_size;
  size_t mt_size = calc_tree_size(enclave_state->num_users, enc_block_size);
  return mt_size;
}
#endif


/**
 * This function calculates the sizes of buffers needed for the untrusted app to
 * store data output sealdata after calling ecall_auditlogPVRA
 * and the auditlog buffer after calling ecall_auditlogPVRA
 * @param [in]  sealedstate: incoming sealdata to ecall_auditlogPVRA
 * @param [out] newsealedstate_size      Output parameter for size of new seal state.
 * @param [out] newauditlog_buffer_size  Output parameter for size of audit log.
 * @return sgx_status_t SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */
sgx_status_t ecall_audit_buffer_sizes(uint8_t *sealedstate, size_t sealedstate_size, size_t *newsealedstate_size, size_t *newauditlog_buffer_size) {
  struct ES enclave_state;
  struct dAppData dAD;
  sgx_status_t ret = SGX_SUCCESS;

  ret = unseal_enclave_state(sealedstate, true, &enclave_state, &dAD);
  if (ret != SGX_SUCCESS) {
    return ret;
  }

  //input calc_auditlog_size(0) since audit log will be reset after ecall_auditlogPVRA
  uint32_t unsealed_data_size = calc_enclave_state_size(&enclave_state) +  calc_appdata_size(&dAD) + calc_auditlog_size(0);

  uint32_t seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);

  *newsealedstate_size = seal_size;

#ifdef MERKLE_TREE
  *newauditlog_buffer_size = calc_auditlog_out_buffer_size(&enclave_state.auditlog) + calc_merkletree_out_buffer_size(&enclave_state);
#else
  *newauditlog_buffer_size = calc_auditlog_out_buffer_size(&enclave_state.auditlog);
#endif
  free_enclave_state(&enclave_state, &dAD);
  return ret;
}

/**
 * This function calculates the sizes of buffers needed for the untrusted app to
 * store data output sealdata after calling ecall_commandPVRA 
 * @param [in]  sealedstate: incoming sealdata to ecall_commandPVRA
 * @param [out] newsealedstate_size Output parameter for size of new seal state.
 * @return sgx_status_t SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */
sgx_status_t ecall_cmd_buffer_sizes(uint8_t *sealedstate, size_t sealedstate_size, size_t *newsealedstate_size) {
  struct ES enclave_state;
  struct dAppData dAD;
  sgx_status_t ret = SGX_SUCCESS;
  ret = unseal_enclave_state(sealedstate, true, &enclave_state, &dAD);
  if (ret != SGX_SUCCESS) {
    return ret;
  }
  //todo handle size that is too large into multiple files
  //input num_entries+1 to calc_auditlog_size since a new entry will be added in ecall_commandPVRA
  uint32_t unsealed_data_size = calc_enclave_state_size(&enclave_state) + 
                                  calc_appdata_size(&dAD) +
                                  calc_auditlog_size(enclave_state.auditlog.num_entries+1);

  uint32_t seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);

  *newsealedstate_size = seal_size;
  return ret;
}

/**
 * This function calculates the sizes of buffers needed for the untrusted app to
 * store data output sealdata after calling ecall_initPVRA 
 * @param [in]  num_users: initial number of users in the system
 * @param [out] sealed_state_size  Output parameter for size of initial seal state.
 * @return sgx_status_t SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */
sgx_status_t ecall_init_buffer_sizes(uint64_t num_users, size_t *sealed_state_size) {
  sgx_status_t ret = SGX_SUCCESS;
  struct ES enclave_state;
  struct dAppData dAD;
  init_enclave_state(&enclave_state, &dAD);
  enclave_state.num_users = num_users;

  ret = initES(&enclave_state, &dAD, num_users);
  if (ret != SGX_SUCCESS) {
    return ret;
  }

  uint32_t unsealed_data_size = calc_enclave_state_size(&enclave_state) + calc_appdata_size(&dAD) + calc_auditlog_size(0);
  uint32_t seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);

  *sealed_state_size = seal_size;
  free_enclave_state(&enclave_state, &dAD);
  return ret;
}

/**
 * This function initializes enclave state struct with default parameters.
 * 
 * @param [out] enclave_state  Output parameter for storing unseal enclave_state
 * @param [out] dAD  Output parameter for application specific data
 */
void init_enclave_state(struct ES *enclave_state,  struct dAppData * dAD){
  enclave_state->num_users = 0;
  enclave_state->auditlog.entries = NULL;
  enclave_state->antireplay.seqno = NULL;
  enclave_state->publickeys.user_pubkeys = NULL;
  dAD->num_dDS = 0;
  dAD->dDS = NULL;
}

/**
 * This function unseal enclave state to create a valid struct ES * enclave_state
 * that can store data 
 * @param [in] sealedstate: sealdata
 * @param [in] CMD: true if being called for use in ecall_commandPVRA, false otherwise
 * @param [out] enclave_state  Output parameter for storing unseal enclave_state
 * @param [out] dAD  Output parameter for application specific data
 * @return sgx_status_t SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */
sgx_status_t unseal_enclave_state(const sgx_sealed_data_t * sealedstate, bool CMD, struct ES * enclave_state, struct dAppData * dAD)
{
    sgx_status_t ret = SGX_SUCCESS;

    uint32_t unsealed_data_size = sgx_get_encrypt_txt_len(sealedstate);
    uint8_t * unsealed_data = (uint8_t *)malloc(unsealed_data_size);
    if (unsealed_data == NULL) {
        printf("[unsealES] malloc(unsealed_data_size) failed!\n");
        return SGX_ERROR_OUT_OF_MEMORY; //todo change to unexpected?
    }

    ret = sgx_unseal_data(sealedstate, NULL, NULL, (const uint8_t *) unsealed_data, &unsealed_data_size);
    if (ret != SGX_SUCCESS) {
        printf("[unsealES] sgx_unseal_data() failed!f\n");
        return ret;
    }

    memcpy(enclave_state, unsealed_data, sizeof(struct ES));
    int offset = sizeof(struct ES);

    size_t user_pubkeys_size = enclave_state->num_users * sizeof(pubkey_t);
    enclave_state->publickeys.user_pubkeys = (pubkey_t *) malloc(user_pubkeys_size);
    memcpy(enclave_state->publickeys.user_pubkeys, unsealed_data + offset, user_pubkeys_size);
    offset += user_pubkeys_size;

    size_t user_seqno_size = enclave_state->num_users * sizeof(uint64_t);
    enclave_state->antireplay.seqno = (uint64_t *) malloc(user_seqno_size);
    memcpy(enclave_state->antireplay.seqno, unsealed_data + offset, user_seqno_size);
    offset += user_seqno_size;    
    
    memcpy(dAD, unsealed_data + offset, sizeof(struct dAppData));
    offset += sizeof(struct dAppData);
    
    struct dynamicDS *dDS = (struct dynamicDS *)malloc(dAD->num_dDS*sizeof(struct dynamicDS));
    for(int i = 0; i < dAD->num_dDS; i++) {
        memcpy(&dDS[i], unsealed_data + offset, sizeof(struct dynamicDS));
        offset += sizeof(struct dynamicDS);
    }
    for(int i = 0; i < dAD->num_dDS; i++) {
        dDS[i].buffer = (uint8_t *) malloc(dDS[i].buffer_size);
        // memset(dDS[i]->buffer, 0,  dDS[i].buffer_size);
        memcpy(dDS[i].buffer, unsealed_data + offset, dDS[i].buffer_size);
        offset += dDS[i].buffer_size;
    }
    dAD->dDS = dDS;

    
    size_t num_audit_entries = enclave_state->auditlog.num_entries;
    size_t current_auditlog_size = calc_auditlog_size(num_audit_entries);
    if (CMD) { //a new entry will be input in audit log in ecall_commandPVRA
      num_audit_entries++;
    }
    size_t auditlog_size = calc_auditlog_size(num_audit_entries);
    enclave_state->auditlog.entries = (struct audit_entry_t *) malloc(auditlog_size);
    memset(enclave_state->auditlog.entries, 0, auditlog_size);
    memcpy(enclave_state->auditlog.entries, unsealed_data + offset, current_auditlog_size);
    offset += auditlog_size;

    ret = initAD(enclave_state, dAD);
    if (ret != SGX_SUCCESS) {
      printf("[unsealES] initAD() failed!\n");
    }
    free(unsealed_data);
    unsealed_data = NULL;
    return ret;
}

/**
 * This function seals struct ES * enclave state
 * @param [in] enclave_state enclave_state that will be sealed
 * @param [in] dAD  application specific data
 * @param [in] sealedstate_size: size of sealed data output buffer
 * @param [out] sealedstate: output buffer for sealed data
 * @return sgx_status_t SGX_SUCCESS (Error code = 0x0000) on success,
 * some other appropriate sgx_status_t value upon failure.
 */
sgx_status_t seal_enclave_state(struct ES * enclave_state, struct dAppData * dAD, size_t sealedstate_size, const sgx_sealed_data_t * sealedstate) {
    uint32_t unsealed_data_size = calc_enclave_state_size(enclave_state) +
                                    calc_appdata_size(dAD) +
                                    calc_auditlog_size(enclave_state->auditlog.num_entries);

    uint32_t seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);
    if(sealedstate_size < seal_size) {
      printf("[sealES] Size allocated for seal is insufficient. %lu < %lu\n", sealedstate_size, seal_size);
      return SGX_ERROR_INVALID_PARAMETER;
    }
    uint8_t * unsealed_data = (uint8_t *)malloc(unsealed_data_size);

    int unsealed_offset = 0;
    memcpy(unsealed_data + unsealed_offset, enclave_state, sizeof(struct ES));
    unsealed_offset += sizeof(struct ES);

    size_t user_pubkeys_size = enclave_state->num_users * sizeof(pubkey_t);
    memcpy(unsealed_data + unsealed_offset, enclave_state->publickeys.user_pubkeys, user_pubkeys_size);
    unsealed_offset += user_pubkeys_size;

    size_t user_seqno_size = enclave_state->num_users * sizeof(uint64_t);
    memcpy(unsealed_data + unsealed_offset, enclave_state->antireplay.seqno, user_seqno_size);
    unsealed_offset += user_seqno_size;

    memcpy(unsealed_data + unsealed_offset, dAD, sizeof(struct dAppData));
    unsealed_offset += sizeof(struct dAppData);
    for(int i = 0; i < dAD->num_dDS; i++) {
      memcpy(unsealed_data + unsealed_offset, &dAD->dDS[i], sizeof(struct dynamicDS));
      unsealed_offset += sizeof(struct dynamicDS);
    }
    for(int i = 0; i < dAD->num_dDS; i++) {
      memcpy(unsealed_data + unsealed_offset, dAD->dDS[i].buffer, dAD->dDS[i].buffer_size);
      unsealed_offset += dAD->dDS[i].buffer_size;
    }

    for (size_t i = 0; i < enclave_state->auditlog.num_entries; i++) {
      struct audit_entry_t *audit_entry = &enclave_state->auditlog.entries[i];
      memcpy(unsealed_data + unsealed_offset, audit_entry, sizeof(struct audit_entry_t));
      unsealed_offset += sizeof(struct audit_entry_t);
    }

    if(unsealed_offset != unsealed_data_size) {
      printf("[sealES] creating unsealed_data blob error. %u != %u\n", unsealed_offset, unsealed_data_size);
      return SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t ret = sgx_seal_data(0U, NULL, unsealed_data_size, (const uint8_t *) unsealed_data, seal_size, sealedstate);
    if(ret != SGX_SUCCESS) {
      printf("[sealES] sgx_seal_data() failed. %d\n", ret);
    }
    free(unsealed_data);
    unsealed_data = NULL;
    return ret;
}

void free_enclave_state(struct ES * enclave_state, struct dAppData * dAD) {
    // FREE dynamic structs 
    // todo make free_encalve_state that is called in ecall_calc_buffer and after calls to seal_enclave_state
    if (enclave_state->auditlog.entries != NULL) {
      free(enclave_state->auditlog.entries);
      enclave_state->auditlog.entries = NULL;
    }
    if (enclave_state->publickeys.user_pubkeys != NULL) {
      free(enclave_state->publickeys.user_pubkeys);
      enclave_state->publickeys.user_pubkeys = NULL;
    }
    if (enclave_state->antireplay.seqno != NULL) {
      free(enclave_state->antireplay.seqno);
      enclave_state->antireplay.seqno = NULL;
    }
    if(dAD->dDS != NULL){
      for(int i = 0; i < dAD->num_dDS; i++) {
        if(dAD->dDS[i].buffer != NULL){
          free(dAD->dDS[i].buffer);
          dAD->dDS[i].buffer = NULL;
        }
      }
      free(dAD->dDS);
      dAD->dDS = NULL;
    }
}
