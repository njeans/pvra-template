/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//#include <stdarg.h>
//#include <stdio.h>
//
//#include "enclave.h"
//#include <enclave_t.h>
//
//#include <sgx_quote.h>
//#include <sgx_tcrypto.h>
//#include <sgx_tseal.h>
//#include <sgx_utils.h>
//
//#include <mbedtls/entropy.h>
//#include <mbedtls/ctr_drbg.h>
//#include <mbedtls/bignum.h>
//#include <mbedtls/pk.h>
//#include <mbedtls/rsa.h>
//
//// [TODO]: If possible remove mbedtls dependence, only used for sha256 hashes now
//
//#include <secp256k1.h>
//#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>

#include "enclave_state.h"

#ifdef MERKLE_TREE
#include "merkletree.h"
#endif

/**
 * This extracts the auditlog for a PVRA enclave.
 *
 * @param [in] sealedstate: incoming previous enclave state seal.
 * @param [out] auditlog: outgoing buffer for auditlog.
 * @param [out] auditlog_signature_ser: the auditlog signature.
 * @param [out] newsealedstate: outgoing new enclave state seal.
 *
 * @return SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */



sgx_status_t ecall_auditlogPVRA(
    uint8_t *sealedstate, size_t sealedstate_size,
    uint8_t *auditlog, size_t auditlog_size,
    uint8_t auditlog_signature_ser[65],
    uint8_t *newsealedstate, size_t newsealedstate_size) {

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  struct ES enclave_state;
  struct dAppData dAD;

#ifdef MERKLE_TREE
  merkle_tree mt = {0, 0, 0, NULL, NULL};
  uint8_t *data[NUM_USERS];
  uint8_t *enc_data[NUM_USERS];
  for(int j = 0; j < NUM_USERS; j++) {
        data[j] = NULL;
        enc_data[j] = NULL;
  }
#endif

  // Control Timing Measurement of an OCALL Overhead.
  if(A_DEBUGRDTSC) ocall_rdtsc();

  /*    (2) Enclave State Initializaiton    */


  /*    Unseal Enclave State    */
  ret = unseal_enclave_state(sealedstate, false, &enclave_state, &dAD);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(A_DEBUGRDTSC) ocall_rdtsc();


 
  // PRINTS AUDIT LOG 
  uint64_t num_audit_entries = enclave_state.auditmetadata.auditlog.num_entries;
  if(DEBUGPRINT) { //todo change to ifdefineif
    printf("[ecPVRA] PRINTING READABLE AUDITLOG len: %d\n", enclave_state.auditmetadata.auditlog.num_entries);
    for(int i = 0; i < enclave_state.auditmetadata.auditlog.num_entries; i++) {
      struct audit_entry_t audit_entry = enclave_state.auditmetadata.auditlog.entries[i];
      printf("[%d]: SEQ: %lu",i, audit_entry.seqNo);
      printf(" ADDR: ");
      print_hexstring_trunc_n((uint8_t *) audit_entry.user_address + 12, sizeof(packed_address_t)-12);
      printf(" HASH: ");
      print_hexstring_trunc_n(audit_entry.command_hash, HASH_SIZE);
      printf("\n");
    }
  }

#ifdef MERKLE_TREE
  size_t block_size = get_user_leaf(&enclave_state, data);
  if(DEBUGPRINT) {
      printf("[eaPVRA] PRINTING User Leaf Nodes leaf_size: %d\n", block_size);
      for(int i = 0; i < NUM_USERS; i++) {
        printf("User[%d]: ", i);
        print_hexstring(data[i], block_size);
      }
  }
  size_t enc_block_size = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + block_size;
  size_t mt_size = calc_tree_size(NUM_USERS, enc_block_size);

  for(int i = 0; i < NUM_USERS; i++) {
    unsigned char AESKey[AESGCM_128_KEY_SIZE];
    enc_data[i] = (uint8_t *) malloc(enc_block_size);
    sgx_status_t ret = genkey_aesgcm128(enclave_state.auditmetadata.master_user_pubkeys[i+1], enclave_state.enclavekeys.enc_prikey, AESKey);
    if (ret != SGX_SUCCESS) {
        goto cleanup;
    }
    ret = encrypt_aesgcm128(AESKey, data[i], block_size, enc_data[i]);
    if (ret != SGX_SUCCESS) {
        goto cleanup;
    }
  }
    for(int j = 0; j < NUM_USERS; j++) {
        if (data[j]) {
            free(data[j]);
            data[j] = NULL;
        }
    }
  if(DEBUGPRINT) {
      printf("[eaPVRA] PRINTING Encrypted User Leaf Nodes leaf_size: %d\n", enc_block_size);
      for(int i = 0; i < NUM_USERS; i++) {
        printf("User[%d]: %p ", i, enc_data[i]);
        print_hexstring(enc_data[i], enc_block_size);
      }
  }

  build_tree(&mt, enc_data, NUM_USERS, enc_block_size);
  if(DEBUGPRINT) {
       printf("[eaPVRA] PRINTING User Merkle Tree mt_size %u\n", mt_size);
       print_tree(&mt);
  }
  serialize_tree(auditlog, &mt);
  cleanup_tree(&mt);
  size_t auditlog_offset = mt_size;
  size_t calc_auditlog_size = calc_auditlog_out_buffer_size(&enclave_state.auditmetadata.auditlog) + mt_size;
#else
  size_t auditlog_offset = 0;
  size_t calc_auditlog_size = calc_auditlog_out_buffer_size(&enclave_state.auditmetadata.auditlog);
#endif

  if (auditlog_size != calc_auditlog_size) {
    printf("[eaPVRA] auditlog_size incorrect %lu != %lu\n", calc_auditlog_size, auditlog_size);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  memcpy_big_uint64(auditlog + auditlog_offset, enclave_state.auditmetadata.auditlog.audit_num);
  auditlog_offset += sizeof(enclave_state.auditmetadata.auditlog.audit_num);

  for(uint64_t i = 0; i < num_audit_entries; i++) {
    memcpy(auditlog + auditlog_offset, &enclave_state.auditmetadata.auditlog.entries[i].user_address, sizeof(packed_address_t));
    auditlog_offset += sizeof(packed_address_t);
  }
  for(uint64_t i = 0; i < num_audit_entries; i++) {
    memcpy(auditlog + auditlog_offset, &enclave_state.auditmetadata.auditlog.entries[i].command_hash, HASH_SIZE);
    auditlog_offset += HASH_SIZE;
  }
  for(uint64_t i = 0; i < num_audit_entries; i++) {
    memcpy_big_uint64(auditlog + auditlog_offset, enclave_state.auditmetadata.auditlog.entries[i].seqNo);
    auditlog_offset += sizeof(enclave_state.auditmetadata.auditlog.entries[i].seqNo);
  }

  if(DEBUGPRINT) printf("[eaPVRA] PRINTING AUDITLOG BUFFER TO BE HASHED: size %d\n", auditlog_size);
  if(DEBUGPRINT) print_hexstring(auditlog, auditlog_size);

  /*   (8) SIGN AUDITLOG   */

  unsigned char auditlog_hash[HASH_SIZE];
  keccak256(auditlog, auditlog_size, auditlog_hash);

  if(DEBUGPRINT) printf("[eaPVRA] Audit log hash: %d\n", sizeof(auditlog_hash));
  if(DEBUGPRINT) print_hexstring(auditlog_hash, sizeof(auditlog_hash));


  secp256k1_ecdsa_recoverable_signature auditlog_signature;
  ret = sign_rec_secp256k1(enclave_state.enclavekeys.enc_prikey, auditlog_hash, &auditlog_signature, auditlog_signature_ser);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(DEBUGPRINT) printf("[eaPVRA] AUDITLOG SIGNATURE serialized\n");
  if(DEBUGPRINT) print_hexstring(auditlog_signature_ser, 65);


  enclave_state.auditmetadata.auditlog.num_entries = 0;
  enclave_state.auditmetadata.auditlog.audit_num+=1;
  if(DEBUGPRINT) printf("[eaPVRA] Reseting audit log num_entries %u audit_num %u\n", enclave_state.auditmetadata.auditlog.num_entries,  enclave_state.auditmetadata.auditlog.audit_num);

  if(A_DEBUGRDTSC) ocall_rdtsc();

  goto seal_cleanup;

  /*   (9) SEAL STATE    */
  seal_cleanup: ;
    ret = seal_enclave_state(&enclave_state, &dAD, newsealedstate_size, newsealedstate);
    if(ret == SGX_SUCCESS) {
      if(DEBUGPRINT) printf("[eaPVRA] sealed state size: [%lu]\n", newsealedstate_size);
    }
    goto cleanup;

  cleanup:
    if(A_DEBUGRDTSC) ocall_rdtsc();
#ifdef MERKLE_TREE
        for(int j = 0; j < NUM_USERS; j++) {
            if (data[j] != NULL){
                free(data[j]);
                data[j] = NULL;
            }
        }
        cleanup_tree(&mt);
#endif
    return ret;
}
