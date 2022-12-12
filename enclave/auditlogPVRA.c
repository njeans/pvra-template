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
  init_enclave_state(&enclave_state, &dAD);

#ifdef MERKLE_TREE
  merkle_tree mt = {0, 0, 0, NULL, NULL};
  uint8_t **leaf_data = NULL;
  uint8_t **enc_leaf_data = NULL;
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
  uint64_t num_audit_entries = enclave_state.auditlog.num_entries;
  if(DEBUGPRINT) { //todo change to ifdefineif
    printf("[ecPVRA] PRINTING READABLE AUDITLOG len: %d\n", enclave_state.auditlog.num_entries);
    for(int i = 0; i < enclave_state.auditlog.num_entries; i++) {
      struct audit_entry_t audit_entry = enclave_state.auditlog.entries[i];
      printf("[%d]: SEQ: %lu",i, audit_entry.seqNo);
      printf(" ADDR: ");
      print_hexstring_trunc_n((uint8_t *) audit_entry.user_address + 12, sizeof(packed_address_t)-12);
      printf(" HASH: ");
      print_hexstring_trunc_n(audit_entry.command_hash, HASH_SIZE);
      printf("\n");
    }
  }

#ifdef MERKLE_TREE
    leaf_data = (uint8_t **) calloc(enclave_state.num_users, sizeof(uint8_t *));
    printf("leaf_data b %p\n", leaf_data);
    size_t leaf_size = get_user_leaf(&enclave_state, leaf_data);
  if(DEBUGPRINT) {
      printf("[eaPVRA] PRINTING User Leaf Nodes leaf_size: %lu\n", leaf_size);
      for(int i = 0; i < enclave_state.num_users; i++) {
        printf("User[%d]: ", i);
        print_hexstring(leaf_data[i], leaf_size);
      }
  }
  size_t enc_leaf_size = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + leaf_size;
  size_t mt_size = calc_tree_size(enclave_state.num_users, enc_leaf_size);

  enc_leaf_data = (uint8_t**) calloc(enclave_state.num_users, sizeof(uint8_t *));
  for(int i = 0; i < enclave_state.num_users; i++) {
    unsigned char AESKey[AESGCM_128_KEY_SIZE];
    sgx_status_t ret = genkey_aesgcm128(enclave_state.publickeys.user_pubkeys[i], enclave_state.enclavekeys.enc_prikey, AESKey);
    if (ret != SGX_SUCCESS) {
        goto cleanup;
    }
    enc_leaf_data[i] = (uint8_t *) malloc(enc_leaf_size);
    ret = encrypt_aesgcm128(AESKey, leaf_data[i], leaf_size, enc_leaf_data[i]);
    if (ret != SGX_SUCCESS) {
        printf("[eaPVRA] encrypt_aesgcm128 failed %d\n", SGX_SUCCESS);
        goto cleanup;
    }
  }

  if(DEBUGPRINT) {
      printf("[eaPVRA] PRINTING Encrypted User Leaf Nodes leaf_size: %lu\n", enc_leaf_size);
      for(int i = 0; i < enclave_state.num_users; i++) {
        printf("User[%d]: ", i);
        print_hexstring(enc_leaf_data[i], enc_leaf_size);
      }
  }

  build_tree(&mt, enc_leaf_data, enclave_state.num_users, enc_leaf_size);
  if(DEBUGPRINT) {
       printf("[eaPVRA] PRINTING User Merkle Tree mt_size %lu\n", mt_size);
       print_tree(&mt);
  }
  serialize_tree(auditlog, &mt);
  cleanup_tree(&mt);
  free_user_leaf(leaf_data);
  free_user_leaf(enc_leaf_data);
  free(leaf_data);
  leaf_data = NULL;
  free(enc_leaf_data);
  enc_leaf_data = NULL;

  size_t auditlog_offset = mt_size;
  size_t calc_auditlog_size = calc_auditlog_out_buffer_size(&enclave_state.auditlog) + mt_size;
#else
  size_t auditlog_offset = 0;
  size_t calc_auditlog_size = calc_auditlog_out_buffer_size(&enclave_state.auditlog);
#endif
  if (auditlog_size != calc_auditlog_size) {
    printf("[eaPVRA] auditlog_size incorrect %lu != %lu\n", calc_auditlog_size, auditlog_size);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  memcpy_big_uint64(auditlog + auditlog_offset, enclave_state.auditlog.audit_num);
  auditlog_offset += sizeof(enclave_state.auditlog.audit_num);

  for(uint64_t i = 0; i < num_audit_entries; i++) {
    memcpy(auditlog + auditlog_offset, &enclave_state.auditlog.entries[i].user_address, sizeof(packed_address_t));
    auditlog_offset += sizeof(packed_address_t);
  }
  for(uint64_t i = 0; i < num_audit_entries; i++) {
    memcpy(auditlog + auditlog_offset, &enclave_state.auditlog.entries[i].command_hash, HASH_SIZE);
    auditlog_offset += HASH_SIZE;
  }
  for(uint64_t i = 0; i < num_audit_entries; i++) {
    memcpy_big_uint64(auditlog + auditlog_offset, enclave_state.auditlog.entries[i].seqNo);
    auditlog_offset += sizeof(enclave_state.auditlog.entries[i].seqNo);
  }

  if(DEBUGPRINT) printf("[eaPVRA] PRINTING AUDITLOG BUFFER TO BE HASHED: size %lu\n", auditlog_size);
  if(DEBUGPRINT) print_hexstring(auditlog, auditlog_size);

  /*   (8) SIGN AUDITLOG   */

  unsigned char auditlog_hash[HASH_SIZE];
  keccak256(auditlog, auditlog_size, auditlog_hash);

  if(DEBUGPRINT) printf("[eaPVRA] Audit log hash: %lu\n", sizeof(auditlog_hash));
  if(DEBUGPRINT) print_hexstring(auditlog_hash, sizeof(auditlog_hash));


  secp256k1_ecdsa_recoverable_signature auditlog_signature;
  ret = sign_rec_secp256k1(enclave_state.enclavekeys.enc_prikey, auditlog_hash, &auditlog_signature, auditlog_signature_ser);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(DEBUGPRINT) printf("[eaPVRA] AUDITLOG SIGNATURE serialized\n");
  if(DEBUGPRINT) print_hexstring(auditlog_signature_ser, 65);


  enclave_state.auditlog.num_entries = 0;
  enclave_state.auditlog.audit_num+=1;
  if(DEBUGPRINT) printf("[eaPVRA] Reseting audit log num_entries %u audit_num %u\n", enclave_state.auditlog.num_entries,  enclave_state.auditlog.audit_num);

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
    if (leaf_data != NULL) {
      free_user_leaf(leaf_data);
      free(leaf_data);
      leaf_data=NULL;
    }
    if (enc_leaf_data != NULL) {
      free_user_leaf(enc_leaf_data);
      free(enc_leaf_data);
      enc_leaf_data=NULL;
    }
    cleanup_tree(&mt);
#endif
    free_enclave_state(&enclave_state, &dAD);
    return ret;
}
