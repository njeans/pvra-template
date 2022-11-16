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
//#include "util.h"



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
  struct clientCommand CC;

  // Control Timing Measurement of an OCALL Overhead.
  if(A_DEBUGRDTSC) ocall_rdtsc();
  if(A_DEBUGRDTSC) ocall_rdtsc();





  /*    (2) Enclave State Initializaiton    */


  /*    Unseal Enclave State    */

  ret = unseal_enclave_state(sealedstate, &enclave_state, &dAD);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(A_DEBUGRDTSC) ocall_rdtsc();


 
  // PRINTS AUDIT LOG 
  uint64_t audit_index = enclave_state.auditmetadata.audit_index;
  if(DEBUGPRINT) { //todo change to ifdefineif
        printf("[eaPVRA] PRINTING READABLE AUDITLOG len: %d\n", audit_index);
        for(int i = 0; i < audit_index; i++) {
          printf("[%d]: SEQ: %lu",i, enclave_state.auditmetadata.auditlog.seqNo[i]);
          printf(" ADDR: ");
          print_hexstring_trunc_n((uint8_t *) enclave_state.auditmetadata.auditlog.user_addresses[i] + 12, sizeof(packed_address_t)-12);
          printf(" HASH: ");
          print_hexstring_trunc_n(&enclave_state.auditmetadata.auditlog.command_hashes[i], HASH_SIZE);
          printf("\n");
        }
  }

  size_t mt_size = 0;
#ifdef MERKLE_TREE
  merkle_tree mt;
  size_t calc_auditlog_size = calc_auditlog_buffer_size(&enclave_state, &mt, &mt_size);
#else
  size_t calc_auditlog_size = calc_auditlog_buffer_size(&enclave_state);
#endif

  if (auditlog_size != calc_auditlog_size) {
    printf("[eaPVRA] auditlog_size incorrect %lu != %lu\n", calc_auditlog_size, auditlog_size);
    goto cleanup;
  }
  size_t auditlog_offset = mt_size;

#ifdef MERKLE_TREE
  serialize_tree(auditlog, &mt);
  cleanup_tree(&mt);
#endif

  memcpy_big_uint64(auditlog + auditlog_offset, enclave_state.auditmetadata.audit_num);
  auditlog_offset += sizeof(enclave_state.auditmetadata.audit_num);

  for(uint64_t i = 0; i < audit_index; i++) {
    memcpy(auditlog + auditlog_offset, &enclave_state.auditmetadata.auditlog.user_addresses[i], sizeof(packed_address_t));
    auditlog_offset += sizeof(packed_address_t);
  }
  for(uint64_t i = 0; i < audit_index; i++) {
    memcpy(auditlog + auditlog_offset, &enclave_state.auditmetadata.auditlog.command_hashes[i], HASH_SIZE);
    auditlog_offset += HASH_SIZE;
  }
  for(uint64_t i = 0; i < audit_index; i++) {
    memcpy_big_uint64(auditlog + auditlog_offset, enclave_state.auditmetadata.auditlog.seqNo[i]);
    auditlog_offset += sizeof(enclave_state.auditmetadata.auditlog.seqNo[i]);
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


  enclave_state.auditmetadata.audit_index = 0;
  enclave_state.auditmetadata.audit_num+=1;
  if(DEBUGPRINT) printf("[eaPVRA] Reseting audit log audit_index %u audit_num %u\n", enclave_state.auditmetadata.audit_index,  enclave_state.auditmetadata.audit_num);

  if(A_DEBUGRDTSC) ocall_rdtsc();

  goto seal_cleanup;

  /*   (9) SEAL STATE    */
  seal_cleanup: ;
    size_t actual_sealedstate_size;
    ret = seal_enclave_state(newsealedstate, newsealedstate_size, &actual_sealedstate_size, &enclave_state, &dAD);
    if (actual_sealedstate_size != newsealedstate_size) {
      printf("[eaPVRA] sealsize incorrect %lu != %lu\n", actual_sealedstate_size, newsealedstate_size);
      ret = SGX_ERROR_UNEXPECTED;
      goto cleanup;
    }
    if(ret == SGX_SUCCESS) {
      if(DEBUGPRINT) printf("[eaPVRA] sealed state size: [%lu]\n", actual_sealedstate_size);
    }
    goto cleanup;

  cleanup:
    if(A_DEBUGRDTSC) ocall_rdtsc();
    return ret;
}
