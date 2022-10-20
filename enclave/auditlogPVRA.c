/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclave.h"
#include <enclave_t.h>

#include <sgx_quote.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

// [TODO]: If possible remove mbedtls dependence, only used for sha256 hashes now

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>

#include "enclavestate.h"
#include "appPVRA.h"
#include "keccak256.h"
#include "util.h"

#define BUFLEN 2048
#define AESGCM_128_KEY_SIZE 16
#define AESGCM_128_MAC_SIZE 16
#define AESGCM_128_IV_SIZE 12

#define A_DEBUGPRINT 1
#define A_DEBUGRDTSC 0 




/**
 * This extracts the auditlog for a PVRA enclave.
 *
 * @param [in] sealedstate: incoming previous enclave state seal.
 * @param [out] auditlog: outgoing buffer for auditlog.
 * @param [out] auditlog_signature: the auditlog signature.
 * @param [out] actual_auditlog_size: size of auditlog buffer.
 *
 * @return SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */



sgx_status_t ecall_auditlogPVRA(
    char *sealedstate, size_t sealedstate_size, 
    char *auditlog, size_t auditlog_size,
    char *auditlog_signature, size_t auditlog_signature_size,
    uint32_t *actual_auditlog_size,
    char *newsealedstate, size_t newsealedstate_size) {


  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  struct ES enclave_state;
  struct dAppData dAD;
  struct clientCommand CC;

  // Control Timing Measurement of an OCALL Overhead.
  if(A_DEBUGRDTSC) ocall_rdtsc();
  if(A_DEBUGRDTSC) ocall_rdtsc();





  /*    (2) Enclave State Initializaiton    */


  /*    Unseal Enclave State    */

  uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealedstate);
  uint8_t *const unsealed_data = (uint8_t *)malloc(unsealed_data_size); 
  if (unsealed_data == NULL) {
    printf("[ecPVRA] malloc(unsealed_data_size) failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  ret = sgx_unseal_data((sgx_sealed_data_t *)sealedstate, NULL, NULL, unsealed_data, &unsealed_data_size);
  if (ret != SGX_SUCCESS) {
    printf("[ecPVRA] sgx_unseal_data() failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  /*    Handles loading dynamic data structures    */

  memcpy(&enclave_state, unsealed_data, sizeof(struct ES));
  int offset = sizeof(struct ES);

  memcpy(&dAD, unsealed_data + offset, sizeof(struct dAppData));
  offset += sizeof(struct dAppData);

  struct dynamicDS **dDS = (struct dynamicDS **)calloc(dAD.num_dDS, sizeof(struct dynamicDS *));
  dAD.dDS = dDS;

  for(int i = 0; i < dAD.num_dDS; i++) {
    struct dynamicDS *tDS = (struct dynamicDS *)calloc(1, sizeof(struct dynamicDS));
    memcpy(tDS, unsealed_data + offset, sizeof(struct dynamicDS));
    offset += sizeof(struct dynamicDS);
    dAD.dDS[i] = tDS;
  }

  for(int i = 0; i < dAD.num_dDS; i++) {
    dAD.dDS[i]->buffer = unsealed_data + offset;
    offset += dAD.dDS[i]->buffer_size;
  }

  initAD(&enclave_state, &dAD);

  if(A_DEBUGRDTSC) ocall_rdtsc();


  

  // PRINTS AUDIT LOG 
  
  int hash_size = 32;
  printf("[eaPVRA] PRINTING READABLE AUDITLOG\n");
  int num_entries = enclave_state.auditmetadata.audit_offset;
  for(int i = 0; i < num_entries; i++) {
    printf("HASH[%d]: ", i);
    print_hexstring(&enclave_state.auditmetadata.auditlog.command_hashes[i], hash_size);
    printf("PKEY[%d]: ", i);
    print_hexstring(&enclave_state.auditmetadata.auditlog.user_pubkeys[i], 20);
  }

  uint32_t auditlogbuf_size = sizeof(enclave_state.auditmetadata.audit_version_no)+num_entries*(sizeof(packed_address_t)+hash_size);
  uint8_t *const auditlogbuf = (uint8_t *)malloc(auditlogbuf_size);
  memcpy_big_uint32(auditlogbuf, enclave_state.auditmetadata.audit_version_no);
  uint32_t auditlog_offset = sizeof(enclave_state.auditmetadata.audit_version_no);

  for(int i = 0; i < num_entries; i++) {
    memcpy(auditlogbuf + auditlog_offset + 12, &enclave_state.auditmetadata.auditlog.user_pubkeys[i], 20);
    auditlog_offset += sizeof(packed_address_t);
  }
  for(int i = 0; i < num_entries; i++) {
    memcpy(auditlogbuf + auditlog_offset, &enclave_state.auditmetadata.auditlog.command_hashes[i], hash_size);
    auditlog_offset += hash_size;
  }

  printf("\n[eaPVRA] PRINTING AUDITLOG BUFFER TO BE HASHED\n", auditlog_offset, auditlogbuf_size);
  print_hexstring(auditlogbuf, auditlogbuf_size);

  *actual_auditlog_size = auditlogbuf_size;
  
  /*   (8) SIGN AUDITLOG   */ 
  unsigned char auditlog_hash[32];
  char eth_prefix[80];
  int len_prefix = sprintf(eth_prefix,"%cEthereum Signed Message:\n%d",25, auditlogbuf_size);
  struct SHA3_CTX ctx_sha3;
  keccak_init(&ctx_sha3);
  keccak_update(&ctx_sha3, eth_prefix, len_prefix-1);
  keccak_update(&ctx_sha3, auditlogbuf, auditlogbuf_size);
  keccak_final(&ctx_sha3, &auditlog_hash);

  secp256k1_ecdsa_recoverable_signature sig;
  unsigned char randomize[32];

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  sgx_read_rand(randomize, sizeof(randomize));
  int secp25k1_ret = secp256k1_context_randomize(ctx, randomize);
//  secp25k1_ret = secp256k1_ecdsa_sign(ctx, &sig, auditlog_hash, &enclave_state.enclavekeys.sig_prikey, NULL, NULL);
  secp25k1_ret = secp256k1_ecdsa_sign_recoverable(ctx, &sig, &auditlog_hash, &enclave_state.enclavekeys.sig_prikey, NULL, NULL);

  unsigned char sig_serialized[65];
  int recovery;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &sig_serialized, &recovery, &sig);
  secp256k1_context_destroy(ctx);
  uint8_t v = ((uint8_t) recovery);
  uint8_t p = (uint8_t) 27;
  v = v + p;
  sig_serialized[64] = v;


  printf("[eiPVRA] AUDITLOG SIGNATURE serialized %d\n", sizeof(sig_serialized));
  print_hexstring(&sig_serialized, sizeof(sig_serialized));


  memcpy(auditlog, auditlogbuf, auditlogbuf_size);
  memcpy(auditlog_signature, &sig_serialized, 65);

  enclave_state.auditmetadata.audit_offset = 0;
  enclave_state.auditmetadata.audit_version_no+=1;
  printf("[eiPVRA] Reseting audit log audit_num %d\n", enclave_state.auditmetadata.audit_version_no);

  if(A_DEBUGRDTSC) ocall_rdtsc();

  size_t new_unsealed_data_size = sizeof(enclave_state) + sizeof(struct dAppData);
  for(int i = 0; i < dAD.num_dDS; i++) {
    new_unsealed_data_size += sizeof(struct dynamicDS);
    new_unsealed_data_size += dAD.dDS[i]->buffer_size;
  }


  uint8_t *const new_unsealed_data = (uint8_t *)malloc(new_unsealed_data_size);

  if (new_unsealed_data == NULL) {
      printf("[ecPVRA] malloc new_unsealed_data blob error.\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;
  }

  int new_unsealed_offset = 0;

  memcpy(new_unsealed_data + new_unsealed_offset, &enclave_state, sizeof(struct ES));
  new_unsealed_offset += sizeof(struct ES);

  memcpy(new_unsealed_data + new_unsealed_offset, &dAD, sizeof(struct dAppData));
  new_unsealed_offset += sizeof(struct dAppData);

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(new_unsealed_data + new_unsealed_offset, dAD.dDS[i], sizeof(struct dynamicDS));
    new_unsealed_offset += sizeof(struct dynamicDS);
  }

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(new_unsealed_data + new_unsealed_offset, dAD.dDS[i]->buffer, dAD.dDS[i]->buffer_size);
    new_unsealed_offset += dAD.dDS[i]->buffer_size;
  }

  if(new_unsealed_offset != new_unsealed_data_size) {
    printf("[ecPVRA] creating new_unsealed_data blob error.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  // FREE metadata structs
  for(int i = 0; i < dAD.num_dDS; i++) {
    if(dAD.dDS[i] != NULL)
      free(dAD.dDS[i]);
  }

  if(dAD.dDS != NULL)
    free(dAD.dDS);
  uint32_t seal_size = sgx_calc_sealed_data_size(0U, new_unsealed_data_size);
  if(A_DEBUGRDTSC) printf("[ecPVRA] New seal_size: [%d]\n", seal_size);

  //printf("[ecPVRA] sealedstate_size: %d\n", sgx_calc_sealed_data_size(0U, sizeof(enclave_state)));
  //if(sealedout_size >= sgx_calc_sealed_data_size(0U, sizeof(enclave_state))) {
  ret = sgx_seal_data(0U, NULL, new_unsealed_data_size, new_unsealed_data, seal_size, (sgx_sealed_data_t *)newsealedstate);
  if(ret !=SGX_SUCCESS) {
    print("[ecPVRA] sgx_seal_data() failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  //}
  //else {
  //  printf("[ecPVRA] Size allocated is less than the required size!\n");
  //  ret = SGX_ERROR_INVALID_PARAMETER;
  //  goto cleanup;
  //}

  if(A_DEBUGPRINT) printf("[ecPVRA] Enclave State sealed success\n");
  ret = SGX_SUCCESS;

  cleanup:
//    if (ctx != NULL) secp256k1_context_destroy(ctx); todo uncomment
    if(A_DEBUGRDTSC) ocall_rdtsc();
    return ret;
}
