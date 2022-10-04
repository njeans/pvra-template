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

#include "enclavestate.h"
#include "appPVRA.h"

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
    uint32_t *actual_auditlog_size) {


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
  
  printf("[eaPVRA] PRINTING READABLE AUDITLOG\n");
  int num_entries = enclave_state.auditmetadata.audit_offset;
  for(int i = 0; i < num_entries; i++) {
    printf("HASH[%d]: ", i);
    print_hexstring(&enclave_state.auditmetadata.auditlog.command_hashes[i], 32);
    printf("PKEY[%d]: ", i);
    print_hexstring(&enclave_state.auditmetadata.auditlog.user_pubkeys[i], 64);
  } 
  



  uint32_t auditlogbuf_size = num_entries*(sizeof(secp256k1_pubkey)+sizeof(sha256_hash_t));
  uint8_t *const auditlogbuf = (uint8_t *)malloc(auditlogbuf_size); 
  uint32_t auditlog_offset = 0;


  for(int i = 0; i < num_entries; i++) {
    memcpy(auditlogbuf + auditlog_offset, &enclave_state.auditmetadata.auditlog.command_hashes[i], 32);
    auditlog_offset += 32;
    memcpy(auditlogbuf + auditlog_offset, &enclave_state.auditmetadata.auditlog.user_pubkeys[i], 64);
    auditlog_offset += 64;
  } 

  printf("\n[eaPVRA] PRINTING AUDITLOG BUFFER TO BE HASHED\n", auditlog_offset, auditlogbuf_size);
  print_hexstring(auditlogbuf, auditlogbuf_size);
  printf("\n");

  *actual_auditlog_size = auditlogbuf_size;
  
  /*   (8) SIGN AUDITLOG   */ 

  unsigned char auditlog_hash[32];
  ret = mbedtls_md(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
      (const unsigned char *)auditlogbuf, 
      auditlogbuf_size, 
      auditlog_hash);
  if(ret != 0) {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  secp256k1_ecdsa_signature sig;
  unsigned char randomize[32];

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  sgx_read_rand(randomize, sizeof(randomize));
  int secp25k1_ret = secp256k1_context_randomize(ctx, randomize);
  secp25k1_ret = secp256k1_ecdsa_sign(ctx, &sig, auditlog_hash, &enclave_state.enclavekeys.sig_prikey, NULL, NULL);

  //printf("[eiPVRA] PUBKEYS SIGNATURE %d\n", sizeof(secp256k1_ecdsa_signature));
  //print_hexstring(&sig, sizeof(secp256k1_ecdsa_signature));

  memcpy(auditlog, auditlogbuf, auditlogbuf_size);
  memcpy(auditlog_signature, &sig, 64);
  secp256k1_context_destroy(ctx);

  if(A_DEBUGRDTSC) ocall_rdtsc();



  cleanup:
    if(A_DEBUGRDTSC) ocall_rdtsc();
    return ret;
}
