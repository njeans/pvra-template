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

#define I_DEBUGPRINT 1
#define I_DEBUGRDTSC 0
#define DETERMINISTIC_ENC_KEY 1




/**
 * This function initializes a PVRA enclave.
 *
 * @param [out] sealedstate: storage of initial enclave state seal.
 * @param [out] encpubkey: 64 byte secp256k1 enclave encryption key.
 * @param [out] encpubkey_signature: enclave-signed encryption key.
 * @param [in] userpubkeys: list of verified users the enclave will recognize.
 * @param [out] userpubkeys_signature: enclave-signed list of user pubkeys.
 *        
 * @return SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */



sgx_status_t ecall_initPVRA(
    sgx_report_t *report, 
    sgx_target_info_t *target_info, 
    char *sealedstate, size_t sealedstate_size, 
    char *encpubkey, size_t encpubkey_size,
    char *encpubkey_signature, size_t encpubkey_signature_size, 
    char *userpubkeys, size_t userpubkeys_size,
    char *userpubkeys_signature, size_t userpubkeys_signature_size) {
  

  struct ES enclave_state;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int secp25k1_ret;

  // Control Timing Measurement of an OCALL Overhead.
  if(I_DEBUGRDTSC) ocall_rdtsc();
  if(I_DEBUGRDTSC) ocall_rdtsc();





  /*    Generate secp256k1 Enclave Encryption Key    */

  unsigned char randomize_e[32];
  secp256k1_prikey seckey_e;
  if(DETERMINISTIC_ENC_KEY) {
    for (int i = 0; i < 32; i++) {
      seckey_e.data[i] = 'c';
    }
  }
  secp256k1_pubkey pubkey_e;
  secp256k1_context* ctx_e = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  // [TODO]: Handle NULL
  if(!DETERMINISTIC_ENC_KEY) sgx_read_rand(randomize_e, sizeof(randomize_e));
  secp25k1_ret = secp256k1_context_randomize(ctx_e, randomize_e);
  // [TODO]: Handle ret
  if(!DETERMINISTIC_ENC_KEY) sgx_read_rand(&seckey_e, sizeof(seckey_e));
  secp25k1_ret = secp256k1_ec_pubkey_create(ctx_e, &pubkey_e, &seckey_e);
  // [TODO]: Handle ret
  enclave_state.enclavekeys.enc_pubkey = pubkey_e;
  enclave_state.enclavekeys.enc_prikey = seckey_e;
  secp256k1_context_destroy(ctx_e);
  memset(&seckey_e, 0, sizeof(seckey_e));
  if(I_DEBUGPRINT) printf("[eiPVRA] Public Enclave Encryption Key (secp256k1)\n");
  if(I_DEBUGPRINT) print_hexstring(&enclave_state.enclavekeys.enc_pubkey, 32);
  if(I_DEBUGPRINT) print_hexstring((char *)(&enclave_state.enclavekeys.enc_pubkey)+32, 32);
  if(I_DEBUGPRINT) printf("\n");

  /* Hardcoded User0 PubKey for testing ECDH Flow in client script */ /*
  //728c48ee66b4229ca476914fc87130014f5bd5eda29116578b2fc2dca01f4b7eb88b77acc107d4136649c470de332962daf17eeead91e5b253fa9912caa94d11
  
  unsigned char user0_pubk[64] = {
    0x72, 0x8c, 0x48, 0xee, 0x66, 0xb4, 0x22, 0x9c, 0xa4, 0x76, 0x91, 0x4f, 0xc8, 0x71, 0x30, 0x01, 0x4f, 0x5b, 0xd5, 0xed, 0xa2, 0x91, 0x16, 0x57, 0x8b, 0x2f, 0xc2, 0xdc, 0xa0, 0x1f, 0x4b, 0x7e, 0xb8, 0x8b, 0x77, 0xac, 0xc1, 0x07, 0xd4, 0x13, 0x66, 0x49, 0xc4, 0x70, 0xde, 0x33, 0x29, 0x62, 0xda, 0xf1, 0x7e, 0xee, 0xad, 0x91, 0xe5, 0xb2, 0x53, 0xfa, 0x99, 0x12, 0xca, 0xa9, 0x4d, 0x11
  };
  secp256k1_pubkey user0_pubkey;
  memcpy(&user0_pubkey, user0_pubk, 64);

  unsigned char user0_prik[64] = {
    0x0a, 0x9f, 0x3a, 0xdc, 0xd5, 0x4e, 0xe2, 0x04, 0x33, 0x15, 0x21, 0x0d, 0xd6, 0xa4, 0xd2, 0xc8, 0xf9, 0x05, 0x90, 0x73, 0x3a, 0x22, 0x7d, 0x6f, 0xc4, 0xa0, 0x87, 0x24, 0x54, 0x3a, 0x24, 0xe2
  };
  secp256k1_prikey user0_prikey;
  memcpy(&user0_prikey, user0_prik, 64);

  unsigned char shared_secret[32];
  secp25k1_ret = secp256k1_ecdh(ctx_e, shared_secret, &user0_pubkey, &enclave_state.enclavekeys.enc_prikey, NULL, NULL);
  if(I_DEBUGPRINT) printf("[eiPVRA] Enclave Generated User0 Shared Secret\n");
  if(I_DEBUGPRINT) print_hexstring(&shared_secret, 32);
  if(I_DEBUGPRINT) printf("\n");

  unsigned char shared_secret2[32];
  secp25k1_ret = secp256k1_ecdh(ctx_e, shared_secret2, &enclave_state.enclavekeys.enc_pubkey, &user0_prikey, NULL, NULL);  
  if(I_DEBUGPRINT) printf("[eiPVRA] User0 Generated Enclave Shared Secret\n");
  if(I_DEBUGPRINT) print_hexstring(&shared_secret2, 32);
  if(I_DEBUGPRINT) printf("\n");
  */
  if(I_DEBUGRDTSC) ocall_rdtsc();





  /*    Generate secp256k1 Enclave Signing Key    */

  unsigned char randomize_s[32];
  secp256k1_prikey seckey_s;
  secp256k1_pubkey pubkey_s;
  secp256k1_context* ctx_s = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  // [TODO]: Handle NULL
  sgx_read_rand(randomize_s, sizeof(randomize_s));
  secp25k1_ret = secp256k1_context_randomize(ctx_s, randomize_s);
  // [TODO]: Handle ret
  sgx_read_rand(&seckey_s, sizeof(seckey_s));
  secp25k1_ret = secp256k1_ec_pubkey_create(ctx_s, &pubkey_s, &seckey_s);
  // [TODO]: Handle ret
  enclave_state.enclavekeys.sig_pubkey = pubkey_s;
  enclave_state.enclavekeys.sig_prikey = seckey_s;
  secp256k1_context_destroy(ctx_s);
  memset(&seckey_s, 0, sizeof(seckey_s));
  if(I_DEBUGPRINT) printf("[eiPVRA] Public Enclave Signing Key (secp256k1)\n");
  if(I_DEBUGPRINT) print_hexstring(&enclave_state.enclavekeys.sig_pubkey, 32);
  if(I_DEBUGPRINT) print_hexstring((char *)(&enclave_state.enclavekeys.sig_pubkey)+32, 32);
  if(I_DEBUGPRINT) printf("\n");

  if(I_DEBUGRDTSC) ocall_rdtsc();



  

  /*    Sign secp256k1 Enclave Encryption Key    */

  unsigned char enc_pubkey_hash[32];
  ret = mbedtls_md(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
      (const unsigned char *)&enclave_state.enclavekeys.enc_pubkey, 
      sizeof(secp256k1_pubkey), 
      enc_pubkey_hash);
  if(ret != 0) {
    printf("[eiPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  secp256k1_ecdsa_signature enc_pubkey_sig;
  unsigned char enc_pubkey_randomize[32];

  secp256k1_context* enc_pubkey_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  sgx_read_rand(enc_pubkey_randomize, sizeof(enc_pubkey_randomize));
  secp25k1_ret = secp256k1_context_randomize(enc_pubkey_ctx, enc_pubkey_randomize);
  secp25k1_ret = secp256k1_ecdsa_sign(enc_pubkey_ctx, &enc_pubkey_sig, enc_pubkey_hash, &enclave_state.enclavekeys.sig_prikey, NULL, NULL);

  //printf("[eiPVRA] ENCPUBKEY SIGNATURE %d\n", sizeof(secp256k1_ecdsa_signature));
  //print_hexstring(&enc_pubkey_sig, sizeof(secp256k1_ecdsa_signature));

  memcpy(encpubkey_signature, &enc_pubkey_sig, 64);
  memcpy(encpubkey, &enclave_state.enclavekeys.enc_pubkey, sizeof(secp256k1_pubkey));

  if(I_DEBUGRDTSC) ocall_rdtsc();





  /*    Initialize Enclave State    */


  /*    Initialize SCS Metadata    */

  for(int i = 0; i < 32; i++) {
    enclave_state.counter.freshness_tag[i] = 0;
  }
  const uint8_t *CCF_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEA22K4KWhmw4IggNWUqtU+yY3C65QgtmVWWFTcTrTUBQwAHC7aqmBK\nBaLM4gAuqAx5nqj0nbfJyaRLzDZImZtI0jF810DJYiQSbArzU7BsTaPAypGC/qB2\ntiRPH+UYNGbFaKhPw/ymdSlqixd0D5YBMMLY6V+GieYNrlkKIQyLEQ7Odwg9UEtf\nyW++Jhdp2BHl5U5c6ZfpOPxpG7vb5tH22z1R6vzYulZ1h6WI+vl92d3REs+Yh9N0\nZMZ/x4J0+4m1T3PmEL1lTKuXxrpYtswYRdfY4+IlVIjzVUDyWv4D9QlcjI3QPxP7\neOtjNcPmGsculftOn70ghJtcvKuUjHAzNQIDAQAB\n-----END PUBLIC KEY-----\n";

  memcpy(enclave_state.counter.CCF_key, CCF_key, strlen(CCF_key));
  if(I_DEBUGPRINT) printf("[eiPVRA] Public CCF Signing Key (RSA2048.pem)\n%s\n", CCF_key);
  if(I_DEBUGPRINT) printf("[eiPVRA] Initialized SCS metadata success\n");


  /*    Initialize Anti-Replay Metadata    */

  for(int i = 0; i < 10; i++) {
    enclave_state.antireplay.seqno[i] = 0;
  }
  if(I_DEBUGPRINT) printf("[eiPVRA] Initialized seqno metadata success\n");


  /*    Initialize Application Data    */

  struct dAppData dAD;
  int initES_ret = initES(&enclave_state, &dAD);

  if(initES_ret != 0) {
    printf("[eiPVRA] initES() memory allocation failure.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  if(I_DEBUGPRINT) printf("[eiPVRA] Initialized application data success\n");


  /*    Initialize USER pubkeys    */

  // Parsing userpubkeys from pubkeys.list
  int num_offset = 0;
  while(userpubkeys[num_offset] != '\n') {
    num_offset++;
    if(num_offset > userpubkeys_size) {
      printf("[eiPVRA] userpubkeys incorrect format.\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
    }
  }

  char *num_buffer = malloc(num_offset+1);
  strncpy(num_buffer, userpubkeys, num_offset);
  num_buffer[num_offset] = 0;
  int num_pubkeys = atoi(num_buffer);
  free(num_buffer);

  enclave_state.auditmetadata.num_pubkeys = num_pubkeys;

  char temp_key_hexstring[129];
  char temp_key_bytes[64];
  num_offset += 1;
  for(int i = 0; i < num_pubkeys; i++) {
    if(num_offset+128 > userpubkeys_size) {
      printf("[eiPVRA] userpubkeys incorrect format.\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
    }
    strncpy(temp_key_hexstring, &userpubkeys[num_offset], 128);
    temp_key_hexstring[128] = 0;
    num_offset += 129;

    // hexstring to bytes
    for(int j = 0; j < 64; j++) {
      char c1 = temp_key_hexstring[2*j];
      int value1 = 0;
      if(c1 >= '0' && c1 <= '9')
        value1 = (c1 - '0');
      else if (c1 >= 'A' && c1 <= 'F') 
        value1 = (10 + (c1 - 'A'));
      else if (c1 >= 'a' && c1 <= 'f')
        value1 = (10 + (c1 - 'a'));
      char c0 = temp_key_hexstring[2*j+1];
      int value0 = 0;
      if(c0 >= '0' && c0 <= '9')
        value0 = (c0 - '0');
      else if (c0 >= 'A' && c0 <= 'F') 
        value0 = (10 + (c0 - 'A'));
      else if (c0 >= 'a' && c0 <= 'f')
        value0 = (10 + (c0 - 'a'));
      temp_key_bytes[j] = (value1<<4) | value0;
    }

    if (i > MAX_USERS) {
      printf("[eiPVRA] pubkeys not enough allocated space.\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
    }
    memcpy(&enclave_state.auditmetadata.master_user_pubkeys[i], temp_key_bytes, sizeof(secp256k1_pubkey));
  }
  if(I_DEBUGPRINT) printf("[eiPVRA] Initialized [%d] User Public Keys success\n", num_pubkeys);


  /*    Initialize AUDIT LOG metadata    */

  enclave_state.auditmetadata.audit_offset = 0;
  enclave_state.auditmetadata.audit_version_no = 0;
  if(I_DEBUGPRINT) printf("[eiPVRA] Initialized audit log metadata success\n");


  /*    Sign all USER pubkeys    */

  unsigned char msg_hash[32];
  ret = mbedtls_md(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
      (const unsigned char *)enclave_state.auditmetadata.master_user_pubkeys, 
      enclave_state.auditmetadata.num_pubkeys*sizeof(sgx_ec256_public_t), 
      msg_hash);
  if(ret != 0) {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  //printf("[eiPVRA] PUBKEYS %d\n", enclave_state.auditmetadata.num_pubkeys*sizeof(sgx_ec256_public_t));
  //print_hexstring(enclave_state.auditmetadata.master_user_pubkeys, enclave_state.auditmetadata.num_pubkeys*sizeof(sgx_ec256_public_t));
  //print_hexstring(msg_hash, 32);

  secp256k1_ecdsa_signature sig;
  unsigned char randomize[32];

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  sgx_read_rand(randomize, sizeof(randomize));
  secp25k1_ret = secp256k1_context_randomize(ctx, randomize);
  secp25k1_ret = secp256k1_ecdsa_sign(ctx, &sig, msg_hash, &enclave_state.enclavekeys.sig_prikey, NULL, NULL);

  //printf("[eiPVRA] PUBKEYS SIGNATURE %d\n", sizeof(secp256k1_ecdsa_signature));
  //print_hexstring(&sig, sizeof(secp256k1_ecdsa_signature));

  memcpy(userpubkeys_signature, &sig, 64);
  secp256k1_context_destroy(ctx);

  if(I_DEBUGPRINT) printf("[eiPVRA] Signed [%d] User Public Keys\n", num_pubkeys);

  /* Verification Code */ /*
  int is_signature_valid;
  if (!secp256k1_ecdsa_signature_parse_compact(ctx1, &sig, serialized_signature)) {
      printf("[eiPVRA] Failed parsing the signature.\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  // Verify a signature. This will return 1 if it's valid and 0 if it's not. 
  is_signature_valid = secp256k1_ecdsa_verify(ctx1, &sig, msg_hash, &pubkey);

  printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");

  printf("Secret Key: ");
  print_hexstring(&enclave_state.enclavekeys.enc_prikey, sizeof(secp256k1_prikey));
  printf("Public Key: ");
  print_hexstring(&enclave_state.enclavekeys.enc_pubkey, sizeof(secp256k1_pubkey));
  printf("Signature: ");
  print_hexstring(serialized_signature, sizeof(serialized_signature)); 
  */
  if(I_DEBUGRDTSC) ocall_rdtsc();
  



  
  /*    Generate Quote    */

  sgx_report_data_t report_data = {{0}};
  memcpy((uint8_t *const) &report_data, (uint8_t *)&enclave_state.enclavekeys.sig_pubkey, 64);

  if(I_DEBUGPRINT) printf("[eiPVRA] Calling enclave to generate attestation report\n");
  ret = sgx_create_report(target_info, &report_data, report);
  //printf("[eiPVRA]: Unsealed the sealed public key and created a report containing the public key in the report data.\n");

  if(I_DEBUGRDTSC) ocall_rdtsc();




  
  /*    Seal Enclave State    */

  // Append dynamic data structures at after the enclave_state struct
  uint32_t unsealed_data_size = sizeof(struct ES) + sizeof(struct dAppData);
  for(int i = 0; i < dAD.num_dDS; i++) {
    unsealed_data_size += sizeof(struct dynamicDS);
    unsealed_data_size += dAD.dDS[i]->buffer_size;
  }
  uint8_t *const unsealed_data = (uint8_t *)malloc(unsealed_data_size); 

  int unsealed_offset = 0;
  memcpy(unsealed_data + unsealed_offset, &enclave_state, sizeof(struct ES));
  unsealed_offset += sizeof(struct ES);

  memcpy(unsealed_data + unsealed_offset, &dAD, sizeof(struct dAppData));
  unsealed_offset += sizeof(struct dAppData);

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(unsealed_data + unsealed_offset, dAD.dDS[i], sizeof(struct dynamicDS));
    unsealed_offset += sizeof(struct dynamicDS);
  }

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(unsealed_data + unsealed_offset, dAD.dDS[i]->buffer, dAD.dDS[i]->buffer_size);
    unsealed_offset += dAD.dDS[i]->buffer_size;
  }

  if(unsealed_offset != unsealed_data_size) {
    printf("[eiPVRA] creating unsealed_data blob error.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  // FREE dynamic AD metadata structs
  for(int i = 0; i < dAD.num_dDS; i++) {
    if(dAD.dDS[i] != NULL)
      free(dAD.dDS[i]);
  }
  if(dAD.dDS != NULL)
    free(dAD.dDS);

  uint32_t init_seal_size = sgx_calc_sealed_data_size(0U, unsealed_data_size);
  if(I_DEBUGPRINT) printf("[eiPVRA] Initial seal_size: [%d]\n", init_seal_size);

  /*if(sealedstate_size < init_seal_size) {
    printf("[eiPVRA] Size allocated for seal is insufficient.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }*/

  ret = sgx_seal_data(0U, NULL, unsealed_data_size, unsealed_data, init_seal_size, (sgx_sealed_data_t *)sealedstate);
  if(ret != SGX_SUCCESS) {
    printf("[eiPVRA] sgx_seal_data() failed. %d\n", ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  if(I_DEBUGPRINT) printf("[eiPVRA] Quote generated success");
  ret = SGX_SUCCESS;

cleanup:
  if(I_DEBUGRDTSC) ocall_rdtsc();
  return ret;
}
