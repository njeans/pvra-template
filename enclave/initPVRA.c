/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclavestate.h"

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

//#include <secp256k1.h>
//#include <secp256k1_ecdh.h>


#define BUFLEN 2048
#define KEY_SIZE 2048
#define MBED_TLS_KEY_SIZE 2049
#define EXPONENT 65537


#define I_DEBUGPRINT 1
#define I_DEBUGRDTSC 0

/**
 * This function initializes a PVRA enclave.
 *
 * @param 
 *
 * @return SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */

sgx_status_t ecall_initPVRA(
    sgx_report_t *report, 
    sgx_target_info_t *target_info, 
    char *sealedstate, size_t sealedstate_size, 
    char *enckey_signature, size_t signature_size, 
    char *pub_enckey, size_t enckey_size) {
  
  struct ES enclave_state;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;



  //unsigned char randomize[32];
  //secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  //sgx_read_rand(randomize, sizeof(randomize));



  if(I_DEBUGRDTSC) ocall_rdtsc();
  if(I_DEBUGRDTSC) ocall_rdtsc();
  /*    Generate Enclave Encryption Key secp256r1    */

  sgx_ecc_state_handle_t p_ecc_handle_e = NULL;
  ret = sgx_ecc256_open_context(&p_ecc_handle_e);
  if(ret != SGX_SUCCESS) {
    printf("[eiPVRA] sgx_ecc256_open_context() failed.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  sgx_ec256_private_t p_private_e;
  sgx_ec256_public_t p_public_e;
  ret = sgx_ecc256_create_key_pair(&p_private_e, &p_public_e, p_ecc_handle_e);
  if(ret != SGX_SUCCESS) {
    printf("[eiPVRA] sgx_ecc256_create_key_pair() failed.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  //enclave_state.enclavekeys.encrypt_prikey = p_private_e;
  //enclave_state.enclavekeys.encrypt_pubkey = p_public_e;

  //if(I_DEBUGPRINT) printf("[eiPVRA] Public Enclave secp256r1 Encryption Key\n");
  //if(I_DEBUGPRINT) print_hexstring(&enclave_state.enclavekeys.encrypt_pubkey, sizeof(sgx_ec256_public_t)/2);
  //if(I_DEBUGPRINT) print_hexstring((char *)(&enclave_state.enclavekeys.encrypt_pubkey)+32, sizeof(sgx_ec256_public_t)/2);
  //if(I_DEBUGPRINT) printf("\n");






  if(I_DEBUGRDTSC) ocall_rdtsc();
  /*    Generate Enclave 2048b-RSA Encryption Key    */


  size_t pri_len = 2048;
  size_t pub_len = 2048;
  const char *pers = "rsa_genkey";
  mbedtls_pk_context pk;    
  mbedtls_rsa_context rsa;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_mpi_init(&N); 
  mbedtls_mpi_init(&P); 
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&D); 
  mbedtls_mpi_init(&E); 
  mbedtls_mpi_init(&DP);
  mbedtls_mpi_init(&DQ); 
  mbedtls_mpi_init(&QP);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
  if(ret != 0) {
    printf("[eiPVRA] mbedtls_ctr_drbg_seed failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT);
  if(ret != 0) {
    printf("[eiPVRA] mbedtls_rsa_gen_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  mbedtls_pk_init(&pk);
  ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
  if(ret != 0) {
    printf("[eiPVRA] mbedtls_pk_setup failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  
  memcpy(mbedtls_pk_rsa(pk), &rsa, sizeof(mbedtls_rsa_context));
  ret = mbedtls_pk_write_key_pem(&pk, enclave_state.enclavekeys.priv_key_buffer, pri_len);
  if(ret != 0) {
    printf("[eiPVRA] mbedtls_pk_write_key_pem failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  
  ret = mbedtls_pk_write_pubkey_pem (&pk, enclave_state.enclavekeys.pub_key_buffer, pub_len);
  if(ret != 0) {
    printf("[eiPVRA] mbedtls_pk_write_pubkey_pem failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  if(I_DEBUGPRINT) printf("[eiPVRA] Public Enclave 2048b-RSA Encryption Key\n%s\n", &enclave_state.enclavekeys.pub_key_buffer);
  //if(I_DEBUGPRINT) printf("[eiPVRA] Private Enclave RSA Encryption Key (RSA2048.pem)\n%s\n", &enclave_state.enclavekeys.priv_key_buffer);






  if(I_DEBUGRDTSC) ocall_rdtsc();
  /*    Generate Enclave secp256r1 Attestation Key    */

  sgx_ecc_state_handle_t p_ecc_handle_s = NULL;
  ret = sgx_ecc256_open_context(&p_ecc_handle_s);
  if(ret != SGX_SUCCESS) {
    printf("[eiPVRA] sgx_ecc256_open_context() failed.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  sgx_ec256_private_t p_private_s;
  sgx_ec256_public_t p_public_s;
  ret = sgx_ecc256_create_key_pair(&p_private_s, &p_public_s, p_ecc_handle_s);
  if(ret != SGX_SUCCESS) {
    printf("[eiPVRA] sgx_ecc256_create_key_pair() failed.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  enclave_state.enclavekeys.sign_prikey = p_private_s;
  enclave_state.enclavekeys.sign_pubkey = p_public_s;

  if(I_DEBUGPRINT) printf("[eiPVRA] Public Enclave secp256r1 Signing Key\n");
  if(I_DEBUGPRINT) print_hexstring(&enclave_state.enclavekeys.sign_pubkey, sizeof(sgx_ec256_public_t)/2);
  if(I_DEBUGPRINT) print_hexstring((char *)(&enclave_state.enclavekeys.sign_pubkey)+32, sizeof(sgx_ec256_public_t)/2);
  if(I_DEBUGPRINT) printf("\n");






  if(I_DEBUGRDTSC) ocall_rdtsc();
  /*    Sign Encryption Key    */

  sgx_ecc_state_handle_t p_ecc_handle_sign = NULL;
  ret = sgx_ecc256_open_context(&p_ecc_handle_sign);
  if(ret != SGX_SUCCESS) {
    printf("[eiPVRA] sgx_ecc256_open_context() failed.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  // Reverse Endianess 
  /*
  sgx_ec256_public_t bigendian_encrypt_pubkey;
  for(int i = 0; i < SGX_ECP256_KEY_SIZE; i++) {
    bigendian_encrypt_pubkey.gx[i] = enclave_state.enclavekeys.encrypt_pubkey.gx[SGX_ECP256_KEY_SIZE-i-1];
    bigendian_encrypt_pubkey.gy[i] = enclave_state.enclavekeys.encrypt_pubkey.gy[SGX_ECP256_KEY_SIZE-i-1];
  }*/

  ret = sgx_ecdsa_sign(&enclave_state.enclavekeys.pub_key_buffer, strlen(&enclave_state.enclavekeys.pub_key_buffer), &enclave_state.enclavekeys.sign_prikey, (sgx_ec256_signature_t *)enckey_signature, p_ecc_handle_sign);
  if(ret != SGX_SUCCESS) {
    printf("[eiPVRA] sgx_ecdsa_sign() failed.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  //printf("%p %p %d %d\n", pub_enckey, &p_public_e, sizeof(p_public_e),  signature_size);
  //ocallbuf(strlen(&enclave_state.enclavekeys.pub_key_buffer));
  //print_hexstring(&p_public_e, sizeof(p_public_e));
  //print_hexstring(&hpub_key, sizeof(hpub_key));
  memcpy(pub_enckey, &enclave_state.enclavekeys.pub_key_buffer, strlen(&enclave_state.enclavekeys.pub_key_buffer));






  if(I_DEBUGRDTSC) ocall_rdtsc();
  /*    Initialize Enclave State    */

  /*    Initialize Application Data    */
  struct dAppData dAD;
  int initES_ret = initES(&enclave_state, &dAD);

  if(initES_ret != 0) {
    printf("[eiPVRA] initES() memory allocation failure.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }


  if(I_DEBUGPRINT) printf("[eiPVRA] Initialized application data state success\n");


  /*    Initialize SCS Metadata    */
  for(int i = 0; i < 32; i++) {
    enclave_state.counter.freshness_tag[i] = 0;
  }
  const uint8_t *CCF_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEA22K4KWhmw4IggNWUqtU+yY3C65QgtmVWWFTcTrTUBQwAHC7aqmBK\nBaLM4gAuqAx5nqj0nbfJyaRLzDZImZtI0jF810DJYiQSbArzU7BsTaPAypGC/qB2\ntiRPH+UYNGbFaKhPw/ymdSlqixd0D5YBMMLY6V+GieYNrlkKIQyLEQ7Odwg9UEtf\nyW++Jhdp2BHl5U5c6ZfpOPxpG7vb5tH22z1R6vzYulZ1h6WI+vl92d3REs+Yh9N0\nZMZ/x4J0+4m1T3PmEL1lTKuXxrpYtswYRdfY4+IlVIjzVUDyWv4D9QlcjI3QPxP7\neOtjNcPmGsculftOn70ghJtcvKuUjHAzNQIDAQAB\n-----END PUBLIC KEY-----\n";

  memcpy(enclave_state.counter.CCF_key, CCF_key, strlen(CCF_key));
  if(I_DEBUGPRINT) printf("[eiPVRA] Public CCF Signing Key (RSA2048.pem)\n%s\n", &enclave_state.counter.CCF_key);


  /*    Initialize Anti-Replay Metadata    */
  for(int i = 0; i < 10; i++) {
    enclave_state.antireplay.seqno[i] = 0;
  }


  /*    Initialize USER pubkeys    */
  //[TODO]


  /*    Sign all USER pubkeys    */
  //[TODO]




  if(I_DEBUGRDTSC) ocall_rdtsc();
  /*    Generate Quote    */

  sgx_report_data_t report_data = {{0}};
  memcpy((uint8_t *const) &report_data, (uint8_t *)&enclave_state.enclavekeys.sign_pubkey, sizeof(sgx_ec256_public_t));

  if(I_DEBUGPRINT) printf("[eiPVRA] Calling enclave to generate attestation report\n");
  ret = sgx_create_report(target_info, &report_data, report);
  //printf("[eiPVRA]: Unsealed the sealed public key and created a report containing the public key in the report data.\n");






  if(I_DEBUGRDTSC) ocall_rdtsc();
  /*    Seal Enclave State    */

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


  // FREE metadata structs
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
  // Step 4: Close Context.
  if (p_ecc_handle_e != NULL) {
    sgx_ecc256_close_context(p_ecc_handle_e);
  }
  if (p_ecc_handle_s != NULL) {
    sgx_ecc256_close_context(p_ecc_handle_s);
  }
  if (p_ecc_handle_sign != NULL) {
    sgx_ecc256_close_context(p_ecc_handle_sign);
  }
  mbedtls_rsa_free(&rsa);
  mbedtls_mpi_free(&N); 
  mbedtls_mpi_free(&P); 
  mbedtls_mpi_free(&Q);
  mbedtls_mpi_free(&D); 
  mbedtls_mpi_free(&E); 
  mbedtls_mpi_free(&DP);
  mbedtls_mpi_free(&DQ); 
  mbedtls_mpi_free(&QP);

  if(I_DEBUGRDTSC) ocall_rdtsc();
  return ret;
}
