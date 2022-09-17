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
#include <sgx_trts.h>

#include <tlibc/math.h>
#include <tlibc/string.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

#define BUFLEN 2048
#define KEY_SIZE 2048
#define MBED_TLS_KEY_SIZE 2049
#define EXPONENT 65537

static uint8_t pub_key_hardcoded[64] = {0x72, 0xe4, 0xa5, 0xcd, 0x3a, 0x58, 0x9a, 0xc9, 0xb1, 0x09, 0x88, 0xfe, 0x2c, 0xa7, 0xdd, 0x65, 0xed, 0xa2, 0x90, 0xf0, 0x76, 0x47, 0xd3, 0xa7, 0x85, 0x58, 0xea, 0x1d, 0x6e, 0x10, 0x51, 0x31, 0xcf, 0xe6, 0x2c, 0x89, 0xe6, 0xc1, 0x0f, 0x55, 0xaa, 0x98, 0xc0, 0x18, 0x91, 0x26, 0x51, 0x90, 0xf0, 0xdf, 0x76, 0x67, 0x8f, 0x5c, 0x85, 0x42, 0x75, 0xf9, 0x44, 0x90, 0x94, 0x84, 0x81, 0xef};
static uint8_t priv_key_hardcoded[32] = {0xb8, 0xb4, 0x75, 0x0e, 0x84, 0xf9, 0xea, 0x10, 0xf3, 0x04, 0x79, 0x4b, 0xbe, 0x85, 0xc2, 0xce, 0x2f, 0xee, 0xf5, 0x27, 0xb8, 0xb7, 0x32, 0xd5, 0xef, 0x00, 0x49, 0xa6, 0x0b, 0x13, 0x2e, 0xfd};

/**
 * This is a test ecall that generates an mbedtls rsa key, signs some data, and verifies it 
 *
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenInEnclaveState            length of encrypted enclave state buffer
 * @param cli_in                       encrypted client input (command)
 * @param lenInCliIn                   length of encrypted client input (command)
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_mbed_sign_enclave_state_and_command_signature(uint8_t enclave_state_in[BUFLEN], size_t lenInEnclaveState, uint8_t cli_in[BUFLEN], size_t lenInCliIn, 
                                int counter, uint8_t priv_key_buffer[MBED_TLS_KEY_SIZE], uint8_t pub_key_buffer[MBED_TLS_KEY_SIZE], uint8_t signature[MBEDTLS_MPI_MAX_SIZE]) 
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  
  size_t pri_len = 2048;
  size_t pub_len = 2048;     
  const char *pers = "rsa_genkey";
  
  mbedtls_pk_context pk;    
  mbedtls_rsa_context rsa;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
  
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
  mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
  mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
  mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
  mbedtls_entropy_init( &entropy );
  
  if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    print("\nTrustedApp: mbedtls_rsa_check_privkey returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  
  if((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT)) != 0) {
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    print("\nTrustedApp: mbedtls_rsa_gen_key returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  mbedtls_pk_init( &pk );

  if((ret = mbedtls_pk_setup( &pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA) )) != 0) {
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_entropy_free( &entropy );
    print("\nTrustedApp: mbedtls_pk_setup returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  
  memcpy(mbedtls_pk_rsa(pk),  &rsa, sizeof(mbedtls_rsa_context));

  if((ret = mbedtls_pk_write_key_pem( &pk, priv_key_buffer, pri_len )) != 0) {
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_entropy_free( &entropy );
    print("\nTrustedApp: mbedtls_pk_write_key_pem returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  
  if((ret = mbedtls_pk_write_pubkey_pem ( &pk, pub_key_buffer, pub_len )) != 0) {
    mbedtls_rsa_free( &rsa );
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_entropy_free( &entropy );
    print("\nTrustedApp: mbedtls_pk_write_pubkey_pem returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  
  mbedtls_rsa_free( &rsa );
  mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
  mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
  mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

  // convert the counter integer to string
  int num_digits = 0;
  int counter_temp = counter;
  while (counter_temp > 0) {
    counter_temp /= 10;
    num_digits++;
  }
  char counter_str[BUFLEN] = {0};
  counter_temp = counter;
  counter_str[num_digits] = 0;
  for (int j = num_digits - 1; j >= 0; --j, counter_temp /= 10) {
      counter_str[j] = (counter_temp % 10) + '0';
  } 
  // combine the enclave state data and client input (command) data into one array
  uint8_t enclave_state_client_input_combined[BUFLEN] = {0};
  int combined_index = 0;
  for (int i = 0; i < lenInEnclaveState; i++) {
    enclave_state_client_input_combined[combined_index] = enclave_state_in[i];
    combined_index++;
  }
  for (int i = 0; i < lenInCliIn; i++) {
    enclave_state_client_input_combined[combined_index] = cli_in[i];
    combined_index++;
  }
  for (int i = 0; i < strlen(counter_str); i++) {
    enclave_state_client_input_combined[combined_index] = counter_str[i];
    combined_index++;
  }
  int len_combined = combined_index;

  unsigned char hashbuf[32];
  unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
  
  mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
  mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
  mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
  mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
  mbedtls_pk_init(&pk);
  
  if((ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)priv_key_buffer, strlen(priv_key_buffer)+1, 0, 0)) != 0) {
      mbedtls_rsa_free( &rsa );
      mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
      mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
      mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
      print("\nTrustedApp: mbedtls_pk_parse_key returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  mbedtls_rsa_context *rsapk = mbedtls_pk_rsa( pk );
      
  if((ret = mbedtls_rsa_check_privkey(rsapk)) != 0) {
      mbedtls_rsa_free( &rsa );
      mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
      mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
      mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
      print("\nTrustedApp: mbedtls_rsa_check_privkey returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  if((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)enclave_state_client_input_combined, len_combined, hashbuf)) != 0) {
      mbedtls_rsa_free( &rsa );
      mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
      mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
      mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
      print("\nTrustedApp: mbedtls_md returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  if((ret = mbedtls_rsa_pkcs1_sign(rsapk, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 64, hashbuf, signature)) != 0) {
      mbedtls_rsa_free( &rsa );
      mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
      mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
      mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
      print("\nTrustedApp: mbedtls_rsa_pkcs1_sign returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }
  
  ret = SGX_SUCCESS;
  return ret;
}

/**
 * This function verifies that an encrypted enclave state and encrypted client input (command) corresponds to some signature 
 *
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenInEnclaveState            length of encrypted enclave state buffer
 * @param cli_in                       encrypted client input (command)
 * @param lenInCliIn                   length of encrypted client input (command)
 * @param public_key_buffer            public key buffer to verify signature
 * @param signature                    signature buffer (should be the signed encrypted enclave state + client input)
 * @param result                       result buffer. first entry will be 0 if the verification is successful and non-0 otherwise
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_mbed_verify_enclave_state_and_command_signature(uint8_t enclave_state_in[BUFLEN], size_t lenInEnclaveState, uint8_t cli_in[BUFLEN], size_t lenInCliIn, 
                                                    int counter, uint8_t public_key_buffer[BUFLEN], uint8_t signature[MBEDTLS_MPI_MAX_SIZE]) 
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  // convert the counter integer to string
  int num_digits = 0;
  int counter_temp = counter;
  while (counter_temp > 0) {
    counter_temp /= 10;
    num_digits++;
  }
  char counter_str[BUFLEN] = {0};
  counter_temp = counter;
  counter_str[num_digits] = 0;
  for (int j = num_digits - 1; j >= 0; --j, counter_temp /= 10) {
      counter_str[j] = (counter_temp % 10) + '0';
  } 
  // combine the enclave state data and client input (command) data into one array
  uint8_t enclave_state_client_input_combined[BUFLEN] = {0};
  int combined_index = 0;
  for (int i = 0; i < lenInEnclaveState; i++) {
    enclave_state_client_input_combined[combined_index] = enclave_state_in[i];
    combined_index++;
  }
  for (int i = 0; i < lenInCliIn; i++) {
    enclave_state_client_input_combined[combined_index] = cli_in[i];
    combined_index++;
  }
  for (int i = 0; i < strlen(counter_str); i++) {
    enclave_state_client_input_combined[combined_index] = counter_str[i];
    combined_index++;
  }
  int len_combined = combined_index;

  // get the hash of the input data
  unsigned char hashbuf_verify[32];
  if((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)enclave_state_client_input_combined, len_combined, hashbuf_verify)) != 0) {
      print("\nTrustedApp: mbedtls_md returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  // load the public key into an mbedtls_pk_context
  mbedtls_pk_context pk_pub_key;
  mbedtls_pk_init( &pk_pub_key );

  if((ret = mbedtls_pk_parse_public_key(&pk_pub_key, (const unsigned char *)public_key_buffer, strlen(public_key_buffer)+1)) != 0) {
    print("\nTrustedApp: mbedtls_pk_parse_public_key returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  
  mbedtls_rsa_context *rsapk_pub_key = mbedtls_pk_rsa( pk_pub_key );

  if((ret = mbedtls_rsa_check_pubkey(rsapk_pub_key)) != 0) {
    print("\nTrustedApp: mbedtls_rsa_check_pubkey returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  // verify that the hash of the input data corresponds to the input signature
  if((ret = mbedtls_rsa_pkcs1_verify(rsapk_pub_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 64, hashbuf_verify, signature)) != 0) {
    print("\nTrustedApp: mbedtls_rsa_pkcs1_verify returned an error!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  ret = SGX_SUCCESS;
  return ret;
}


/**
 * This function verifies that an encrypted enclave state and encrypted client input (command) corresponds to some signature 
 *
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenInEnclaveState            length of encrypted enclave state buffer
 * @param cli_in                       encrypted client input (command)
 * @param lenInCliIn                   length of encrypted client input (command)
 * @param public_key_buffer            public key buffer to verify signature
 * @param signature                    signature buffer (should be the signed encrypted enclave state + client input)
 * @param result                       result buffer. first entry will be 0 if the verification is successful and non-0 otherwise
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_verify_enclave_state_and_command_signature(uint8_t enclave_state_in[BUFLEN], size_t lenInEnclaveState, uint8_t cli_in[BUFLEN], size_t lenInCliIn, 
                                                    int counter, uint8_t public_key_buffer[BUFLEN], uint8_t signature[BUFLEN], uint8_t result[BUFLEN]) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // convert the counter integer to string
  int num_digits = 0;
  int counter_temp = counter;
  while (counter_temp > 0) {
    counter_temp /= 10;
    num_digits++;
  }
  char counter_str[BUFLEN] = {0};
  counter_temp = counter;
  counter_str[num_digits] = 0;
  for (int j = num_digits - 1; j >= 0; --j, counter_temp /= 10) {
      counter_str[j] = (counter_temp % 10) + '0';
  }
  
  // combine the enclave state data and client input (command) data into one array
  uint8_t enclave_state_client_input_combined[BUFLEN] = {0};
  int combined_index = 0;
  for (int i = 0; i < lenInEnclaveState; i++) {
    enclave_state_client_input_combined[combined_index] = enclave_state_in[i];
    combined_index++;
  }
  for (int i = 0; i < lenInCliIn; i++) {
    enclave_state_client_input_combined[combined_index] = cli_in[i];
    combined_index++;
  }
  for (int i = 0; i < strlen(counter_str); i++) {
    enclave_state_client_input_combined[combined_index] = counter_str[i];
    combined_index++;
  }
  
  int len_combined = combined_index;


  // set up the sgx sha-256 handle and hash the combined array
  if ((ret = sgx_ecdsa_verify((uint8_t *)enclave_state_client_input_combined, len_combined, 
                            pub_key_hardcoded, (sgx_ec256_signature_t *)signature, result, p_ecc_handle) != SGX_SUCCESS)) {
    print("\nTrustedApp: sgx_ecdsa_verify() failed !\n");
    goto cleanup;
  }

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function combines an encrypted enclave state and encrypted client input (command) and signs the data using ECDSA 
 *
 * @param enclave_state_in             encrypted enclave state buffer
 * @param lenInEnclaveState            length of encrypted enclave state buffer
 * @param cli_in                       encrypted client input (command)
 * @param lenInCliIn                   length of encrypted client input (command)
 * @param private_key_buffer           private key buffer to sign the data
 * @param signature                    output signature buffer
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_sign_enclave_state_and_command(uint8_t enclave_state_in[BUFLEN], size_t lenInEnclaveState, uint8_t cli_in[BUFLEN], size_t lenInCliIn, 
                                                    int counter, uint8_t private_key_buffer[BUFLEN], uint8_t signature[BUFLEN]) {
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // convert the counter integer to string
  int num_digits = 0;
  int counter_temp = counter;
  while (counter_temp > 0) {
    counter_temp /= 10;
    num_digits++;
  }
  char counter_str[BUFLEN] = {0};
  counter_temp = counter;
  counter_str[num_digits] = 0;
  for (int j = num_digits - 1; j >= 0; --j, counter_temp /= 10) {
      counter_str[j] = (counter_temp % 10) + '0';
  }
  
  // combine the enclave state data and client input (command) data into one array
  uint8_t enclave_state_client_input_combined[BUFLEN] = {0};
  int combined_index = 0;
  for (int i = 0; i < lenInEnclaveState; i++) {
    enclave_state_client_input_combined[combined_index] = enclave_state_in[i];
    combined_index++;
  }
  for (int i = 0; i < lenInCliIn; i++) {
    enclave_state_client_input_combined[combined_index] = cli_in[i];
    combined_index++;
  }
  for (int i = 0; i < strlen(counter_str); i++) {
    enclave_state_client_input_combined[combined_index] = counter_str[i];
    combined_index++;
  }
  int len_combined = combined_index;

  // set up the sgx sha-256 handle and hash the combined array
  sgx_ec256_signature_t sig;
  if ((ret = sgx_ecdsa_sign((uint8_t *)enclave_state_client_input_combined, len_combined, 
                            priv_key_hardcoded, &sig, p_ecc_handle) != SGX_SUCCESS)) {
    print("\nTrustedApp: sgx_ecdsa_sign() failed !\n");
    goto cleanup;
  }

  memcpy(signature, &sig, BUFLEN);

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function generates a public/private key pair to sign and verify ECDSA signatures
 *
 * @param pub_key_buffer               output public key buffer
 * @param priv_key_buffer              output private key buffer
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_generate_key_ecdsa(uint8_t pub_key_buffer[BUFLEN], uint8_t priv_key_buffer[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }
  if (ret = sgx_ecc256_create_key_pair((sgx_ec256_private_t *)priv_key_buffer, (sgx_ec256_public_t *)pub_key_buffer,
                                   p_ecc_handle) != SGX_SUCCESS) {
    print("\nTrustedApp: Generate ECDSA key pair failed !\n");
    goto cleanup;
  }
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  // free(enclave_state_str);
  // cJSON_Delete(enclave_state);
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

