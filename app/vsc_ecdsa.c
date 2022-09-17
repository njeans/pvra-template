/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool enclave_mbedtls_test(char  * enc_enclave_state_txt_file, char  * enc_client_input_txt_file) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("\n[GatewayApp]: Calling enclave to mbed tls test \n");

  uint8_t enc_enclave_state[2048] = {0};
  uint8_t enc_client_input_state[2048] = {0};
  size_t enc_enclave_state_size;
  size_t enc_client_input_size;
  load_text(enc_enclave_state_txt_file, enc_enclave_state, &enc_enclave_state_size);
  load_text(enc_client_input_txt_file, enc_client_input_state, &enc_client_input_size);

  /*
   * Invoke ECALL, 'ecall_mbedtls_test()'
   */
  uint8_t pub_key_buffer[2049] = {0};
  uint8_t priv_key_buffer[2049] = {0};
  uint8_t signature[1024] = {0};
  sgx_lasterr = ecall_mbed_sign_enclave_state_and_command_signature(enclave_id, &ecall_retval, enc_enclave_state, enc_enclave_state_size,
                                    enc_client_input_state, enc_client_input_size, 0, priv_key_buffer, pub_key_buffer, signature);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_mbedtls_test returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  sgx_lasterr = ecall_mbed_verify_enclave_state_and_command_signature(enclave_id, &ecall_retval, enc_enclave_state, enc_enclave_state_size,
                                    enc_client_input_state, enc_client_input_size, 0, pub_key_buffer, signature);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_mbedtls_test returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  // printf("\n MBED PUB KEY \n");
  // printf("\n MBED PUB KEY LEN %u \n", strlen(pub_key_buffer));
  // for (int i = 0 ; i < 2049; i++) {
  //   printf("%02x ", pub_key_buffer[i]);
  // }

  // printf("\n MBED PRIV KEY \n");
  // printf("\n MBED PRIV KEY LEN %u \n", strlen(priv_key_buffer));
  // for (int i = 0 ; i < 2049; i++) {
  //   printf("%02x ", priv_key_buffer[i]);
  // }

  return (sgx_lasterr == SGX_SUCCESS);
}

bool enclave_verify_enclave_state_and_command_signature(char  * enc_enclave_state_txt_file, char  * enc_client_input_txt_file, 
                                                        char * signature_file, char * pub_key_txt_file, int counter) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("\n[GatewayApp]: Calling enclave to verify \n");

  uint8_t enc_enclave_state[2048] = {0};
  uint8_t enc_client_input_state[2048] = {0};
  uint8_t signature[2048] = {0};
  uint8_t pub_key_buffer[2048] = {0};
  size_t enc_enclave_state_size;
  size_t enc_client_input_size;
  size_t signature_size;
  size_t pub_key_size;
  load_text(enc_enclave_state_txt_file, enc_enclave_state, &enc_enclave_state_size);
  load_text(enc_client_input_txt_file, enc_client_input_state, &enc_client_input_size);
  load_text(signature_file, signature, &signature_size);
  load_text(pub_key_txt_file, pub_key_buffer, &pub_key_size); 

  /*
   * Invoke ECALL, 'ecall_verify_enclave_state_and_command_signature()'
   */
  uint8_t result[2048];
  sgx_lasterr = ecall_verify_enclave_state_and_command_signature(enclave_id, &ecall_retval, enc_enclave_state, enc_enclave_state_size,
                                                    enc_client_input_state, enc_client_input_size, counter, pub_key_buffer, signature, result);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_verify_enclave_state_and_command_signature returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  /*
   * Invoke ECALL, 'ecall_get_total_counter()'
   */
  int total_counter[1] = {0};
  sgx_lasterr = ecall_get_total_counter(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, enc_enclave_state, enc_enclave_state_size, total_counter);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_get_total_counter returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  int total_counter_val = total_counter[0];
  if (total_counter_val + 1 != counter) {
    printf("[GatewayApp]: ERROR: counter mismatch \n");
    uint8_t new_enclave_state[2048];
    sgx_lasterr = ecall_enclave_state_add_counter_mismatch(enclave_id, &ecall_retval, (uint8_t *)aes_gcm_key_buffer, counter - total_counter_val, enc_enclave_state, enc_enclave_state_size, 
                                                          enc_client_input_state, enc_client_input_size, new_enclave_state);
    if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
      fprintf(stderr, "[GatewayApp]: ERROR: ecall_enclave_state_add_counter_mismatch returned %d\n",
              ecall_retval);
      sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }
    copy_to_encrypted_buffer(new_enclave_state, 2048);
  } else {
    copy_to_encrypted_buffer(enc_enclave_state, 2048);
  }

  printf("\n result \n");
  for (int i = 0; i < 100; i++) {
    printf("%u ", result[i]);
  }     
  printf("\n");

  return (sgx_lasterr == SGX_SUCCESS);
}

bool enclave_sign_enclave_state_and_command(char  * enc_enclave_state_txt_file, char  * enc_client_input_txt_file, 
                                            int counter, char * priv_key_txt_file, char * signature_out_file) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("\n[GatewayApp]: Calling enclave to sign \n");

  uint8_t enc_enclave_state[2048] = {0};
  uint8_t enc_client_input_state[2048] = {0};
  uint8_t priv_key_buffer[2048] = {0};
  size_t enc_enclave_state_size;
  size_t enc_client_input_size;
  size_t priv_key_size;
  load_text(enc_enclave_state_txt_file, enc_enclave_state, &enc_enclave_state_size);
  load_text(enc_client_input_txt_file, enc_client_input_state, &enc_client_input_size);
  load_text(priv_key_txt_file, priv_key_buffer, &priv_key_size);


  /*
   * Invoke ECALL, 'ecall_sign_enclave_state_and_command()'
   */
  uint8_t signature[2048];
  sgx_lasterr = ecall_sign_enclave_state_and_command(enclave_id, &ecall_retval, enc_enclave_state, enc_enclave_state_size,
                                                    enc_client_input_state, enc_client_input_size, counter, priv_key_buffer, signature);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_sign_enclave_state_and_command returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }

  save_text(signature, 2048, signature_out_file);

  return (sgx_lasterr == SGX_SUCCESS);
}

bool enclave_generate_key_ecdsa(uint8_t * pub_key_out_file, uint8_t * priv_key_out_file) {
  sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

  printf("\n[GatewayApp]: Calling enclave to generate key data\n");

  uint8_t pub_key_buffer[2048] = {0};
  uint8_t priv_key_buffer[2048] = {0};

  /*
   * Invoke ECALL, 'ecall_generate_key_ecdsa()', to generate a key
   */
   
     clock_t t;
   t = clock();
   
  sgx_lasterr = ecall_generate_key_ecdsa(enclave_id, &ecall_retval, pub_key_buffer, priv_key_buffer);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != SGX_SUCCESS)) {
    fprintf(stderr, "[GatewayApp]: ERROR: ecall_generate_key_ecdsa returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  

  save_text(pub_key_buffer, 64, pub_key_out_file);
  save_text(priv_key_buffer, 32, priv_key_out_file);
  
       t = clock() - t;
   double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
   printf("THIS program took %f seconds to execute", time_taken);


  return (sgx_lasterr == SGX_SUCCESS);
}
