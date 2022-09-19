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

#define AES_128_KEY_SIZE 16
#define SGX_AESGCM_MAC_SIZE 16
#define SGX_AESGCM_IV_SIZE 12
#define BUFLEN 2048

/**
 * This function encrypts a message using Rijndael (AES) encryption for the VSC application.
 *
 * @param aes_key             Encryption key
 * @param len_key             length in bits of encryption key
 * @param decMessageIn        message string to be encrypted
 * @param lenIn               length of decMessageIn in bytes
 * @param encMessageOut       pointer to encrypted message
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_encrypt_aes(uint8_t aes_key[AES_128_KEY_SIZE], char decMessageIn[BUFLEN], size_t lenIn, char encMessageOut[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

        printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
        print_hexstring(aes_key, AES_128_KEY_SIZE);
        printf("\n%d\n", AES_128_KEY_SIZE);
        printf("%d %d %s", lenIn, strlen(decMessageIn), decMessageIn);

  size_t lenOutExpected = SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + lenIn;
  if (lenOutExpected >= BUFLEN) {
    print("\nTrustedApp: Decrypted message is too large! !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  // unsigned long x = *((unsigned long*)p_ecc_handle);
  uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

  if (AES_128_KEY_SIZE == 16) {
    sgx_rijndael128GCM_encrypt(
      (sgx_aes_gcm_128bit_key_t *) aes_key, // key
      origMessage, lenIn, // message pointer, length of message
      p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, // destination
      p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE, // iv pointer, iv length
      NULL, 0, // aad pointer, aad length
      (sgx_aes_gcm_128bit_tag_t *) (p_dst) // pointer to MAC information
    );
    memcpy(encMessageOut, p_dst, lenOutExpected);
    print("\nTrustedApp: Successfully encrypted message!\n");

  } else {
    print("\nTrustedApp: Key length (len_key) not valid! !\n");
  }

  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }
  return ret;
}

/**
 * This function encrypts a message using Rijndael (AES) encryption for the VSC application.
 *
 * @param aes_key             Encryption key
 * @param len_key             length in bits of encryption key
 * @param decMessageIn        message string to be encrypted
 * @param lenIn               length of decMessageIn in bytes
 * @param encMessageOut       pointer to encrypted message
 * 
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_decrypt_aes(uint8_t aes_key[AES_128_KEY_SIZE], char encMessageIn[BUFLEN], size_t lenIn, char decMessageOut[BUFLEN]) {
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle = NULL;

  size_t lenOutExpected = lenIn - SGX_AESGCM_MAC_SIZE - SGX_AESGCM_IV_SIZE;
  if (lenOutExpected >= BUFLEN || lenOutExpected < 0) {
    print("\nTrustedApp: Decrypted message is too large or too small!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  if ((ret = sgx_ecc256_open_context(&p_ecc_handle)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

  if (AES_128_KEY_SIZE == 16) {
    sgx_status_t decrypt_status = sgx_rijndael128GCM_decrypt(
      (sgx_aes_gcm_128bit_key_t *) aes_key, // encryption key
      encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE, // pointer to message
      lenOutExpected, // length of message
      p_dst, // pointer to output
      encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE, // pointer to iv and iv size
      NULL, 0, // pointer to aad and aad length
      (sgx_aes_gcm_128bit_tag_t *) encMessage // pointer to encrypted message
    );

    // print decrypt_status
    if (decrypt_status != 0) {
      char a = decrypt_status % 16;
      a += (a >= 10) ? 'a' - 10 : '0';
      char b = (decrypt_status / 16) % 16;
      b += (b >= 10) ? 'a' - 10 : '0';
      char c = (decrypt_status / 256) % 16;
      c += (c >= 10) ? 'a' - 10 : '0';
      char d = (decrypt_status / 4096) % 16;
      d += (d >= 10) ? 'a' - 10 : '0';
      char buff[5] = {d, c, b, a, ' ', 0};
      print("\nTrusted App: Decryption status error \n");
      print(buff);
      print("\n");
      ret = SGX_ERROR_UNEXPECTED;
      goto cleanup;
    } else {
      memcpy(decMessageOut, p_dst, lenOutExpected);
      print("\nTrustedApp: Successfully decrypted message!\n");
    }
  } else {
    print("\nTrustedApp: Key length (len_key) not valid! !\n");
    ret = SGX_ERROR_UNEXPECTED;
    goto cleanup;
  }
  
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle != NULL) {
    sgx_ecc256_close_context(p_ecc_handle);
  }

  return ret;
}
