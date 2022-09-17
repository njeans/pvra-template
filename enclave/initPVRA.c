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

/**
 * This function generates a key pair and then seals the private key.
 *
 * @param pubkey                 Output parameter for public key.
 * @param pubkey_size            Input parameter for size of public key.
 * @param sealedprivkey          Output parameter for sealed private key.
 * @param sealedprivkey_size     Input parameter for size of sealed private key.
 *
 * @return                       SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */

sgx_status_t ecall_initPVRA(sgx_report_t *report, sgx_target_info_t *target_info, char *sealedstate, size_t sealedstate_size, char *enckey_signature, size_t signature_size, char *pub_enckey, size_t enckey_size) {
  

  struct ES enclave_state;

  ocallrdtsc();
  

  // Generate Enclave Encryption Key
  // Step 1: Open Context.
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle_e = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle_e)) != SGX_SUCCESS) {
    print("\n[[TrustedApp]][initPVRA]: sgx_ecc256_open_context() failed encryptkey!\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private_e;
  sgx_ec256_public_t p_public_e;
  if ((ret = sgx_ecc256_create_key_pair(&p_private_e, &p_public_e, p_ecc_handle_e)) !=
      SGX_SUCCESS) {
    print("\n[[TrustedApp]][initPVRA]: sgx_ecc256_create_key_pair() failed encryptkey!\n");
    goto cleanup;
  }

  enclave_state.enclavekeys.encrypt_prikey = p_private_e;
  enclave_state.enclavekeys.encrypt_pubkey = p_public_e;

  printf("GOTHERE :D!\n");

  // Generate Enclave Signing Key
  // Step 1: Open Context.
  ret = SGX_ERROR_UNEXPECTED;
  sgx_ecc_state_handle_t p_ecc_handle_s = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle_s)) != SGX_SUCCESS) {
    print("\n[[TrustedApp]][initPVRA]: sgx_ecc256_open_context() failed signingkey!\n");
    goto cleanup;
  }

  // Step 2: Create Key Pair.
  sgx_ec256_private_t p_private_s;
  sgx_ec256_public_t p_public_s;
  if ((ret = sgx_ecc256_create_key_pair(&p_private_s, &p_public_s, p_ecc_handle_s)) !=
      SGX_SUCCESS) {
    print("\n[[TrustedApp]][initPVRA]: sgx_ecc256_create_key_pair() failed signingkey!\n");
    goto cleanup;
  }

  // Hardcoded Signing Key
  static const sgx_ec256_public_t hpub_key = {
      {
          0x31, 0x35, 0xb2, 0x8a, 0x4b, 0x32, 0x52, 0x21,
          0x8c, 0x78, 0x03, 0xf5, 0x6b, 0x9a, 0xdf, 0x31,
          0xf8, 0xfa, 0x51, 0xbe, 0xab, 0xb6, 0xe1, 0xe0,
          0x36, 0xdf, 0x94, 0x16, 0x30, 0x4b, 0x56, 0x0f,
      },
      {
          0xb9, 0x55, 0xce, 0x98, 0xd7, 0xb5, 0xc4, 0x8a,
          0xf7, 0x98, 0xb5, 0xb0, 0x47, 0xca, 0xbd, 0x25,
          0xbb, 0x83, 0x72, 0x8c, 0x2c, 0x85, 0xbb, 0x10,
          0x11, 0xaf, 0x90, 0x3e, 0xf3, 0x2a, 0x27, 0x56
      }

  };

  static const sgx_ec256_private_t hpri_key = {
      {
          0x55, 0xa8, 0x76, 0x30, 0xd8, 0xb9, 0x24, 0xcd,
          0xec, 0xe5, 0x4e, 0xe0, 0x2e, 0x9e, 0x42, 0xdb,
          0x8b, 0x4f, 0x5c, 0x0b, 0xbd, 0xc7, 0xda, 0xdd,
          0xf2, 0xbc, 0xa2, 0x89, 0x1e, 0xcf, 0x6e, 0x5c
      }

  };

  //enclave_state.enclavekeys.sign_prikey = p_private_s;
  //enclave_state.enclavekeys.sign_pubkey = p_public_s;

  enclave_state.enclavekeys.sign_prikey = hpri_key;
  enclave_state.enclavekeys.sign_pubkey = hpub_key;


  // Sign Encryption Key + Publish

  // Step 4: Perform ECDSA Signing.
  
  sgx_ecc_state_handle_t p_ecc_handle_sign = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle_sign)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }

  if ((ret = sgx_ecdsa_sign(&p_public_e, sizeof(p_public_e), &hpri_key, (sgx_ec256_signature_t *)enckey_signature, p_ecc_handle_sign)) != SGX_SUCCESS) {
    printf("\n[Enclave]: sgx_ecdsa_sign() failed !\n");
  }

  printf("%p %p %d %d\n", pub_enckey, &p_public_e, sizeof(p_public_e),  signature_size);
  
  memcpy(pub_enckey, &p_public_e, sizeof(p_public_e));
  print_hexstring(&p_public_e, sizeof(p_public_e));
  print_hexstring(&hpub_key, sizeof(hpub_key));



  // Initialize Application Data
  enclave_state.appdata.i = 42;



  // Initialize Freshness Tag and CCF Key
  for (int i = 0; i < 64; i++) {
    enclave_state.counter.freshness_tag[i] = 0;
  }
  const char CCF_key = "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAs1l0PEtgQRtk5mkclhMFTtkLGWUG/11ZiMG+wA7FCIljrs0u6rzT\n8XSILc0Gr7JEAQO+2r8r23HQnqQMRrAL8TnTHXWrClat7SFoOQlIQ3Oy0C2sxmk+\nKFhKFZy9fxCVcy4H+Qu6OF4HY6Aym08/oPBhIEnw7W29eH7VrkCrRDa9MwYZibD1\nyz8GM7OwrltU5wWt8GL0SMcMRe0rAfziwS+8u+rGFGVrPZ8f2ZhZrq0bfCIWdtp6\n58K1LqKomLayIDowy+9Lk79nI17xV7YnJammzZgSaNQXy+Az9c1rszT7RHK4rhUN\n0J8IDxuZVpzWjIEJQXY92yZQ0x7loNq8uwIDAQAB\n-----END RSA PUBLIC KEY-----\n";
  // Either fixed or assign here.




  // Initialize Anti Replay
  for (int i = 0; i < 10; i++) {
    enclave_state.antireplay.seqno[i] = 0;
  }


  // Generate Quote
  sgx_report_data_t report_data = {{0}};

  printf("[Enclave][initPVRA]: sig_pub: ");
  print_hexstring(&hpub_key, sizeof(hpub_key));
  printf("[Enclave][initPVRA]: sig_pri: ");
  print_hexstring(&hpri_key, sizeof(hpri_key));

  memcpy((uint8_t *const) &report_data, (uint8_t *)&hpub_key, sizeof(hpub_key));
  //memcpy((uint8_t *const) (&report_data + sizeof(p_public_s)), (uint8_t *)&p_public_e, sizeof(p_public_e));

  // BEGIN WIP --------------------------------------------
  print("[[TrustedApp]][initPVRA]: Calling enclave to generate attestation report\n");
  ret = sgx_create_report(target_info, &report_data, report);
  // --------------------------------------------- END WIP
  print("\n[[TrustedApp]][initPVRA]: Unsealed the sealed public key and created a report containing the public key in the report data.\n");


  // Seal Enclave State
  printf("sealedstate_size: %d\n", sgx_calc_sealed_data_size(0U, sizeof(enclave_state)));
  if (sealedstate_size >= sgx_calc_sealed_data_size(0U, sizeof(enclave_state))) {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(enclave_state), (uint8_t *)&enclave_state,
                             (uint32_t)sealedstate_size,
                             (sgx_sealed_data_t *)sealedstate)) !=
        SGX_SUCCESS) {
      print("\n[[TrustedApp]][initPVRA]: sgx_seal_data() failed !\n");
      goto cleanup;
    }
  } else {
    print("\n[[TrustedApp]][initPVRA]: Size allocated for sealedprivkey by untrusted app "
          "is less than the required size !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  print("\n[[TrustedApp]][initPVRA]: Enclave State initialized and sealed, quote generated.\n");
  ret = SGX_SUCCESS;

cleanup:
  // Step 4: Close Context.
  if (p_ecc_handle_e != NULL) {
    sgx_ecc256_close_context(p_ecc_handle_e);
  }
    printf("GOTHERE :D!\n");
  if (p_ecc_handle_s != NULL) {
    sgx_ecc256_close_context(p_ecc_handle_s);
  }
    printf("GOTHERE :D!\n");
  if (p_ecc_handle_sign != NULL) {
    sgx_ecc256_close_context(p_ecc_handle_sign);
  }  printf("GOTHERE :D!\n");

  ocallrdtsc();
    printf("GOTHERE :D!\n");
  return ret;
}
