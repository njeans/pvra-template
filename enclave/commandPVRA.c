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

#define BUFLEN 2048
#define KEY_SIZE 2048
#define MBED_TLS_KEY_SIZE 2049
#define EXPONENT 65537

#define AESGCM_128_KEY_SIZE 16
#define AESGCM_128_MAC_SIZE 16
#define AESGCM_128_IV_SIZE 12
#define EXPECTEDINPUT 16



sgx_status_t ecall_commandPVRA(
      char *sealedstate, size_t sealedstate_size, 
      char *signedFT, size_t signedFT_size, 
      char *eCMD, size_t eCMD_size, 
      char *eAESkey, size_t eAESkey_size, 
      char *cResponse, size_t cResponse_size) {


  sgx_status_t ret = SGX_ERROR_UNEXPECTED;



  /*   (2) ENCLAVE STATE INIT    */
  // Step 1: Calculate sealed/encrypted data length.
  uint32_t unsealed_data_size =
      sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealedstate);
  uint8_t *const unsealed_data =
      (uint8_t *)malloc(unsealed_data_size); 
  // Check malloc return;
  if (unsealed_data == NULL) {
    print("\n[ecPVRA]: malloc(unsealed_data_size) failed !\n");
    return ret;
  }

  // Step 2: Unseal data.
  if ((ret = sgx_unseal_data((sgx_sealed_data_t *)sealedstate, NULL, NULL,
                             unsealed_data, &unsealed_data_size)) !=
      SGX_SUCCESS) {
    print("\n[ecPVRA]: sgx_unseal_data() failed !\n");
    return ret;
  }

  struct ES *enclave_state;
  enclave_state = malloc(sizeof(struct ES));
  memcpy(enclave_state, unsealed_data, sizeof(struct ES));
  //print_hexstring(&enclave_state->enclavekeys.encrypt_pubkey, sizeof(sgx_ec256_public_t));




  /*   (3) SIGNEDFT VERIFICATION    */
  const char* b64pub = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQXRsS1RW\nN09kU2EzK3hIQndCKzhhTm9TdkZESC9qdUVMQjFWOU9kWFZZQVlhQ0NsaEJOSncK\nbkF2NEJQRUdUTmU4MHBwNEpBSE9JdUk1aURJUW1QOGgrTzhZTzVMVEttaEhhV3Nj\nbWU4TTJoNk8wbit4U3l4bwpzbUsyTk43Y3NBRzBja0Y0MTBmVHN5cS80TU4rRURH\nYTBoVU04SHlEMWZGVWUraStGSGJ6RVVmT09mRkxLaHdPCjhtVUowTTBFMmRRMFhh\nRFUyRHJDZ0lBWklFS044Q3RkeVBhcHIwTHhqNTVzRmVpRkt2T2RhanlnbGtvbmtl\nV2oKVHRCczBqcFlpMzhRVUJZK1gwSEdYVld2Z29tTyttRzJCZG1rZTZHTnpNYmRP\nQTFiRExFVlpUZ21EWUZUTmgvbApCYXViRzFlZ1h5eDNkQ1NuVk44VFl4cnVuN0Rt\nVFNndXJRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K\n";







  /*   (4) COMMAND DECRYPTION    */

  const char *pers = "rsa_genkey";
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  mbedtls_pk_init(&pk);
  
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
  if(ret != 0)
  {
    printf("[ecPVRA]: mbedtls_pk_parse_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  
  ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)&enclave_state->enclavekeys.priv_key_buffer, strlen(&enclave_state->enclavekeys.priv_key_buffer)+1, 0, 0);
  if(ret != 0)
  {
    printf("[ecPVRA]: mbedtls_pk_parse_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  /*
  mbedtls_rsa_context *rsapk = mbedtls_pk_rsa(pk);

  ret = mbedtls_rsa_check_privkey(rsapk);
  if(ret != 0)
  {
    printf("[ecPVRA]: mbedtls_rsa_check_privkey failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  */


  /* RSA Encryption Example */
  /*
  unsigned char *to_encrypt = "mykey";
  int to_encrypt_len = strlen(to_encrypt);
  unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
  size_t olen = 0;
  ret = mbedtls_pk_encrypt( &pk, to_encrypt, to_encrypt_len,
                                    buf, &olen, sizeof(buf),
                                    mbedtls_ctr_drbg_random, &ctr_drbg );
  if(ret != 0)
  {
    printf("[ecPVRA]: mbedtls_pk_encrypt failed, returned -0x%04x\n", -ret); 
  } 

  printf("[ecPVRA]: RSA_Encrypt: ");
  print_hexstring(buf, olen);
  */



  /* RSA Decryption of AESkey using enclave private encryption key */
  unsigned char AESkey[MBEDTLS_MPI_MAX_SIZE];
  size_t AESkey_len = 0;

  ret = mbedtls_pk_decrypt(&pk, eAESkey, eAESkey_size, AESkey, &AESkey_len, sizeof(AESkey), mbedtls_ctr_drbg_random, &ctr_drbg);
  if(ret != 0)
  {
    printf("[ecPVRA]: mbedtls_pk_parse_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  printf("[ecPVRA]: Decrypted eAESkey: "); 
  print_hexstring(AESkey, AESkey_len);





  uint8_t tag_dst[BUFLEN] = {0};
  uint8_t cipher_dst[BUFLEN] = {0};

  char *pt = "{user_data}";
  size_t pt_len = strlen(pt);
  size_t ct_len = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + pt_len;
  //ct_len check

  static const unsigned char plaintext[] = {
    0x7B,0x75,0x73,0x65,
    0x72,0x5F,0x64,0x61,
    0x74,0x61,0x7D,0x00,
    0x00,0x00,0x00,0x00
  };

  //https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes
  unsigned char aes128GCM_iv[AESGCM_128_IV_SIZE] = { 
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
  };

  static const unsigned char aes128GCM_key[AESGCM_128_KEY_SIZE] = {
    0x57,0x4b,0x73,0x58,
    0x04,0xac,0x02,0xfb,
    0xc6,0xf3,0x5c,0x71,
    0x7a,0x62,0x95,0x8d
  };

  //sgx_read_rand(aes128GCM_iv, AESGCM_128_IV_SIZE);

  sgx_status_t encrypt_status = sgx_rijndael128GCM_encrypt(
    (sgx_aes_gcm_128bit_key_t *) AESkey,
    (const uint8_t *) pt, (uint32_t) pt_len,                        
    (uint8_t *) cipher_dst,
    (const uint8_t *) aes128GCM_iv, (uint32_t) SGX_AESGCM_IV_SIZE,
    (const uint8_t *) NULL, (uint32_t) 0,
    (sgx_aes_gcm_128bit_tag_t *) tag_dst
  );

  if(encrypt_status) {
    printf("[ecPVRA]: Failed to Encrypt Command\n");
  }

  /*
  printf("ENCRYPTED COMMAND\n[TAG]   ");
  print_hexstring(tag_dst, AESGCM_128_MAC_SIZE);
  printf("[IV]    ");
  print_hexstring(aes128GCM_iv, AESGCM_128_IV_SIZE);
  printf("[CT]    ");
  print_hexstring(cipher_dst, pt_len);
  */


  /*
  uint8_t eCMD_full[BUFLEN] = {0};

  memcpy(eCMD_full, tag_dst, AESGCM_128_MAC_SIZE);
  memcpy(eCMD_full + AESGCM_128_MAC_SIZE, aes128GCM_iv, AESGCM_128_IV_SIZE);
  memcpy(eCMD_full + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE, cipher_dst, pt_len);
  printf("[FULL]  ");
  print_hexstring(eCMD_full, ct_len);
  */
  uint8_t *eCMD_full = eCMD;


  uint8_t plain_dst[BUFLEN] = {0};
  size_t ct_src_len = ct_len - AESGCM_128_MAC_SIZE - AESGCM_128_IV_SIZE;
  //dpt_len check

  uint8_t *ct_src = &eCMD_full[AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE];
  uint8_t *iv_src = &eCMD_full[AESGCM_128_MAC_SIZE];
  uint8_t *tag_src = eCMD_full;

  sgx_status_t decrypt_status = sgx_rijndael128GCM_decrypt(
    (sgx_aes_gcm_128bit_key_t *) AESkey,
    (const uint8_t *) ct_src, (uint32_t) ct_src_len,
    (uint8_t *) plain_dst,
    (const uint8_t *) iv_src, (uint32_t) SGX_AESGCM_IV_SIZE,
    NULL, 0,
    (sgx_aes_gcm_128bit_tag_t *) tag_src
  );

  if(decrypt_status) {
    printf("[ecPVRA]: Failed to Decrypt Command\n");
  }

  printf("[ecPVRA]: Decrypted eCMD: %s\n", plain_dst);








  /*   (5) SEQNO VERIFICATION    */


  /*   (6) PROCESS COMMAND    */



  /*   (7) FT UPDATE    */



  /*   (8) SIGN CRESPONSE   */




  /*   (9) SEAL STATE    */



  ret = SGX_SUCCESS;

/*
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
*/

  //ocallrdtsc();
  ret = SGX_SUCCESS;


  cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);
    return ret;
}
