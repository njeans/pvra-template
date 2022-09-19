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



int cmd0(struct ES *enclave_state)
{
  enclave_state->appdata.i = 10;
  printf("[ecPVRA]: Ran CMD0 appdata set to %d\n", enclave_state->appdata.i);
  return 1;
}

int cmd1(struct ES *enclave_state)
{
  enclave_state->appdata.i = 20;
  printf("[ecPVRA]: Ran CMD1 appdata set to %d\n", enclave_state->appdata.i);
  return 2;
}



sgx_status_t ecall_commandPVRA(
      char *sealedstate, size_t sealedstate_size, 
      char *signedFT, size_t signedFT_size, 
      char *eCMD, size_t eCMD_size, 
      char *eAESkey, size_t eAESkey_size, 
      char *cResponse, size_t cResponse_size,
      char *cResponse_signature, size_t cResponse_signature_size,
      char *sealedout, size_t sealedout_size) {


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

  struct ES enclave_state;
  memcpy(&enclave_state, unsealed_data, sizeof(struct ES));
  //print_hexstring(&enclave_state.enclavekeys.encrypt_pubkey, sizeof(sgx_ec256_public_t));




  /*   (3) SIGNEDFT VERIFICATION    */

/* RSA Signature Example */

/*
  mbedtls_pk_context pks;    
  mbedtls_rsa_context rsas;

  mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
  unsigned char hashbuf[32];
  char *msg = "hello";
  unsigned char dmsg[32] = {
    0xfc,0x85,0x75,0x32,0xb5,0x57,0x96,0xa4,
    0x6a,0xac,0xe6,0xa5,0x3c,0x33,0x92,0x76,
    0x3b,0x7b,0xe4,0xa4,0x3f,0x05,0x52,0x68,
    0x88,0xda,0x5a,0x57,0x43,0x8b,0x12,0x0e
  };
  unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
  uint8_t sigbuf[MBEDTLS_MPI_MAX_SIZE];
  
  mbedtls_rsa_init( &rsas, MBEDTLS_RSA_PKCS_V15, 0 );
  mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
  mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
  mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );
  mbedtls_pk_init(&pks);
  
  if((ret = mbedtls_pk_parse_key(&pks, (const unsigned char *)&enclave_state.enclavekeys.priv_key_buffer, strlen(&enclave_state.enclavekeys.priv_key_buffer)+1, 0, 0)) != 0) {
      print("\nTrustedApp: mbedtls_pk_parse_key returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  mbedtls_rsa_context *rsapk = mbedtls_pk_rsa( pks );
      
  if((ret = mbedtls_rsa_check_privkey(rsapk)) != 0) {
      print("\nTrustedApp: mbedtls_rsa_check_privkey returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  if((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)msg, 5, hashbuf)) != 0) {

      print("\nTrustedApp: mbedtls_md returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }


  if((ret = mbedtls_rsa_pkcs1_sign(rsapk, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 64, hashbuf, sigbuf)) != 0) {
      print("\nTrustedApp: mbedtls_rsa_pkcs1_sign returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  print_hexstring(sigbuf, sizeof(sigbuf));
  */


  uint8_t hsignature[MBEDTLS_MPI_MAX_SIZE] = {
    0x38,0x3c,0x66,0x10,0x0b,0x48,0x40,0xab,0x94,0xa9,0x4f,0x97,0x1a,0x5f,0x86,0x39,
    0x34,0x2c,0x17,0x0f,0xe9,0x52,0xfa,0x47,0x96,0x1e,0xb9,0x3f,0x7d,0xba,0xbf,0x51,
    0x77,0xb8,0xd9,0xa4,0x21,0x8a,0x26,0x4f,0x30,0xfb,0x6c,0x9b,0x6a,0xf6,0x3b,0xff,
    0xda,0xb1,0x41,0x80,0x97,0x1b,0xf1,0x61,0x99,0x3c,0x32,0x48,0x23,0x62,0x6a,0xe4,
    0x7c,0xc8,0x68,0x3f,0xc4,0x0e,0xe3,0xf2,0x76,0x27,0x62,0x43,0x67,0xfd,0x1c,0x32,
    0x76,0xf1,0x3a,0xb5,0x57,0x6e,0xf9,0xba,0x2d,0xe3,0xf7,0xcb,0x4f,0xa9,0x37,0x8c,
    0xd3,0x0b,0x32,0x97,0x3d,0x36,0x8d,0xac,0xd1,0x3c,0x2b,0x86,0x37,0xa6,0xd9,0xe7,
    0x34,0xfa,0x48,0xb3,0xe6,0x9b,0x42,0x4c,0xad,0x25,0x20,0xa9,0xfb,0xf8,0x3d,0x7b,
    0xf2,0x15,0xa7,0xd2,0xaf,0x6c,0x51,0xb6,0x57,0x67,0xac,0x63,0x04,0xaa,0xac,0xc0,
    0xaf,0xbc,0x1f,0x4f,0xe2,0x89,0xf3,0x7c,0x97,0x28,0x4a,0xe8,0xee,0xbb,0xa1,0x4c,
    0x16,0xa8,0x2d,0xdf,0x7d,0xe3,0x75,0xf0,0x6d,0x03,0x50,0xb2,0xcb,0x3a,0xb6,0x8a,
    0x46,0x03,0x0d,0x1b,0xa2,0x8f,0x9f,0xb9,0x04,0x8a,0x9c,0xe7,0x5d,0xc7,0xa5,0x8f,
    0x42,0x7f,0x77,0x6e,0x1d,0xa1,0x42,0x2e,0xb5,0xd6,0x7f,0x4a,0xe9,0xc6,0xf9,0x17,
    0x65,0x7d,0x38,0xa3,0x9a,0x41,0xd7,0x65,0x05,0x18,0x37,0x36,0xf2,0x5f,0x10,0x9e,
    0x77,0x8b,0x31,0x69,0x27,0x6f,0x27,0xda,0x7d,0x50,0x1b,0xe9,0xa2,0xfc,0x2c,0x2d,
    0x74,0x0a,0xfb,0x46,0x37,0x3c,0xd3,0x1e,0x02,0xc2,0x3f,0xe4,0xb4,0x9d,0xff,0x73
  };

  //print_hexstring(signature, sizeof(signature));
  char *msg = "hello"; 
  // msg = Hash( enclave_state.counter.freshness_tag || Hash(sealedstate || eCMD))

  unsigned char msg_hash[32];

  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)msg, strlen(msg), msg_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA]: mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  mbedtls_pk_context pk_pub_key;
  mbedtls_pk_init(&pk_pub_key);

  ret = mbedtls_pk_parse_public_key(&pk_pub_key, (const unsigned char *)&enclave_state.counter.CCF_key, strlen(&enclave_state.counter.CCF_key)+1);
  if(ret != 0) 
  {
    printf("[ecPVRA]: mbedtls_pk_parse_public_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  
  mbedtls_rsa_context *rsapk_pub_key = mbedtls_pk_rsa(pk_pub_key);

  ret = mbedtls_rsa_check_pubkey(rsapk_pub_key);
  if(ret != 0) 
  {
    printf("[ecPVRA]: mbedtls_rsa_check_pubkey failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }

  ret = mbedtls_rsa_pkcs1_verify(rsapk_pub_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 64, msg_hash, signedFT);
  if(ret != 0) 
  {
    printf("[ecPVRA]: mbedtls_rsa_pkcs1_verify failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    return ret;
  }
  else {
    printf("[ecPVRA]: SCS signature verification success\n");
  }





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

  
  ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)&enclave_state.enclavekeys.priv_key_buffer, strlen(&enclave_state.enclavekeys.priv_key_buffer)+1, 0, 0);
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








  int cType = (plain_dst[1]-'0');
  //cInput =
  //seqNO =
  //clientID =
  //printf("CT = %d\n", cType);


  /*   (5) SEQNO VERIFICATION    */


  /*   (6) PROCESS COMMAND    */

  int cRet = 0;

  switch(cType) {
    case 0:
      cRet = cmd0(&enclave_state);
      break;
    case 1:
      cRet = cmd1(&enclave_state);
      break;
    default:
      break;
  }

  char cResponse_raw = '0' + cRet;

  /*   (7) FT UPDATE    */
  //memcpy(&enclave_state.counter.freshness_tag, msg, strlen(msg));


  /*   (8) SIGN CRESPONSE   */
  // Sign Encryption Key + Publish
  sgx_ecc_state_handle_t p_ecc_handle_sign = NULL;
  if ((ret = sgx_ecc256_open_context(&p_ecc_handle_sign)) != SGX_SUCCESS) {
    print("\nTrustedApp: sgx_ecc256_open_context() failed !\n");
    goto cleanup;
  }


  memcpy(cResponse, &cResponse_raw, 1);

  if ((ret = sgx_ecdsa_sign(&cResponse_raw, 1, &enclave_state.enclavekeys.sign_prikey, (sgx_ec256_signature_t *)cResponse_signature, p_ecc_handle_sign)) != SGX_SUCCESS) {
    printf("\n[Enclave]: sgx_ecdsa_sign() failed !\n");
  }





  /*   (9) SEAL STATE    */
  printf("[ecPVRA]: sealedstate_size: %d\n", sgx_calc_sealed_data_size(0U, sizeof(enclave_state)));
  if (sealedout_size >= sgx_calc_sealed_data_size(0U, sizeof(enclave_state))) {
    if ((ret = sgx_seal_data(0U, NULL, sizeof(enclave_state), (uint8_t *)&enclave_state,
                             (uint32_t)sealedout_size,
                             (sgx_sealed_data_t *)sealedout)) !=
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

  print("[eiPVRA]: Enclave State initialized and sealed, quote generated.\n");
  ret = SGX_SUCCESS;


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
