/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdarg.h>
#include <stdio.h>

#include "enclavestate.h"
#include "appPVRA.h"

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
    char *FT, size_t FT_size,
    char *eCMD, size_t eCMD_size, 
    char *eAESkey, size_t eAESkey_size, 
    char *cResponse, size_t cResponse_size,
    char *cResponse_signature, size_t cResponse_signature_size,
    char *sealedout, size_t sealedout_size) {


  sgx_status_t ret = SGX_ERROR_UNEXPECTED;



  /*   (2) ENCLAVE STATE INIT    */


  // Unseal Enclave State
  uint32_t unsealed_data_size = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealedstate);
  uint8_t *const unsealed_data = (uint8_t *)malloc(unsealed_data_size); 
  if (unsealed_data == NULL) {
    print("[ecPVRA] malloc(unsealed_data_size) failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  ret = sgx_unseal_data((sgx_sealed_data_t *)sealedstate, NULL, NULL, unsealed_data, &unsealed_data_size);
  if (ret != SGX_SUCCESS) {
    print("[ecPVRA] sgx_unseal_data() failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  // Load unsealed blob into struct
  struct ES enclave_state;
  memcpy(&enclave_state, unsealed_data, sizeof(struct ES));



  /*   (3) SIGNEDFT VERIFICATION    */


  /* RSA Signature Example *//*
  mbedtls_pk_context pks;    
  mbedtls_rsa_context rsas;

  mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
  unsigned char hashbuf[32];
  char msg[128] = "0000000000000000000000000000000000000000000000000000000000000000a547891be9ed742869b0cdac2644c0ba676ec14da845fb8ab072eea7bc221ca0";
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

  if((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)msg, 128, hashbuf)) != 0) {

      print("\nTrustedApp: mbedtls_md returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }


    printf("[ecPVRA] hashbuf = ");
  print_hexstring(hashbuf, 32);

  //insert extra
  unsigned char ex_hexstring[65];
  const char *hex = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    ex_hexstring[2*i+1] = hex[hashbuf[i] & 0xF];
    ex_hexstring[2*i] = hex[(hashbuf[i]>>4) & 0xF];
  }
  ex_hexstring[64] = 0;

  printf("STRING: %s\n", ex_hexstring);

  unsigned char final_hash[32];

  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)ex_hexstring, 64, final_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }


  printf("[ecPVRA] finalHash = ");
  print_hexstring(final_hash, 32);






  if((ret = mbedtls_rsa_pkcs1_sign(rsapk, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 64, final_hash, sigbuf)) != 0) {
      print("\nTrustedApp: mbedtls_rsa_pkcs1_sign returned an error!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      return ret;
  }

  print_hexstring(sigbuf, signedFT_size);

  print_hexstring(signedFT, signedFT_size);*/
  
  //return ret;

  /*
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
  */

  // Computing expected newFT from sealedState + eCMD + ES.freshness_tag

  unsigned char bigbuf[10000];
  memcpy(bigbuf, sealedstate, sealedstate_size);
  memcpy(bigbuf+sealedstate_size, eCMD, eCMD_size);
  unsigned char sealcmd_hash[32];

  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)bigbuf, sealedstate_size+eCMD_size, sealcmd_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  //printf("[ecPVRA] Enclave Computed sealcmd\n");
  //print_hexstring(sealcmd_hash, 32);


  unsigned char ftold_hash[32];
  memcpy(ftold_hash, enclave_state.counter.freshness_tag, 32);

  //printf("FTOLD: "); print_hexstring(ftold_hash, 32);

  /*for(int i = 0; i < 32; i++) {
    ftold_hash[i] = 0;
  }*/

  unsigned char merge[64];
  memcpy(merge, ftold_hash, 32);
  memcpy(merge+32, sealcmd_hash, 32);

  //printf("merge: "); print_hexstring(merge, 64);

  unsigned char merge_hexstring[129];
  //printf("MEREGE: %s")
  //unsigned char merge_hexstring[128] = "0000000000000000000000000000000000000000000000000000000000000000a547891be9ed742869b0cdac2644c0ba676ec14da845fb8ab072eea7bc221ca0";
  // TODO: change hash(hexstring[128]) to hash(bytes[32])

  const char *hex = "0123456789abcdef";
  for (int i = 0; i < 64; i++) {
    merge_hexstring[2*i+1] = hex[merge[i] & 0xF];
    merge_hexstring[2*i] = hex[(merge[i]>>4) & 0xF];
  }

  merge_hexstring[128] = 0;

  //printf("MERGE: %s\n", merge_hexstring);

  unsigned char ft_hash[32];

  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)merge_hexstring, 128, ft_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

/*
  unsigned char final_hexstring[64];
  const char *hex = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    final_hexstring[2*i+1] = hex[ft_hash[i] & 0xF];
    final_hexstring[2*i] = hex[(ft_hash[i]>>4) & 0xF];
  }




  unsigned char final_hash[32];

  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)final_hexstring, 64, final_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
*/




  //printf("[ecPVRA] SCS Received newFT = %d %s", FT_size, FT);
  //print_hexstring(FT, 32);

  printf("[ecPVRA] SCS Expected newFT = ");
  print_hexstring(ft_hash, 32);


  unsigned char ex_hexstring[65];
  //const char *hex = "0123456789abcdef";
  for (int i = 0; i < 32; i++) {
    ex_hexstring[2*i+1] = hex[ft_hash[i] & 0xF];
    ex_hexstring[2*i] = hex[(ft_hash[i]>>4) & 0xF];
  }
  ex_hexstring[64] = 0;

  int same = 0;
  for(int i = 0; i < 64; i++) {
    if(ex_hexstring[i] != FT[i]) {
      same = 1;
    }
  }

  
  if(same == 0) {
    printf("[ecPVRA] FT Match: success\n");
  }
  else {
    printf("[ecPVRA] FT Match: failure\n");
  }




  //printf("[ecPVRA] SCS Received newFT: %s\n", FT);
  unsigned char msg_hash[32];




  // TODO: technically unneeded hash, receive hash in FT
  // TODO: insert comparison between calculated and FT


 // printf("[ecPVRA] FT = %s", FT);
  //print_hexstring(ft_hash, 32);

  //printf("FT[%d]: %s, STRING[%d]: %s\n", strlen(FT), FT, 64, ex_hexstring);

  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)FT, strlen(FT)-1, msg_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  //  printf("[ecPVRA] msgHash = ");
  //print_hexstring(msg_hash, 32);

  mbedtls_pk_context pk_pub_key;
  mbedtls_pk_init(&pk_pub_key);

  ret = mbedtls_pk_parse_public_key(&pk_pub_key, (const unsigned char *)&enclave_state.counter.CCF_key, strlen(&enclave_state.counter.CCF_key)+1);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_pk_parse_public_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  
  mbedtls_rsa_context *rsapk_pub_key = mbedtls_pk_rsa(pk_pub_key);

  ret = mbedtls_rsa_check_pubkey(rsapk_pub_key);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_rsa_check_pubkey failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  ret = mbedtls_rsa_pkcs1_verify(rsapk_pub_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 64, msg_hash, signedFT);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_rsa_pkcs1_verify failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  else {
    printf("[ecPVRA] SCS Signature verification success\n");
  }


  //enclave_state.enclavekeys.priv_key_buffer
  //enclave_state.counter.CCF_key





  /*   (4) COMMAND DECRYPTION    */


  // RSA Decryption of AESkey using enclave private encryption key
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
    printf("[ecPVRA] mbedtls_pk_parse_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  
  ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)&enclave_state.enclavekeys.priv_key_buffer, strlen(&enclave_state.enclavekeys.priv_key_buffer)+1, 0, 0);
  if(ret != 0)
  {
    printf("[ecPVRA] mbedtls_pk_parse_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  unsigned char AESkey[MBEDTLS_MPI_MAX_SIZE];
  size_t AESkey_len = 0;

  ret = mbedtls_pk_decrypt(&pk, eAESkey, eAESkey_size, AESkey, &AESkey_len, sizeof(AESkey), mbedtls_ctr_drbg_random, &ctr_drbg);
  if(ret != 0)
  {
    printf("[ecPVRA] mbedtls_pk_parse_key failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  printf("[ecPVRA] Decrypted eAESkey: "); 
  print_hexstring_n(AESkey, AESkey_len);
  printf(" success\n");

  /*
  mbedtls_rsa_context *rsapk = mbedtls_pk_rsa(pk);

  ret = mbedtls_rsa_check_privkey(rsapk);
  if(ret != 0)
  {
    printf("[ecPVRA] mbedtls_rsa_check_privkey failed, returned -0x%04x\n", -ret);
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
    printf("[ecPVRA] mbedtls_pk_encrypt failed, returned -0x%04x\n", -ret); 
  } 

  printf("[ecPVRA] RSA_Encrypt: ");
  print_hexstring(buf, olen);
  */


  /* AES Encryption Example *//*
  uint8_t tag_dst[BUFLEN] = {0};
  uint8_t cipher_dst[BUFLEN] = {0};
  char *pt = "{user_data}";
  size_t pt_len = strlen(pt);
  size_t ct_len = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + pt_len;

  unsigned char aes128GCM_iv[AESGCM_128_IV_SIZE] = { 
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00
  };

  static const unsigned char plaintext[] = {
    0x7B,0x75,0x73,0x65,
    0x72,0x5F,0x64,0x61,
    0x74,0x61,0x7D,0x00,
    0x00,0x00,0x00,0x00
  };

  //https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes

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
    printf("[ecPVRA] Failed to Encrypt Command\n");
  }

  printf("ENCRYPTED COMMAND\n[TAG]   ");
  print_hexstring(tag_dst, AESGCM_128_MAC_SIZE);
  printf("[IV]    ");
  print_hexstring(aes128GCM_iv, AESGCM_128_IV_SIZE);
  printf("[CT]    ");
  print_hexstring(cipher_dst, pt_len);

  uint8_t eCMD_full[BUFLEN] = {0};

  memcpy(eCMD_full, tag_dst, AESGCM_128_MAC_SIZE);
  memcpy(eCMD_full + AESGCM_128_MAC_SIZE, aes128GCM_iv, AESGCM_128_IV_SIZE);
  memcpy(eCMD_full + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE, cipher_dst, pt_len);
  printf("[FULL]  ");
  print_hexstring(eCMD_full, ct_len);
  */


  uint8_t *eCMD_full = eCMD;

  uint8_t plain_dst[BUFLEN] = {0};
  size_t exp_ct_len = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + sizeof(struct clientCommand);
  size_t ct_len = eCMD_size;
  //size_t ct_len = exp_ct_len;
  size_t ct_src_len = ct_len - AESGCM_128_MAC_SIZE - AESGCM_128_IV_SIZE;
  
  if (ct_src_len != sizeof(struct clientCommand)) {
    printf("[ecPVRA] BAD eCMD %d %d\n", ct_src_len, sizeof(struct clientCommand));
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

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
    printf("[ecPVRA] Failed to Decrypt Command\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }


  // Load decrypted blob into struct
  struct clientCommand CC;
  memcpy(&CC, plain_dst, sizeof(struct clientCommand));
  printf("[ecPVRA] Decrypted eCMD hexstring: ");
  print_hexstring_n(plain_dst, sizeof(struct clientCommand));
  printf(" success\n");
  print_clientCommand(&CC);





  /*   (5) SEQNO VERIFICATION    */
  // TODO: bring back for final
  if(CC.seqNo != enclave_state.antireplay.seqno[CC.cid]) {
    printf("SeqNo failure [%d] =/= [%d]\n", CC.seqNo, enclave_state.antireplay.seqno[CC.cid]);
    return ret;
  }
  printf("SeqNo success [%d]\n", enclave_state.antireplay.seqno[CC.cid]);
  enclave_state.antireplay.seqno[CC.cid]++;




  /*   (6) PROCESS COMMAND    */

  struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*);
  int init_ret = initFP(functions);
  if(init_ret != 0) {
    printf("[ecPVRA] Init Function Pointers Failed\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  struct cResponse cRet;

  // APPLICATION KERNEL INVOKED
  cRet = (*functions[CC.CT.tid])(&enclave_state, &CC.CI);

  char* cRstring = cRet.message;
  //printf("[%d] %s\n", strlen(cRstring), cRstring);




  /*   (7) FT UPDATE    */

  memcpy(enclave_state.counter.freshness_tag, ft_hash, 32);
  printf("[ecPVRA] SCS Local FT updated success\n");
  //print_hexstring_n(enclave_state.counter.freshness_tag, 32);
  //printf(" success\n");


  /*   (8) SIGN CRESPONSE   */

  sgx_ecc_state_handle_t p_ecc_handle_sign = NULL;
  if((ret = sgx_ecc256_open_context(&p_ecc_handle_sign)) != SGX_SUCCESS) {
    print("[ecPVRA] sgx_ecc256_open_context() failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  memcpy(cResponse, cRstring, strlen(cRstring));

  if((ret = sgx_ecdsa_sign(cRstring, strlen(cRstring), &enclave_state.enclavekeys.sign_prikey, (sgx_ec256_signature_t *)cResponse_signature, p_ecc_handle_sign)) != SGX_SUCCESS) {
    printf("[ecPVRA] sgx_ecdsa_sign() failed !\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  printf("[ecPVRA] CResponse signed success\n");





  /*   (9) SEAL STATE    */

  //printf("[ecPVRA] sealedstate_size: %d\n", sgx_calc_sealed_data_size(0U, sizeof(enclave_state)));
  if(sealedout_size >= sgx_calc_sealed_data_size(0U, sizeof(enclave_state))) {
    ret = sgx_seal_data(0U, NULL, sizeof(enclave_state), (uint8_t *)&enclave_state, (uint32_t)sealedout_size, (sgx_sealed_data_t *)sealedout);
    if(ret !=SGX_SUCCESS) {
      print("[ecPVRA] sgx_seal_data() failed!\n");
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;
    }
  } 
  else {
    printf("[ecPVRA] Size allocated is less than the required size!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  printf("[ecPVRA] Enclave State sealed success\n");
  ret = SGX_SUCCESS;

  cleanup:
    if(rsapk_pub_key != NULL)
      mbedtls_rsa_free(rsapk_pub_key);
    // Not pointers don't need to freed
    /*
    if(pk_pub_key != NULL)
      mbedtls_pk_free(&pk_pub_key);
    if(ctr_drbg != NULL)
      mbedtls_ctr_drbg_free(&ctr_drbg);
    if(entropy != NULL)
      mbedtls_entropy_free(&entropy);
    if(pk != NULL)
      mbedtls_pk_free(&pk);
    if(p_ecc_handle_sign != NULL)
      sgx_ecc256_close_context(p_ecc_handle_sign);
    */
    return ret;
}
