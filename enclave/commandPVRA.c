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
#include "keccak256.h"

#include "enclavestate.h"
#include "appPVRA.h"

#define BUFLEN 2048
#define AESGCM_128_KEY_SIZE 16
#define AESGCM_128_MAC_SIZE 16
#define AESGCM_128_IV_SIZE 12

#define C_DEBUGPRINT 1
#define C_DEBUGRDTSC 0 


void get_address(secp256k1_pubkey * pubkey, address_t* out) {
    struct SHA3_CTX ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, pubkey, 64);
    unsigned char result[32];
    keccak_final(&ctx, &result);
    memcpy(out, &result[12], 20);
}

/**
 * This function executes one PVRA command.
 *
 * @param [in] sealedstate: incoming previous enclave state seal.
 * @param [in] FT: freshness tag that was signed by CCF.
 * @param [in] FT_signature: the CCF signature.
 * @param [in] eCMD: encrypted private_command.
 * @param [in] cmdpubkey: user_pubkey associated with command.
 * @param [out] cResponse: outgoing response to user that is enclave-signed.
 * @param [out] cResponse_signature: the cResponse signature.
 * @param [out] newsealedstate: outgoing new enclave state seal.
 *
 * @return SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */



sgx_status_t ecall_commandPVRA(
    char *sealedstate, size_t sealedstate_size, 
    char *FT, size_t FT_size,
    char *FT_signature, size_t FT_signature_size, 
    char *eCMD, size_t eCMD_size, 
    char *cmdpubkey, size_t cmdpubkey_size, 
    char *cResponse, size_t cResponse_size,
    char *cResponse_signature, size_t cResponse_signature_size,
    char *newsealedstate, size_t newsealedstate_size) {


  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  struct ES enclave_state;
  struct dAppData dAD;
  struct clientCommand CC;

  // Control Timing Measurement of an OCALL Overhead.
  if(C_DEBUGRDTSC) ocall_rdtsc();
  if(C_DEBUGRDTSC) ocall_rdtsc();





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

  if(C_DEBUGRDTSC) ocall_rdtsc();





  /*    (3) SCS Verification    */


  /*    Computing expected newFT from sealedState + eCMD + ES.freshness_tag   */

  uint32_t bigbuf_size = sealedstate_size + eCMD_size;
  uint8_t *const bigbuf = (uint8_t *)malloc(bigbuf_size); 
  memcpy(bigbuf, sealedstate, sealedstate_size);
  memcpy(bigbuf+sealedstate_size, eCMD, eCMD_size);

  unsigned char sealcmd_hash[32];
  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)bigbuf, sealedstate_size+eCMD_size, sealcmd_hash);
  if(ret != 0) {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  //printf("[ecPVRA] SCS sealcmd hash: \n"); print_hexstring(sealcmd_hash, 32);

  unsigned char ftold_hash[32];
  memcpy(ftold_hash, enclave_state.counter.freshness_tag, 32);
  //printf("[ecPVRA] SCS ftold hash: "); print_hexstring(ftold_hash, 32);

  unsigned char merge[64];
  memcpy(merge, ftold_hash, 32);
  memcpy(merge+32, sealcmd_hash, 32);
  //printf("[ecPVRA] SCS ftold||sealcmd: "); print_hexstring(merge, 64);

  // TODO: change hash(hexstring[128]) to hash(bytes[32])
  unsigned char merge_hexstring[129];
  const char *hex = "0123456789abcdef";
  for (int i = 0; i < 64; i++) {
    merge_hexstring[2*i+1] = hex[merge[i] & 0xF];
    merge_hexstring[2*i] = hex[(merge[i]>>4) & 0xF];
  }
  merge_hexstring[128] = 0;
  //printf("[ecPVRA] SCS merge_hexstring: %s\n", merge_hexstring);

  unsigned char ft_hash[32];
  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)merge_hexstring, 128, ft_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  //printf("[ecPVRA] SCS Received newFT = %d %s", FT_size, FT); print_hexstring(FT, 32);
  if(C_DEBUGPRINT) printf("[ecPVRA] SCS Expected newFT = ");
  if(C_DEBUGPRINT) print_hexstring(ft_hash, 32);

  unsigned char ex_hexstring[65];
  for (int i = 0; i < 32; i++) {
    ex_hexstring[2*i+1] = hex[ft_hash[i] & 0xF];
    ex_hexstring[2*i] = hex[(ft_hash[i]>>4) & 0xF];
  }
  ex_hexstring[64] = 0;


  /*    Comparing expected newFT to FT returned from SCS    */

  int same = 0;
  for(int i = 0; i < 64; i++) {
    if(ex_hexstring[i] != FT[i]) {
      same = 1;
    }
  }

  if(same == 0) {
    if(C_DEBUGPRINT) printf("[ecPVRA] SCS FT Match: success\n");
  }
  else {
    if(C_DEBUGPRINT) printf("[ecPVRA] SCS FT Match: failure (if CCF_ENABLE=1)\n");
  }


  /*    Verifying SCS Signature    */

  unsigned char msg_hash[32];
  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)FT, strlen(FT)-1, msg_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  //printf("[ecPVRA] SCS signature msg hash = "); print_hexstring(msg_hash, 32);

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

  ret = mbedtls_rsa_pkcs1_verify(rsapk_pub_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 64, msg_hash, FT_signature);
  if(ret != 0) 
  {
    printf("[ecPVRA] SCS Signature verification failed on mbedtls_rsa_pkcs1_verify, returned -0x%04x (if CCF_ENABLE=1)\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    //goto cleanup;
  }
  else {
    if(C_DEBUGPRINT) printf("[ecPVRA] SCS Signature verification success\n");
  }

  if(C_DEBUGRDTSC) ocall_rdtsc();




  
  /*    (4) Command Decryption    */


  /*    Reading the user_pubkey    */

  memcpy(&CC.user_pubkey, cmdpubkey, sizeof(secp256k1_pubkey));
  int user_idx = -1;
  for(int i = 0; i < MAX_USERS; i++) {
    if(strncmp(&CC.user_pubkey, &enclave_state.auditmetadata.master_user_pubkeys[i], sizeof(secp256k1_pubkey)) == 0) {
      user_idx = i;
    }
  }
  if (user_idx == -1) {
    if(C_DEBUGPRINT) printf("[ecPVRA] user_pubkey NOT FOUND rejecting command\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  if(C_DEBUGPRINT) printf("[ecPVRA] CMD user_pubkey[%d]: ", user_idx);
  if(C_DEBUGPRINT) print_hexstring_n(&CC.user_pubkey, 3);
  if(C_DEBUGPRINT) printf("....");
  if(C_DEBUGPRINT) print_hexstring_n(((char *)&CC.user_pubkey)+61, 3);
  if(C_DEBUGPRINT) printf(" success\n");


  /*    ECDH protocol to generate shared secret AESKey    */

  unsigned char randomize_e[32];
  secp256k1_context* ctx_e = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  // Handle NULL
  sgx_read_rand(randomize_e, sizeof(randomize_e));
  int secp25k1_ret = secp256k1_context_randomize(ctx_e, randomize_e);
  unsigned char shared_secret[32];

  secp256k1_pubkey user_pubkey;
  char user_pubkey_buff[65];
  user_pubkey_buff[0] = 4;
  memcpy(&user_pubkey_buff[1], &enclave_state.auditmetadata.master_user_pubkeys[user_idx], 64);
  secp256k1_ec_pubkey_parse(ctx_e, &user_pubkey, &user_pubkey_buff, 65);

  secp25k1_ret = secp256k1_ecdh(ctx_e, shared_secret, &user_pubkey, &enclave_state.enclavekeys.enc_prikey, NULL, NULL);
  //if(C_DEBUGPRINT) printf("[eiPVRA] Enclave Generated User0 Shared Secret\n");
  //if(C_DEBUGPRINT) print_hexstring(&shared_secret, 32);
  //if(C_DEBUGPRINT) printf("\n");
  unsigned char AESkey[16];
  size_t AESkey_len = 16;
  memcpy(AESkey, shared_secret, 16);


  /*    AES Decryption of CMD using AESkey    */

  uint8_t *eCMD_full = eCMD;

  uint8_t plain_dst[BUFLEN] = {0};
  size_t exp_ct_len = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + sizeof(struct private_command);
  size_t ct_len = eCMD_size;
  //size_t ct_len = exp_ct_len;
  size_t ct_src_len = ct_len - AESGCM_128_MAC_SIZE - AESGCM_128_IV_SIZE;
  
  if (ct_src_len != sizeof(struct private_command)) {
    printf("[ecPVRA] BAD eCMD %d %d\n", ct_src_len, sizeof(struct private_command));
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

  /*    Load decrypted private_command into struct clientCommand   */

  memcpy(&CC.eCMD, plain_dst, sizeof(struct private_command));
  if(C_DEBUGPRINT) printf("[ecPVRA] Decrypted eCMD hexstring: ");
  if(C_DEBUGPRINT) print_hexstring_n(plain_dst, sizeof(struct private_command));
  if(C_DEBUGPRINT) printf(" success\n");
  if(C_DEBUGPRINT) print_clientCommand(&CC);

  if(C_DEBUGRDTSC) ocall_rdtsc();




  
  /*    (5) SEQNO Verification    */

  if(CC.eCMD.seqNo != enclave_state.antireplay.seqno[user_idx]) {
    printf("SeqNo failure received [%d] =/= [%d] logged\n", CC.eCMD.seqNo, enclave_state.antireplay.seqno[user_idx]);
    return ret;
  }
  if(C_DEBUGPRINT) printf("SeqNo success [%d]\n", enclave_state.antireplay.seqno[user_idx]);
  enclave_state.antireplay.seqno[user_idx]++;

  if(C_DEBUGRDTSC) ocall_rdtsc();




  
  /*   (6) PROCESS COMMAND    */

  struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*);
  int init_ret = initFP(functions);
  if(init_ret != 0) {
    printf("[ecPVRA] Init Function Pointers Failed\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  struct cResponse cRet;

  /*   APPLICATION KERNEL INVOKED    */
  cRet = (*functions[CC.eCMD.CT.tid])(&enclave_state, &CC.eCMD.CI);
  char* cRstring = cRet.message;
  //printf("[ecPVRA] cRet.message: [%d] %s\n", strlen(cRstring), cRstring);
  if(C_DEBUGRDTSC) ocall_rdtsc();




  
  /*   (6.5) UPDATE AUDIT LOG    */
  int entry = enclave_state.auditmetadata.audit_offset;
  unsigned char eCMD_hash[32];
  ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)eCMD, eCMD_size, eCMD_hash);
  if(ret != 0) 
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  get_address(&CC.user_pubkey, &enclave_state.auditmetadata.auditlog.user_pubkeys[entry]);
  memcpy(&enclave_state.auditmetadata.auditlog.command_hashes[entry], eCMD_hash, 32);
  enclave_state.auditmetadata.audit_offset++;

  if(C_DEBUGRDTSC) ocall_rdtsc();

  // PRINTS AUDIT LOG 
  /*
  for(int i = 0; i < entry+1; i++) {
    printf("ENTRY[%d]: ", i);
    print_hexstring(&enclave_state.auditmetadata.auditlog.command_hashes[i], 32);
    printf("PBUKEY: ");
    print_hexstring(&enclave_state.auditmetadata.auditlog.user_pubkeys[i], 20);
  } 
  */




  
  /*   (7) FT UPDATE    */

  memcpy(enclave_state.counter.freshness_tag, ft_hash, 32);
  if(C_DEBUGPRINT) printf("[ecPVRA] SCS Local FT updated success\n");
  //print_hexstring_n(enclave_state.counter.freshness_tag, 32);
  //printf(" success\n");
  if(C_DEBUGRDTSC) ocall_rdtsc();




  
  /*   (8) SIGN CRESPONSE   */

  unsigned char cR_hash[32];
  ret = mbedtls_md(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 
      (const unsigned char *)cRstring, 
      strlen(cRstring), 
      cR_hash);
  if(ret != 0) {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -ret);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  secp256k1_ecdsa_signature sig;
  unsigned char randomize[32];

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  sgx_read_rand(randomize, sizeof(randomize));
  secp25k1_ret = secp256k1_context_randomize(ctx, randomize);
  secp25k1_ret = secp256k1_ecdsa_sign(ctx, &sig, cR_hash, &enclave_state.enclavekeys.sig_prikey, NULL, NULL);

  //printf("[eiPVRA] PUBKEYS SIGNATURE %d\n", sizeof(secp256k1_ecdsa_signature));
  //print_hexstring(&sig, sizeof(secp256k1_ecdsa_signature));

  memcpy(cResponse, cRstring, strlen(cRstring));
  memcpy(cResponse_signature, &sig, 64);
  secp256k1_context_destroy(ctx);

  if(C_DEBUGRDTSC) ocall_rdtsc();





  /*   (9) SEAL STATE    */

  // TODO: THIS WILL BREAK if new_unsealed_data_size > newsealedstate_size
  uint32_t new_unsealed_data_size = sizeof(enclave_state) + sizeof(struct dAppData);
  for(int i = 0; i < dAD.num_dDS; i++) {
    new_unsealed_data_size += sizeof(struct dynamicDS);
    new_unsealed_data_size += dAD.dDS[i]->buffer_size;
  }
  uint8_t *const new_unsealed_data = (uint8_t *)malloc(new_unsealed_data_size); 

  int new_unsealed_offset = 0;
  memcpy(new_unsealed_data + new_unsealed_offset, &enclave_state, sizeof(struct ES));
  new_unsealed_offset += sizeof(struct ES);

  memcpy(new_unsealed_data + new_unsealed_offset, &dAD, sizeof(struct dAppData));
  new_unsealed_offset += sizeof(struct dAppData);

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(new_unsealed_data + new_unsealed_offset, dAD.dDS[i], sizeof(struct dynamicDS));
    new_unsealed_offset += sizeof(struct dynamicDS);
  }

  for(int i = 0; i < dAD.num_dDS; i++) {
    memcpy(new_unsealed_data + new_unsealed_offset, dAD.dDS[i]->buffer, dAD.dDS[i]->buffer_size);
    new_unsealed_offset += dAD.dDS[i]->buffer_size;
  }

  if(new_unsealed_offset != new_unsealed_data_size) {
    printf("[ecPVRA] creating new_unsealed_data blob error.\n");
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


  uint32_t seal_size = sgx_calc_sealed_data_size(0U, new_unsealed_data_size);
  if(C_DEBUGPRINT) printf("[ecPVRA] New seal_size: [%d]\n", seal_size);

  //printf("[ecPVRA] sealedstate_size: %d\n", sgx_calc_sealed_data_size(0U, sizeof(enclave_state)));
  //if(sealedout_size >= sgx_calc_sealed_data_size(0U, sizeof(enclave_state))) {
  ret = sgx_seal_data(0U, NULL, new_unsealed_data_size, new_unsealed_data, seal_size, (sgx_sealed_data_t *)newsealedstate);
  if(ret !=SGX_SUCCESS) {
    print("[ecPVRA] sgx_seal_data() failed!\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  //} 
  //else {
  //  printf("[ecPVRA] Size allocated is less than the required size!\n");
  //  ret = SGX_ERROR_INVALID_PARAMETER;
  //  goto cleanup;
  //}

  if(C_DEBUGPRINT) printf("[ecPVRA] Enclave State sealed success\n");
  ret = SGX_SUCCESS;



  cleanup:
    if(rsapk_pub_key != NULL)
      mbedtls_rsa_free(rsapk_pub_key);
    if(C_DEBUGRDTSC) ocall_rdtsc();
    return ret;
}
