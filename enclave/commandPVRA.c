/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

//#include <stdarg.h>
//#include <stdio.h>
//
//#include "enclave.h"
//#include <enclave_t.h>
//
//#include <sgx_quote.h>
//#include <sgx_tcrypto.h>
//#include <sgx_tseal.h>
//#include <sgx_utils.h>
#include <mbedtls/md.h>
//#include <mbedtls/entropy.h>
//#include <mbedtls/ctr_drbg.h>
//#include <mbedtls/bignum.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>

// [TODO]: If possible remove mbedtls dependence, only used for sha256 hashes now

//#include <secp256k1.h>
//#include <secp256k1_ecdh.h>

#include "enclave_state.h"
//#include "appPVRA.h"
#include "keccak256.h"
#include "util.h"

sgx_status_t encrypt_cResponse(unsigned char AESKey[AESGCM_128_KEY_SIZE], struct cResponse * cResp, uint8_t * enc_cResponse, size_t enc_cResponse_size);
sgx_status_t sign_cResponse(uint8_t seckey[32], struct cResponse * cResp, unsigned char *sig_ser);

/**
 * This function executes one PVRA command.
 *
 * @param [in] sealedstate: incoming previous enclave state seal.
 * @param [in] FT: freshness tag that was signed by CCF.
 * @param [in] FT_signature: the CCF signature.
 * @param [in] eCMD: encrypted private_command.
 * @param [out] enc_cResponse: outgoing response to user that is enclave-signed and encrypted.
 * @param [out] cResponse_signature: the cResponse signature.
 * @param [out] newsealedstate: outgoing new enclave state seal.
 *
 * @return SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
 */
sgx_status_t ecall_commandPVRA(
    uint8_t *sealedstate, size_t sealedstate_size,
    uint8_t FT[8],
    uint8_t FT_signature[64],
    uint8_t *eCMD, size_t eCMD_size,
    uint8_t *enc_cResponse, size_t enc_cResponse_size,
    uint8_t cResponse_signature[64],
    uint8_t *newsealedstate, size_t newsealedstate_size) {

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  struct ES enclave_state;
  struct dAppData dAD;
  struct clientCommand CC;
  struct cResponse cResp;
  char resp[100];
  int err;

  // Control Timing Measurement of an OCALL Overhead.
  if(C_DEBUGRDTSC) ocall_rdtsc();
  if(C_DEBUGRDTSC) ocall_rdtsc();


  /*    Unseal Enclave State    */
  ret = unseal_enclave_state(sealedstate, true, &enclave_state, &dAD);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(C_DEBUGRDTSC) ocall_rdtsc();

  if(eCMD_size < 64 + sizeof(uint64_t)) {//at minimum the command should have a public key seq no and 1+ bytes of data
    printf("[ecPVRA] malformed eCMD eCMD_size %lu < %lu\n", eCMD_size, 64 + sizeof(uint64_t));
    sprintf(resp, "malformed eCMD eCMD_size %lu < %lu\n", eCMD_size, 64 + sizeof(uint64_t));
    formatResponse(enc_cResponse + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE, -1, resp);
    if (ret == SGX_SUCCESS)
        ret = sign_cResponse(enclave_state.enclavekeys.enc_prikey, enc_cResponse, cResponse_signature);
    goto cleanup;
  }

  /*  UPDATE AUDIT LOG    */
  if(DEBUGPRINT) printf("[ecPVRA] eCMD_full: ");
  if(DEBUGPRINT) print_hexstring(eCMD, eCMD_size);
  memcpy(&CC.seqNo, eCMD, sizeof(uint64_t));
  memcpy(CC.user_pubkey, eCMD + sizeof(uint64_t), 64);
  uint8_t *eCMD_full = eCMD + sizeof(uint64_t) + 64; //first 8+64 bytes is the seq num and then user public key
  size_t eCMD_full_size = eCMD_size - sizeof(uint64_t) - 64; //first 8+64 bytes is the seq num and then user public key
  if(DEBUGPRINT) printf("[ecPVRA] eCMD: ");
  if(DEBUGPRINT) print_hexstring(eCMD_full, eCMD_full_size);

  unsigned char eCMD_hash[HASH_SIZE];
  struct SHA3_CTX ctx_hash_eCMD;
  keccak_init(&ctx_hash_eCMD);
  keccak_update(&ctx_hash_eCMD, eCMD_full, eCMD_full_size);
  keccak_final(&ctx_hash_eCMD, eCMD_hash);
  if(DEBUGPRINT) printf("[ecPVRA] eCMD_hash: ");
  if(DEBUGPRINT) print_hexstring(eCMD_hash, HASH_SIZE);

  if(C_DEBUGRDTSC) ocall_rdtsc();

  uint64_t auditlog_entry_index = enclave_state.auditmetadata.auditlog.num_entries;
  struct audit_entry_t *new_audit_entry = &enclave_state.auditmetadata.auditlog.entries[auditlog_entry_index];
  get_packed_address(CC.user_pubkey, new_audit_entry->user_address);
  memcpy(&new_audit_entry->command_hash, eCMD_hash, HASH_SIZE);
  new_audit_entry->seqNo = CC.seqNo;
  enclave_state.auditmetadata.auditlog.num_entries++;

  // PRINTS AUDIT LOG
  if(DEBUGPRINT) { //todo change to ifdefineif
    printf("[ecPVRA] PRINTING READABLE AUDITLOG len: %d\n", enclave_state.auditmetadata.auditlog.num_entries);
    for(int i = 0; i < enclave_state.auditmetadata.auditlog.num_entries; i++) {
      struct audit_entry_t audit_entry = enclave_state.auditmetadata.auditlog.entries[i];
      printf("[%d]: SEQ: %lu",i, audit_entry.seqNo);
      printf(" ADDR: ");
      print_hexstring_trunc_n((uint8_t *) audit_entry.user_address + 12, sizeof(packed_address_t)-12);
      printf(" HASH: ");
      print_hexstring_trunc_n(audit_entry.command_hash, HASH_SIZE);
      printf("\n");
    }
  }

  /*    SCS Verification    */
   
  //Computing expected newFT from sealedState + eCMD + ES.freshness_tag   */
  
  uint32_t bigbuf_size = sealedstate_size + eCMD_size;//todo make sure this hash is calculated correctly because eCMD format changed
  uint8_t *bigbuf = (uint8_t *)malloc(bigbuf_size);
  memcpy(bigbuf, sealedstate, sealedstate_size);
  memcpy(bigbuf+sealedstate_size, eCMD, eCMD_size);
  
  unsigned char sealcmd_hash[HASH_SIZE];
  err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)bigbuf, sealedstate_size+eCMD_size, sealcmd_hash);
  if(err != 0) {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -err);
    ret = SGX_ERROR_UNEXPECTED;
    goto cleanup;
  }
//  if(DEBUGPRINT) printf("[ecPVRA] SCS sealcmd hash: \n"); print_hexstring(sealcmd_hash, HASH_SIZE);

//  if(DEBUGPRINT) printf("[ecPVRA] SCS ftold hash: "); print_hexstring(enclave_state.counter.freshness_tag, HASH_SIZE);
  
  unsigned char merge[HASH_SIZE*2];
  memcpy(merge, enclave_state.counter.freshness_tag, HASH_SIZE);
  memcpy(merge+HASH_SIZE, sealcmd_hash, HASH_SIZE);
//  if(DEBUGPRINT) printf("[ecPVRA] SCS ftold||sealcmd: "); print_hexstring(merge, HASH_SIZE*2);

  // TODO: change hash(hexstring[128]) to hash(bytes[32])
  unsigned char merge_hexstring[129];
  const char *hex = "0123456789abcdef";
  for (int i = 0; i < 64; i++) {
    merge_hexstring[2*i+1] = hex[merge[i] & 0xF];
    merge_hexstring[2*i] = hex[(merge[i]>>4) & 0xF];
  }
  merge_hexstring[128] = 0;
//  if(DEBUGPRINT) printf("[ecPVRA] SCS merge_hexstring: %s\n", merge_hexstring);

  unsigned char ft_hash[HASH_SIZE];
  err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)merge_hexstring, 128, ft_hash);
  if(err != 0)
  {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -err);
    ret = SGX_ERROR_UNEXPECTED;
    goto cleanup;
  }

  if(DEBUGPRINT) printf("[ecPVRA] SCS Received newFT = %.*s\n", 8, FT);
  if(DEBUGPRINT) printf("[ecPVRA] SCS Expected newFT = ");
  if(DEBUGPRINT) print_hexstring(ft_hash, HASH_SIZE);

  unsigned char ex_hexstring[65];
  for (int i = 0; i < 32; i++) {
    ex_hexstring[2*i+1] = hex[ft_hash[i] & 0xF];
    ex_hexstring[2*i] = hex[(ft_hash[i]>>4) & 0xF];
  }
  ex_hexstring[64] = 0;

  /*    Comparing expected newFT to FT returned from SCS    */
  for(int i = 0; i < 64; i++) { //todo this is weird and will break because FT is len 8
    if(ex_hexstring[i] != FT[i]) {
      printf("[ecPVRA] SCS FT Match: failure");
      if (CCF_ENABLE == 1){
        printf("\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
      } else {
        printf(" CCF_ENABLE=0 ignoring..\n");
        break;
      }
    }
  }

  /*    Verifying SCS Signature    */
  unsigned char msg_hash[32];
  err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (const unsigned char *)FT, 8, msg_hash);
  if(err != 0) {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -err);
    ret = SGX_ERROR_UNEXPECTED;
    goto cleanup;
  }
//  if(DEBUGPRINT) printf("[ecPVRA] SCS signature msg hash = "); print_hexstring(msg_hash, HASH_SIZE);

  mbedtls_pk_context pk_pub_key;
  mbedtls_pk_init(&pk_pub_key);
  err = mbedtls_pk_parse_public_key(&pk_pub_key, (const unsigned char *)&enclave_state.counter.CCF_key, strlen(&enclave_state.counter.CCF_key)+1);
  if(err != 0) {
    printf("[ecPVRA] mbedtls_pk_parse_public_key failed, returned -0x%04x\n", -err);
    ret = SGX_ERROR_UNEXPECTED;
    goto cleanup;
  }

  mbedtls_rsa_context *rsapk_pub_key = mbedtls_pk_rsa(pk_pub_key);
  err = mbedtls_rsa_check_pubkey(rsapk_pub_key);
  if(err != 0) {
    printf("[ecPVRA] mbedtls_rsa_check_pubkey failed, returned -0x%04x\n", -err);
    err = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  err = mbedtls_rsa_pkcs1_verify(rsapk_pub_key, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 64, msg_hash, FT_signature);
  if(err != 0) {
    printf("[ecPVRA] SCS Signature verification failed on mbedtls_rsa_pkcs1_verify, returned -0x%04x", -err);
    if (CCF_ENABLE == 1) {
        printf("\n");
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    } else {
        printf(" CCF_ENABLE=0 ignoring..\n");
    }
  } else {
    if(DEBUGPRINT) printf("[ecPVRA] SCS Signature verification success\n");
  }

  if(C_DEBUGRDTSC) ocall_rdtsc();


  /*    (4) Command Decryption    */

  if(DEBUGPRINT) printf("[ecPVRA] eCMD user_pubkey: ");
  if(DEBUGPRINT) print_hexstring(&CC.user_pubkey, 64);
  int user_idx = -1;
  for(int i = 0; i < NUM_USERS+1; i++) {
    if(strncmp(CC.user_pubkey, enclave_state.auditmetadata.master_user_pubkeys[i], 64) == 0) {
      user_idx = i;
      break;
    }
  }

  if (user_idx == -1) {
    printf("[ecPVRA] user_pubkey NOT FOUND rejecting command\n");
    formatResponse(enc_cResponse + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE, -2, "user public key NOT FOUND rejecting command");
    ret = sign_cResponse(enclave_state.enclavekeys.enc_prikey, enc_cResponse, cResponse_signature);
    goto seal_cleanup;
  }

  if(DEBUGPRINT) printf("[ecPVRA] CMD user_idx %d\n", user_idx);

  /*    ECDH protocol to generate shared secret AESKey    */
  unsigned char AESKey[AESGCM_128_KEY_SIZE];
  ret = genkey_aesgcm128(enclave_state.auditmetadata.master_user_pubkeys[user_idx], enclave_state.enclavekeys.enc_prikey, AESKey);
  if(DEBUGPRINT) printf("[eiPVRA] Enclave Generated AES key ");
  if(DEBUGPRINT) print_hexstring(AESKey, AESGCM_128_KEY_SIZE);


  /*    AES Decryption of CMD using AESKey    */

  uint8_t plain_dst[sizeof(struct private_command)] = {0};
  size_t exp_ct_len = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + sizeof(struct private_command);
  size_t ct_len = eCMD_full_size;
  size_t ct_src_len = ct_len - AESGCM_128_MAC_SIZE - AESGCM_128_IV_SIZE;
  if (ct_src_len != sizeof(struct private_command)) {
    sprintf(resp, "BAD eCMD length %d expected length %d", ct_src_len, sizeof(struct private_command));
    formatResponse(&cResp, -3, resp);
    sign_cResponse(enclave_state.enclavekeys.enc_prikey, &cResp, cResponse_signature);
    encrypt_cResponse(AESKey, &cResp, enc_cResponse, enc_cResponse_size);
    goto seal_cleanup;
  }

  uint8_t *ct_src = &eCMD_full[AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE];
  uint8_t *iv_src = &eCMD_full[AESGCM_128_MAC_SIZE];
  uint8_t *tag_src = eCMD_full;

  err = sgx_rijndael128GCM_decrypt(
    (sgx_aes_gcm_128bit_key_t *) AESKey,
    (const uint8_t *) ct_src, (uint32_t) ct_src_len,
    (uint8_t *) plain_dst,
    (const uint8_t *) iv_src, (uint32_t) SGX_AESGCM_IV_SIZE,
    NULL, 0,
    (sgx_aes_gcm_128bit_tag_t *) tag_src
  );

  if(err) {
    printf("[ecPVRA] Failed to Decrypt Command err: %d\n", err);
    sprintf(resp, "Failed to Decrypt Command err: %d", err);
    formatResponse(&cResp, -3, resp);
    sign_cResponse(enclave_state.enclavekeys.enc_prikey, &cResp, cResponse_signature);
    encrypt_cResponse(AESKey, &cResp, enc_cResponse, enc_cResponse_size);
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto seal_cleanup;
  }

  /*    Load decrypted private_command into struct clientCommand   */

  memcpy(&CC.eCMD, plain_dst, sizeof(struct private_command));
  if(DEBUGPRINT) printf("[ecPVRA] Decrypted eCMD\n");
  if(DEBUGPRINT) print_hexstring(plain_dst, sizeof(struct private_command));
  if(DEBUGPRINT) print_clientCommand(&CC, user_idx-1);

  if(C_DEBUGRDTSC) ocall_rdtsc();


  
  /*    (5) SEQNO Verification    */
  if (user_idx > 0) { //i.e. not admin
    if(CC.seqNo != enclave_state.antireplay.seqno[user_idx-1]+1) {
        printf("[ecPVRA] SeqNo failure received [%lu] != [%lu] Not logging\n", CC.seqNo, enclave_state.antireplay.seqno[user_idx-1]+1);
        sprintf(resp, "SeqNo failure received [%lu] != [%lu] NOT logging\n", CC.seqNo, enclave_state.antireplay.seqno[user_idx-1]+1);
        formatResponse(&cResp, -4, resp);
        sign_cResponse(enclave_state.enclavekeys.enc_prikey, &cResp, cResponse_signature);
        encrypt_cResponse(AESKey, &cResp, enc_cResponse, enc_cResponse_size);
        goto cleanup;
    }
    enclave_state.antireplay.seqno[user_idx-1]++;
    if(DEBUGPRINT) printf("[ecPVRA] SeqNo success [%lu]\n", enclave_state.antireplay.seqno[user_idx-1]);
  }
  if(C_DEBUGRDTSC) ocall_rdtsc();




  
  /*   (6) PROCESS COMMAND    */
#ifdef NUM_ADMIN_COMMANDS
  struct cResponse (*functions[NUM_COMMANDS+NUM_ADMIN_COMMANDS])(struct ES*, struct cInputs*, uint32_t);
#else
  struct cResponse (*functions[NUM_COMMANDS])(struct ES*, struct cInputs*, uint32_t);
#endif

  int init_ret = initFP(functions);
  if(init_ret != 0) {
    printf("[ecPVRA] Init Function Pointers Failed\n");
    ret = SGX_ERROR_UNEXPECTED;
    goto cleanup;
  }
  /*   APPLICATION KERNEL INVOKED    */
  cResp = (*functions[CC.eCMD.CT])(&enclave_state, &CC.eCMD.CI, user_idx-1);
  
  /*   (7) FT UPDATE    */

  memcpy(enclave_state.counter.freshness_tag, ft_hash, 32); //todo why is this done here
  if(DEBUGPRINT) printf("[ecPVRA] SCS Local FT updated ");
  if(DEBUGPRINT) print_hexstring(enclave_state.counter.freshness_tag, 32);

  if(C_DEBUGRDTSC) ocall_rdtsc();


  /*   (8) SIGN cRESPONSE    */

  sign_cResponse(enclave_state.enclavekeys.enc_prikey, &cResp, cResponse_signature);
  encrypt_cResponse(AESKey, &cResp, enc_cResponse, enc_cResponse_size);

  if(C_DEBUGRDTSC) ocall_rdtsc();

  goto seal_cleanup;

  /*   (9) SEAL STATE    */
  //todo should still seal audit log if user has errors but not if admin has errors
  seal_cleanup: ;
    ret = seal_enclave_state(&enclave_state, &dAD, newsealedstate_size, newsealedstate);
    if(ret == SGX_SUCCESS) {
      if(DEBUGPRINT) printf("[eiPVRA] sealed state size: [%lu]\n", newsealedstate_size);
    }
    goto cleanup;

  cleanup:
    if(rsapk_pub_key != NULL)
      mbedtls_rsa_free(rsapk_pub_key);
    if (bigbuf != NULL)
        free(bigbuf);
    if(C_DEBUGRDTSC) ocall_rdtsc();
    return ret;
}

sgx_status_t sign_cResponse(uint8_t seckey[32], struct cResponse * cResp, unsigned char *sig_ser){
  unsigned char cR_hash[HASH_SIZE];
  int err = mbedtls_md(
    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    cResp,
    sizeof(struct cResponse),
    cR_hash);
  if(err != 0) {
    printf("[ecPVRA] mbedtls_md failed, returned -0x%04x\n", -err);
    return SGX_ERROR_UNEXPECTED;
  }

  secp256k1_ecdsa_signature sig;

  sgx_status_t ret = sign_secp256k1(seckey, cR_hash, &sig, sig_ser);
  if (ret == SGX_SUCCESS) {
    if(DEBUGPRINT) printf("[eiPVRA] cResponse SIGNATURE serealized ");
    if(DEBUGPRINT) print_hexstring(sig_ser, 64);
  }
  return ret;
}

sgx_status_t encrypt_cResponse(unsigned char AESKey[AESGCM_128_KEY_SIZE], struct cResponse * cResp, uint8_t * enc_cResponse, size_t enc_cResponse_size){
  size_t expected_cResponse_size = AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE + sizeof(struct cResponse);
  if (enc_cResponse_size != expected_cResponse_size) {
      printf("[eiPVRA] enc_cResponse_size incorrect %lu != %lu\n", enc_cResponse_size, expected_cResponse_size);
      return SGX_ERROR_UNEXPECTED;
  }

  sgx_status_t ret = encrypt_aesgcm128(AESKey, (uint8_t *)cResp, sizeof(struct cResponse), enc_cResponse);

  if (ret == SGX_SUCCESS) {
    if(DEBUGPRINT) printf("[eiPVRA] encrypted  cResponse ");
    if(DEBUGPRINT) print_hexstring(enc_cResponse, enc_cResponse_size);
  }

  return ret;
}