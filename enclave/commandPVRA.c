#include "enclave_state.h"
#include "keccak256.h"
#include "util.h"

sgx_status_t encrypt_cResponse(unsigned char AESKey[AESGCM_128_KEY_SIZE], struct cResponse * cResp, uint8_t * enc_cResponse, size_t enc_cResponse_size);
sgx_status_t sign_cResponse(uint8_t seckey[32], struct cResponse * cResp, unsigned char *sig_ser);

/**
 * This function executes one PVRA command.
 *
 * @param [in] sealedstate: incoming previous enclave state seal.
 * @param [in] FT: freshness tag with evidence that was signed by CCF.
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
    uint8_t * FT, size_t FT_size,
    uint8_t * FT_signature, size_t FT_signature_size,
    uint8_t *eCMD, size_t eCMD_size,
    uint8_t *enc_cResponse, size_t enc_cResponse_size,
    uint8_t cResponse_signature[64],
    uint8_t *newsealedstate, size_t newsealedstate_size) {

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  struct ES enclave_state;
  struct dAppData dAD;
  init_enclave_state(&enclave_state, &dAD);
  struct clientCommand CC;
  struct cResponse cResp;
  char resp[100];
  int err;
  uint8_t *bigbuf = NULL;
  struct ccf_proof scs_proof;
  scs_proof.proof = NULL;

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

  uint64_t auditlog_entry_index = enclave_state.auditlog.num_entries;
  struct audit_entry_t *new_audit_entry = &enclave_state.auditlog.entries[auditlog_entry_index];
  get_packed_address(CC.user_pubkey, new_audit_entry->user_address);
  memcpy(&new_audit_entry->command_hash, eCMD_hash, HASH_SIZE);
  new_audit_entry->seqNo = CC.seqNo;
  enclave_state.auditlog.num_entries++;

  // PRINTS AUDIT LOG
  if(DEBUGPRINT) { //todo change to ifdefineif
    printf("[ecPVRA] PRINTING READABLE AUDITLOG len: %d\n", enclave_state.auditlog.num_entries);
    for(int i = 0; i < enclave_state.auditlog.num_entries; i++) {
      struct audit_entry_t audit_entry = enclave_state.auditlog.entries[i];
      printf("[%d]: SEQ: %lu",i, audit_entry.seqNo);
      printf(" ADDR: ");
      print_hexstring_trunc_n((uint8_t *) audit_entry.user_address + 12, sizeof(packed_address_t)-12);
      printf(" HASH: ");
      print_hexstring_trunc_n(audit_entry.command_hash, HASH_SIZE);
      printf("\n");
    }
  }

  /*    SCS Verification    */
  
  if(DEBUGPRINT) printf("[ecPVRA] FT evidence: "); print_hexstring(FT, FT_size);

  err = parse_ccf_proof(FT, FT_size, &scs_proof);
  if (err != 0) {
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }
  //Computing expected newFT from sealedState + eCMD + ES.freshness_tag   */
  
  uint32_t bigbuf_size = sealedstate_size + eCMD_size;
  bigbuf = (uint8_t *)malloc(bigbuf_size);
  memcpy(bigbuf, sealedstate, sealedstate_size);
  memcpy(bigbuf+sealedstate_size, eCMD, eCMD_size);
  
  unsigned char sealcmd_hash[HASH_SIZE];
  sha256(bigbuf, sealedstate_size+eCMD_size, sealcmd_hash);
  free(bigbuf);
  bigbuf=NULL;
  if(DEBUGPRINT) printf("[ecPVRA] SCS sealcmd hash: \n"); print_hexstring(sealcmd_hash, HASH_SIZE);

 if(DEBUGPRINT) printf("[ecPVRA] SCS ft old hash: "); print_hexstring(enclave_state.counter.freshness_tag, HASH_SIZE);
  
  unsigned char merge[HASH_SIZE*2];
  memcpy(merge, enclave_state.counter.freshness_tag, HASH_SIZE);
  memcpy(merge+HASH_SIZE, sealcmd_hash, HASH_SIZE);
 if(DEBUGPRINT) printf("[ecPVRA] SCS ftold||sealcmd: "); print_hexstring(merge, HASH_SIZE*2);

  unsigned char ft_hash[HASH_SIZE];

  sha256(merge, HASH_SIZE*2, ft_hash);

  if(DEBUGPRINT) printf("[ecPVRA] SCS Received FT %lu = ", HASH_SIZE);
  if(DEBUGPRINT) print_hexstring(FT, HASH_SIZE);
  if(DEBUGPRINT) printf("[ecPVRA] SCS Expected FT %lu = ", HASH_SIZE);
  if(DEBUGPRINT) print_hexstring(ft_hash, HASH_SIZE);

  /*    Comparing expected newFT to FT returned from SCS    */
  for(int i = 0; i < HASH_SIZE; i++) {
    if(ft_hash[i] != scs_proof.FT[i]) {
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
  err = check_ccf_proof(&scs_proof, FT_signature, FT_signature_size);
  if(err != 0) {
    printf("[ecPVRA] SCS Signature verification failed\n");
    if (CCF_ENABLE == 1) {
        ret = SGX_ERROR_INVALID_PARAMETER;
        goto cleanup;
    } else {
        printf(" CCF_ENABLE=%d ignoring..\n", CCF_ENABLE);
    }
  } else {
    if(DEBUGPRINT) printf("[ecPVRA] SCS Signature verification success\n");
  }
  free_ccf_proof(&scs_proof);


  /*    (4) Command Decryption    */

  if(DEBUGPRINT) printf("[ecPVRA] eCMD user_pubkey: ");
  if(DEBUGPRINT) print_hexstring(&CC.user_pubkey, 64);
  int user_idx = -2;
  if(strncmp(CC.user_pubkey, enclave_state.publickeys.admin_pubkey, 64) == 0) {
    user_idx = -1;
  } else {
    for(int i = 0; i < enclave_state.num_users; i++) {
      if(strncmp(CC.user_pubkey, enclave_state.publickeys.user_pubkeys[i], 64) == 0) {
        user_idx = i;
        break;
      }
    }
  }

  if (user_idx == -2) {
    printf("[ecPVRA] user_pubkey NOT FOUND rejecting command\n");
    formatResponse(enc_cResponse + AESGCM_128_MAC_SIZE + AESGCM_128_IV_SIZE, -2, "user public key NOT FOUND rejecting command");
    ret = sign_cResponse(enclave_state.enclavekeys.enc_prikey, enc_cResponse, cResponse_signature);
    goto seal_cleanup;
  }
  if (user_idx == -1) {
    if(DEBUGPRINT) printf("[ecPVRA] CMD user_idx admin_user\n");
  } else {
    if(DEBUGPRINT) printf("[ecPVRA] CMD user_idx %d\n", user_idx);
  }

  /*    ECDH protocol to generate shared secret AESKey    */
  unsigned char AESKey[AESGCM_128_KEY_SIZE];
  ret = genkey_aesgcm128(CC.user_pubkey, enclave_state.enclavekeys.enc_prikey, AESKey);
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
  if (user_idx >= 0) { //i.e. not admin
    if(CC.seqNo != enclave_state.antireplay.seqno[user_idx]+1) {
        printf("[ecPVRA] SeqNo failure received [%lu] != [%lu] Not logging\n", CC.seqNo, enclave_state.antireplay.seqno[user_idx]+1);
        sprintf(resp, "SeqNo failure received [%lu] != [%lu] NOT logging\n", CC.seqNo, enclave_state.antireplay.seqno[user_idx]+1);
        formatResponse(&cResp, -4, resp);
        sign_cResponse(enclave_state.enclavekeys.enc_prikey, &cResp, cResponse_signature);
        encrypt_cResponse(AESKey, &cResp, enc_cResponse, enc_cResponse_size);
        goto cleanup;
    }
    enclave_state.antireplay.seqno[user_idx]++;
    if(DEBUGPRINT) printf("[ecPVRA] SeqNo success [%lu]\n", enclave_state.antireplay.seqno[user_idx]);
  }
  if(C_DEBUGRDTSC) ocall_rdtsc();




  
  /*   (6) FT UPDATE    */

  memcpy(enclave_state.counter.freshness_tag, ft_hash, 32); //todo why is this done here
  if(DEBUGPRINT) printf("[ecPVRA] SCS Local FT updated ");
  if(DEBUGPRINT) print_hexstring(enclave_state.counter.freshness_tag, 32);

  /*   (7) PROCESS COMMAND    */
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
  cResp = (*functions[CC.eCMD.CT])(&enclave_state, &CC.eCMD.CI, user_idx);
  

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
    if (bigbuf != NULL)
        free(bigbuf);
    free_ccf_proof(&scs_proof);
    free_enclave_state(&enclave_state, &dAD);
    if(C_DEBUGRDTSC) ocall_rdtsc();
    return ret;
}
