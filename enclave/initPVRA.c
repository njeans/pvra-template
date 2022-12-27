/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
*/

//#include <stdarg.h>
//#include <stdio.h>

//#include "enclave.h"
//#include <enclave_t.h>
//
//#include <sgx_quote.h>
//#include <sgx_tcrypto.h>
//#include <sgx_tseal.h>
//#include <sgx_utils.h>
//
// #include <mbedtls/md.h>
//#include <mbedtls/ctr_drbg.h>
//#include <mbedtls/bignum.h>
//#include <mbedtls/pk.h>
//#include <mbedtls/rsa.h>
//
//// [TODO]: If possible remove mbedtls dependence, only used for sha256 hashes now
//
//#include <secp256k1.h>
//#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
//
#include "enclave_state.h"
//#include "keccak256.h"
//#include "util.h"



/*
 * This function initializes a PVRA enclave.
 *
 * @param [in] userpubkeys: list of verified users the enclave will recognize.
 * @param [out] sealedstate: storage of initial enclave state seal.
 * @param [out] encpubkey: secp256k1 enclave encryption key.
 * @param [out] encpubkey_signature_ser: enclave signature for encryption key.
 * @param [out] useraddrs_signature_ser: enclave signature for list of user pubkeys.
 *        
 * @return SGX_SUCCESS (Error code = 0x0000) on success,
 * some sgx_status_t value upon failure.
*/



sgx_status_t ecall_initPVRA(
    sgx_target_info_t *target_info,
    uint64_t num_users, char *userpubkeys, size_t userpubkeys_size,
    sgx_report_t *report,
    uint8_t *sealedstate, size_t sealedstate_size,
    uint8_t encpubkey_ser[65],
    uint8_t encpubkey_signature_ser[64],
    uint8_t useraddrs_signature_ser[65]) {

  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int err;
  struct ES enclave_state;
  struct dAppData dAD;
  init_enclave_state(&enclave_state, &dAD);
  enclave_state.num_users  = num_users;

  // Control Timing Measurement of an OCALL Overhead.
  if(I_DEBUGRDTSC) ocall_rdtsc();

  //    Generate secp256k1 Enclave Encryption Key    //
  unsigned char seed_e = 'c';
  ret = genkey_secp256k1(seed_e, &enclave_state.enclavekeys.enc_prikey,
                                 &enclave_state.enclavekeys.enc_pubkey,
                                 encpubkey_ser);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(DEBUGPRINT) printf("[eiPVRA] Public Enclave Encryption Key (secp256k1)\n");
  if(DEBUGPRINT) print_hexstring(&enclave_state.enclavekeys.enc_pubkey, sizeof(secp256k1_pubkey));

  if(DEBUGPRINT) printf("[eiPVRA] Public Enclave Encryption Key serialized (secp256k1)\n");
  if(DEBUGPRINT) print_hexstring(encpubkey_ser, 65);

  if(I_DEBUGRDTSC) ocall_rdtsc();

  //    Generate secp256k1 Enclave Signing Key    //
  unsigned char signpubkey_ser[65];
  unsigned char seed_s = 'n';
  ret = genkey_secp256k1(seed_s, &enclave_state.enclavekeys.sig_prikey,
                                &enclave_state.enclavekeys.sig_pubkey,
                                signpubkey_ser);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(DEBUGPRINT) printf("[eiPVRA] Public Enclave Signing Key serialized (secp256k1)\n");
  if(DEBUGPRINT) print_hexstring(signpubkey_ser, 65);

  if(I_DEBUGRDTSC) ocall_rdtsc();


  //    Sign secp256k1 Enclave Encryption Key    //

  unsigned char encpubkey_hash[HASH_SIZE];
  sha256(encpubkey_ser, sizeof(encpubkey_ser), encpubkey_hash);

  if(DEBUGPRINT) printf("[eiPVRA] Public Enclave Encryption Key hash\n");
  if(DEBUGPRINT) print_hexstring(encpubkey_hash, sizeof(encpubkey_hash));

  secp256k1_ecdsa_signature encpubkey_signature;
  ret = sign_secp256k1(enclave_state.enclavekeys.sig_prikey, encpubkey_hash, &encpubkey_signature, encpubkey_signature_ser);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }
  if(DEBUGPRINT) printf("[eiPVRA] Public Enclave Encryption Key SIGNATURE serialized\n");
  if(DEBUGPRINT) print_hexstring(encpubkey_signature_ser, 64);

  if(I_DEBUGRDTSC) ocall_rdtsc();

  //    Initialize SCS Metadata    //
  memset(enclave_state.counter.freshness_tag, 0, 32);
  if(DEBUGPRINT) printf("[eiPVRA] Initialized SCS metadata success\n");


  //    Initialize Anti-Replay Metadata    //
  enclave_state.antireplay.seqno = (uint64_t *) malloc(sizeof(uint64_t)*num_users);
  for (uint64_t i = 0; i < num_users; i++) {
    enclave_state.antireplay.seqno[i] = 0;
  }
  if(DEBUGPRINT) printf("[eiPVRA] Initialized seqno metadata success\n");


  //    Initialize Application Data    //
  err = initES(&enclave_state, &dAD, num_users);

  if(err != 0) {
    printf_stderr("[eiPVRA] initES() memory allocation failure.\n");
    ret = SGX_ERROR_INVALID_PARAMETER;
    goto cleanup;
  }

  if(DEBUGPRINT) printf("[eiPVRA] Initialized application data success\n");


  //    Initialize USER pubkeys    //


  // Parsing userpubkeys from pubkeys.list
  hexstr_to_bytes(userpubkeys, 128, enclave_state.publickeys.admin_pubkey);
  enclave_state.publickeys.user_pubkeys = (pubkey_t *) malloc(sizeof(pubkey_t)*num_users);
  int uidx = 0;
  for(int i = 129; i< strlen(userpubkeys); i+=129) {
    hexstr_to_bytes(userpubkeys + i, 128, enclave_state.publickeys.user_pubkeys[uidx]);
    uidx++;
    if (uidx > num_users) {
      printf_stderr("[eiPVRA] input does not contain %u+1 pubkeys\n", num_users);
      ret = SGX_ERROR_INVALID_PARAMETER;
      goto cleanup;   
    }
  }


  if(DEBUGPRINT) {
      printf("[eiPVRA] Initialized [%d] Public Keys success\n", num_users+1);
      printf("ADMIN:\n");
      print_hexstring(enclave_state.publickeys.admin_pubkey, 64);
      printf("USERS:\n");
      for (int i = 0; i < num_users; i++) {
        print_hexstring(enclave_state.publickeys.user_pubkeys[i], 64);
      }
  }


  //    Sign all USER pubkeys    //
  unsigned char msg_hash[32];
  hash_address_list(&enclave_state.publickeys.admin_pubkey, enclave_state.publickeys.user_pubkeys, num_users, &msg_hash);
  if(DEBUGPRINT) printf("[eiPVRA] Admin+Users eth addresses hash\n");
  if(DEBUGPRINT) print_hexstring(&msg_hash, HASH_SIZE);


  secp256k1_ecdsa_recoverable_signature useraddrs_signature;
  ret = sign_rec_secp256k1(enclave_state.enclavekeys.enc_prikey, msg_hash, &useraddrs_signature, useraddrs_signature_ser);
  if (ret != SGX_SUCCESS) {
    goto cleanup;
  }

  if(DEBUGPRINT) printf("[eiPVRA] Signed [%d] Public Keys\n", num_users+1);
  if(DEBUGPRINT) printf("[eiPVRA] ADDRESS SIGNATURE serialized\n");
  if(DEBUGPRINT) print_hexstring(useraddrs_signature_ser, 65);


  //    Initialize AUDIT LOG metadata    //
  enclave_state.auditlog.num_entries = 0;
  enclave_state.auditlog.audit_num = 1;
  enclave_state.auditlog.entries = NULL;
  if(DEBUGPRINT) printf("[eiPVRA] Initialized audit log metadata success\n");

  if(I_DEBUGRDTSC) ocall_rdtsc();
  




  //    Generate Report    //

  sgx_report_data_t report_data = {{0}};
  memcpy((uint8_t *const) &report_data, (uint8_t *)&enclave_state.enclavekeys.sig_pubkey, 64);

  if(DEBUGPRINT) printf("[eiPVRA] Calling enclave to generate attestation report\n");
  ret = sgx_create_report(target_info, &report_data, report);
  if(ret == SGX_SUCCESS) {
    if(DEBUGPRINT) printf("[eiPVRA] Report generated success\n");
  } else {
    printf("[eiPVRA] Report generation failed %d\n", ret);
    goto cleanup;
  }
  if(I_DEBUGRDTSC) ocall_rdtsc();

  //    Seal Enclave State    //
  ret = seal_enclave_state(&enclave_state, &dAD, sealedstate_size, sealedstate);
  if(ret == SGX_SUCCESS) {
    if(DEBUGPRINT) printf("[eiPVRA] Initial seal_size: [%lu]\n", sealedstate_size);
  } else {
    printf_stderr("[eiPVRA] seal_enclave_state error: [%d]\n", ret);
  } 

  goto cleanup;

cleanup:
  if(I_DEBUGRDTSC) ocall_rdtsc();
  free_enclave_state(&enclave_state, &dAD);
  return ret;

}
