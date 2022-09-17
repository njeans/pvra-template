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

sgx_status_t ecall_commandPVRA(sgx_report_t *report, sgx_target_info_t *target_info, char *sealedstate, size_t sealedstate_size) {

    /*  enclave_id, &ecall_retval, (char *)sealed_state_buffer,
      sealed_state_buffer_size, (char *)signed_FT,
      signed_FT_size, (char *)signed_FT,
      signed_FT_size, (char *)eCMD,
      eCMD_size, (char *)eAESkey,
      eAESkey_size, (char *)cResponse,
      cResponse_size) {
*/
  struct ES enclave_state;
  ocallrdtsc();
  sgx_status_t ret = SGX_SUCCESS;

  return ret;
}
