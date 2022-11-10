/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include "app.h"


bool enclave_get_init_buffer_sizes() {
  sgx_status_t ecall_retval = SGX_SUCCESS;

  printf("[GatewayApp] Querying enclave for buffer sizes\n");

  /*
   * Invoke ECALL, 'ecall_init_buffer_sizes()', to calculate the sizes of
   * buffers needed for the untrusted app to store initial data seal data from the enclave.
   */
  sgx_lasterr = ecall_init_buffer_sizes(enclave_id, &ecall_retval, &sealed_state_buffer_size);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)) {
    fprintf(stderr,
            "[GatewayApp] ERROR: ecall_init_buffer_sizes returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  printf("[GatewayApp] sealed_state_buffer_size %lu\n", sealed_state_buffer_size);

  return (sgx_lasterr == SGX_SUCCESS);
}

bool enclave_get_buffer_sizes() {
  sgx_status_t ecall_retval = SGX_SUCCESS;

  printf("[GatewayApp] Querying enclave for buffer sizes\n");
  /*
   * Invoke ECALL, 'ecall_calc_buffer_sizes()', to calculate the sizes of
   * buffers needed for the untrusted app to store seal data from the enclave.
   */
  sgx_lasterr = ecall_calc_buffer_sizes(enclave_id, &ecall_retval,
                    (uint8_t *)sealed_state_buffer, sealed_state_buffer_size,
                     &sealed_out_buffer_size, &auditlog_buffer_size);
  if (sgx_lasterr == SGX_SUCCESS && (ecall_retval != 0)) {
    fprintf(stderr,
            "[GatewayApp] ERROR: ecall_calc_buffer_sizes returned %d\n",
            ecall_retval);
    sgx_lasterr = SGX_ERROR_UNEXPECTED;
  }
  printf("[GatewayApp] sealed_out_buffer_size %lu\n", sealed_out_buffer_size);
  printf("[GatewayApp] auditlog_buffer_size %lu\n", auditlog_buffer_size);

  return (sgx_lasterr == SGX_SUCCESS);
}
