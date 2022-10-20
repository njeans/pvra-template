/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "app.h"

bool commandPVRA() {

  printf("[hcPVRA] Invoking ecall_commandPVRA\n");

  sgx_status_t ecall_retval = SGX_SUCCESS;


  sgx_report_t report;
  sgx_spid_t spid;
  sgx_target_info_t target_info;
  sgx_epid_group_id_t epid_gid;
  sgx_status_t status;

  clock_t t;
  t = clock();
  tsc_idx = 0;

  sgx_lasterr = ecall_commandPVRA(
      enclave_id, &ecall_retval, 
      (char *)sealed_state_buffer, sealed_state_buffer_size, 
      (char *)FT_buffer, FT_buffer_size,
      (char *)signedFT_buffer, signedFT_buffer_size, 
      (char *)eCMD_buffer, eCMD_buffer_size, 
      (char *)eAESkey_buffer, eAESkey_buffer_size,
      (char *)cResponse_buffer, cResponse_buffer_size,
      (char *)cRsig_buffer, cRsig_buffer_size,
      (char *)sealed_out_buffer, sealed_out_buffer_size);
  
  t = clock() - t;
  double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
  printf("[hcPVRA] ecall_commandPVRA took %f seconds\n", time_taken);
   

  for(int i = 0; i < tsc_idx; i++)
    printf("%lu\n", tsc_dump[i]);


  return (sgx_lasterr == SGX_SUCCESS);


}

