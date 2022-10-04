/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */



#include "app.h"

bool auditlogPVRA() {

  printf("[hcPVRA] Invoking ecall_auditlogPVRA\n");

  sgx_status_t ecall_retval = SGX_SUCCESS;


  sgx_report_t report;
  sgx_spid_t spid;
  sgx_target_info_t target_info;
  sgx_epid_group_id_t epid_gid;
  sgx_status_t status;

  clock_t t;
  t = clock();
  tsc_idx = 0;

  sgx_lasterr = ecall_auditlogPVRA(
      enclave_id, &ecall_retval, 
      (char *)sealed_state_buffer, sealed_state_buffer_size, 
      (char *)auditlog_buffer, auditlog_buffer_size,
      (char *)auditlog_signature_buffer, auditlog_signature_buffer_size,
      &actual_auditlog_size);
  
  t = clock() - t;
  double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
  printf("[hcPVRA] ecall_auditlogPVRA took %f seconds\n", time_taken);
   

  for(int i = 0; i < tsc_idx; i++)
    printf("%lu\n", tsc_dump[i]);


  return (sgx_lasterr == SGX_SUCCESS);


}

