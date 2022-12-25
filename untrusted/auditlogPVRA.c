#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */



#include "app.h"

bool auditlogPVRA(void) {

  printf("[hcPVRA] Invoking ecall_auditlogPVRA\n");

  sgx_status_t ecall_retval = SGX_SUCCESS;


//  sgx_report_t report;
//  sgx_spid_t spid;
//  sgx_target_info_t target_info;
//  sgx_epid_group_id_t epid_gid;
//  sgx_status_t status;

  clock_t t;
  t = clock();
  tsc_idx = 0;

  sgx_lasterr = ecall_auditlogPVRA(
      enclave_id, &ecall_retval, 
      (uint8_t *)sealed_state_buffer, sealed_state_buffer_size,
      (uint8_t *)auditlog_buffer, auditlog_buffer_size,
      (uint8_t *)auditlog_signature_buffer,
      (uint8_t *)sealed_out_buffer, sealed_out_buffer_size);

  t = clock() - t;
  double time_taken = ((double)t)/CLOCKS_PER_SEC; // calculate the elapsed time
  printf("[hcPVRA] ecall_auditlogPVRA took %f seconds\n", time_taken);
   

  for(int i = 0; i < tsc_idx; i++)
    printf("%lu\n", tsc_dump[i]);


  return (sgx_lasterr == SGX_SUCCESS);


}

