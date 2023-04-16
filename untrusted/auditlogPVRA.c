#include <stdlib.h>

#include <enclave_u.h>

#include "app.h"

bool auditlogPVRA(void) {

  printf("Invoking ecall_auditlogPVRA\n");

  sgx_status_t ecall_retval = SGX_SUCCESS;

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
  printf("ecall_auditlogPVRA took %f seconds\n", time_taken);
   
  for(int i = 0; i < tsc_idx; i++)
    printf("%d: %lu\n", i, tsc_dump[i]);

  return (sgx_lasterr == SGX_SUCCESS);
}

